// Package transport carries a single DNS message to one server over UDP, TCP,
// DoT or DoH, and measures the round trip.
package transport

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// The ports each transport expects a nameserver to listen on.
const (
	PortDNS = 53
	PortDoT = 853
	PortDoH = 443
)

const (
	// DefaultTimeout bounds a single query.
	DefaultTimeout = 2 * time.Second

	// DefaultUDPSize is the EDNS0 buffer we advertise: the size RFC 9715
	// recommends to stay clear of IP fragmentation.
	DefaultUDPSize = 1232
)

// Transport exchanges messages with one server. Implementations are stateless
// with respect to the resolution: retries, truncation handling and EDNS
// fallback are the resolver's business.
type Transport interface {
	// Proto names the transport as it appears in the trace: udp, tcp, dot or doh.
	Proto() string

	// Port is where this transport expects a nameserver to listen. Glue carries
	// addresses and never ports, so this is what fills the gap.
	Port() uint16

	// Exchange sends req to server and returns the response and the measured
	// round trip time. name is the server's DNS name when known, used for TLS
	// verification by the encrypted transports.
	Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error)
}

// Config tunes a transport.
type Config struct {
	// Timeout bounds one query, DefaultTimeout when zero.
	Timeout time.Duration

	// TLS configures the encrypted transports. A nil config verifies against
	// the host's roots, under the name the delegation gave the server.
	TLS *tls.Config

	// Port overrides where nameservers are expected to listen. Zero uses the
	// port the protocol is registered on.
	Port uint16
}

// port is where servers are asked, which is the protocol's own unless the
// caller knows better.
func (c Config) port(standard uint16) uint16 {
	if c.Port != 0 {
		return c.Port
	}
	return standard
}

// tlsConfig is the config to dial with, named for the server being dialled.
func (c Config) tlsConfig(name string, protocols []string) *tls.Config {
	config := &tls.Config{}
	if c.TLS != nil {
		config = c.TLS.Clone()
	}
	if config.ServerName == "" {
		config.ServerName = strings.TrimSuffix(name, ".")
	}
	if len(config.NextProtos) == 0 {
		config.NextProtos = protocols
	}
	return config
}

// NewQuery builds an iterative query: recursion is never desired, since every
// server we talk to is meant to answer from its own zone. EDNS0 is advertised
// when udpSize is not zero, and the DO bit asks for signatures.
func NewQuery(name string, qtype uint16, udpSize uint16, dnssec bool) (*dns.Msg, error) {
	req := dns.NewMsg(name, qtype)
	if req == nil {
		return nil, fmt.Errorf("unknown query type %d", qtype)
	}
	req.RecursionDesired = false
	req.UDPSize = udpSize
	req.Security = dnssec
	return req, nil
}

// WithSubnet attaches the client subnet of RFC 7871 to a query, which asks the
// server to answer as it would for somebody inside that prefix. The address is
// masked to the prefix, since the bits past it are nobody's business and the
// protocol requires them to be zero.
//
// An option needs EDNS0 to ride in, so a query asked without it is left alone:
// that is the fallback for a server that could not parse EDNS0 in the first
// place, and it is no place to try again.
func WithSubnet(req *dns.Msg, prefix netip.Prefix) {
	if !prefix.IsValid() || req.UDPSize == 0 {
		return
	}

	addr := prefix.Masked().Addr()
	family := uint16(1) // IP
	if !addr.Unmap().Is4() {
		family = 2 // IP6
	}
	req.Pseudo = append(req.Pseudo, &dns.SUBNET{
		Family:  family,
		Netmask: uint8(prefix.Bits()),
		Address: addr,
	})
}

// WithNSID asks the server to say which of itself answered (RFC 5001). One
// anycast address is many machines, and nothing else in a reply tells them
// apart.
//
// Like a client subnet the option needs EDNS0 to ride in, so a query asked
// without it is left alone: that is the fallback for a server that could not
// parse EDNS0 in the first place.
func WithNSID(req *dns.Msg) {
	if req.UDPSize == 0 {
		return
	}
	req.Pseudo = append(req.Pseudo, &dns.NSID{})
}

// MaxNSID is how much of an identifier is kept. A server may answer with as
// much as it likes, and a line of a tree has room for a name.
const MaxNSID = 32

// EchoedNSID is what a server called itself, empty for one that called itself
// nothing. The identifier is opaque bytes that operators write names into, and
// it arrives hex encoded: a name is handed back as the name, and anything else
// stays the hex it came as.
//
// It is the one part of a reply whose bytes the server alone chooses, and it is
// drawn on a line of a tree that has a width and a charset to keep, so what
// leaves here is printable, bounded, and holds no spaces to break a line into
// fields at.
func EchoedNSID(resp *dns.Msg) string {
	if resp == nil {
		return ""
	}
	for _, rr := range resp.Pseudo {
		nsid, ok := rr.(*dns.NSID)
		if !ok || nsid.Nsid == "" {
			continue
		}
		return clip(readable(nsid.Nsid))
	}
	return ""
}

// readable is the text an identifier carries, or the hex it arrived as where it
// carries none. The space counts as unreadable here: a drawn field ends at one,
// and an identifier is one field.
func readable(hexed string) string {
	raw, err := hex.DecodeString(hexed)
	if err != nil {
		return hexed // not hex at all, and not ours to make sense of
	}
	for _, b := range raw {
		if b <= ' ' || b > '~' {
			return hexed
		}
	}
	return string(raw)
}

// clip bounds what a server can take up, and says where it was cut.
func clip(text string) string {
	if len(text) <= MaxNSID {
		return text
	}
	return text[:MaxNSID] + "..."
}

// Extended reads what a server said about its own answer: the extended errors
// of RFC 8914, in the order they arrived. An rcode says what happened and these
// say why, which is the difference between a name that is not there and a name
// somebody would not answer for.
func Extended(resp *dns.Msg) []trace.ExtendedError {
	if resp == nil {
		return nil
	}

	var extended []trace.ExtendedError
	for _, rr := range resp.Pseudo {
		ede, ok := rr.(*dns.EDE)
		if !ok {
			continue
		}
		extended = append(extended, trace.ExtendedError{
			Code:   ede.InfoCode,
			Reason: dns.ExtendedErrorToString[ede.InfoCode],
			Text:   ede.ExtraText,
		})
	}
	return extended
}

// EchoedSubnet is the client subnet a server handed back, nil when it handed
// back none. A server that echoes one has taken it into account; the scope is
// how much of it shaped the answer, and a zero scope means the answer is the
// same wherever it was asked from.
func EchoedSubnet(resp *dns.Msg) *trace.Subnet {
	if resp == nil {
		return nil
	}

	for _, rr := range resp.Pseudo {
		subnet, ok := rr.(*dns.SUBNET)
		if !ok || !subnet.Address.IsValid() {
			continue
		}
		prefix, err := subnet.Address.Unmap().Prefix(int(subnet.Netmask))
		if err != nil {
			continue // a netmask the address cannot carry says nothing
		}
		return &trace.Subnet{Prefix: prefix, Scope: subnet.Scope}
	}
	return nil
}

// IsTimeout reports whether err is the server staying silent, which the tree
// shows as an unanswered hop rather than a hard failure.
func IsTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// exchange is the round trip every transport built on a socket shares. They
// differ only in the network they dial and whether TLS wraps it.
func exchange(ctx context.Context, proto string, cfg Config, tlsConfig *tls.Config, req *dns.Msg, server netip.AddrPort) (*dns.Msg, time.Duration, error) {
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	if !server.IsValid() || server.Port() == 0 {
		return nil, 0, fmt.Errorf("%s: not a server address", server)
	}

	timeout, err := queryTimeout(ctx, cfg)
	if err != nil {
		return nil, 0, err
	}
	client := &dns.Client{Transport: &dns.Transport{
		Dialer:       &net.Dialer{Timeout: timeout},
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		TLSConfig:    tlsConfig,
	}}

	// Pack into a fresh buffer: the client hands the request's buffer over to
	// the response, so a reused request would scribble over an earlier answer.
	req.Data = nil

	start := time.Now()
	resp, _, err := client.Exchange(ctx, req, network(proto, server.Addr()), server.String())
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, fmt.Errorf("%s %s: %w", proto, server, err)
	}
	return resp, rtt, nil
}

// queryTimeout is what is left of the per-query budget once the run wide
// deadline is taken into account.
func queryTimeout(ctx context.Context, cfg Config) (time.Duration, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	if timeout <= 0 {
		return 0, context.DeadlineExceeded
	}
	return timeout, nil
}

// network pins the address family, so -4 and -6 are honoured by the socket and
// not only by the choice of server.
func network(proto string, addr netip.Addr) string {
	if addr.Is4() {
		return proto + "4"
	}
	return proto + "6"
}
