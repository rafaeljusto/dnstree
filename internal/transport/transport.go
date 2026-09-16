// Package transport carries a single DNS message to one server over UDP, TCP,
// DoT or DoH, and measures the round trip.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
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
