// Package dane connects to the MX hosts --mail found covered by DANE, and to
// the SRV targets --srv found covered, and holds the certificate each address
// presents against the host's TLSA set (RFC 6698, RFC 7672 3, RFC 7673). It is
// best effort like the AS lookups: nothing here fails a resolution, and an
// address that cannot be reached is one that could not be checked from here,
// never one that does not match.
package dane

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

const (
	// Port is where mail between servers is delivered.
	Port = 25

	// DefaultTimeout is how long one address may take, greeting included: a
	// server behind a pregreet test holds the banner back for seconds.
	DefaultTimeout = 10 * time.Second

	// maxRead bounds what one server may send, the banner, the EHLO answer
	// and the handshake together. A chain is a few KiB.
	maxRead = 256 << 10

	// maxAddrs bounds the addresses checked for one host, and maxChecks those
	// checked in all.
	maxAddrs  = 4
	maxChecks = 16
)

// Dial opens a connection to one address of a server.
type Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

// Config is how the check reaches the servers. The zero value dials mail
// servers on port 25, SRV targets on their own port, with DefaultTimeout, at
// any address.
type Config struct {
	Dial    Dial
	Port    uint16
	Timeout time.Duration

	// Allow is which addresses may be dialled, nil for any. The addresses are
	// a signed zone's to choose, and one that names a loopback or private
	// address would have this machine greet whatever listens there.
	Allow func(netip.Addr) bool
}

// endpoint is one host on one port that --tlsa connects to, whoever named it.
type endpoint struct {
	host string
	port uint16

	// sni is the name asked for in the handshake, and names those a DANE-TA
	// match has to find in the certificate.
	sni   string
	names []string

	// start is how the service starts TLS, and domain the name it is
	// introduced to.
	start  starter
	domain string

	records []trace.TLSARecord
	addrs   []netip.Addr
	into    *[]trace.Presented
	who     client
}

// client is who decides by the check, in the words a reason uses.
type client struct {
	does, doesNot string
}

var (
	sender    = client{"a sender that checks DANE delivers to it", "a sender that checks DANE does not deliver to it"}
	connector = client{"a client that checks DANE connects to it", "a client that checks DANE does not connect to it"}
)

// Check connects to every address of each host of the mail path, and of the
// SRV targets, whose TLSA set a client would use, records what it presented
// in the host's Presented, and warns of what a client would refuse.
// Certificates are read against when the walk was made.
func Check(ctx context.Context, tr *trace.Trace, cfg Config) {
	cfg.Port = cmp.Or(cfg.Port, Port)
	cfg.Timeout = cmp.Or(cfg.Timeout, DefaultTimeout)
	if cfg.Dial == nil {
		cfg.Dial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", addr.String())
		}
	}

	mail, srv, unknown := endpoints(tr, cfg)
	var wg sync.WaitGroup
	checks, leftMail, leftSRV := 0, 0, 0
	for _, group := range []struct {
		endpoints []*endpoint
		left      *int
	}{{mail, &leftMail}, {srv, &leftSRV}} {
		for _, ep := range group.endpoints {
			addrs := ep.addrs[:min(len(ep.addrs), maxAddrs, maxChecks-checks)]
			checks, *group.left = checks+len(addrs), *group.left+len(ep.addrs)-len(addrs)
			*ep.into = make([]trace.Presented, len(addrs))
			for j, addr := range addrs {
				if cfg.Allow != nil && !cfg.Allow(addr) {
					(*ep.into)[j] = trace.Presented{Addr: addr, State: trace.PresentedUnreached, Why: reached + private}
					continue
				}
				wg.Go(func() {
					(*ep.into)[j] = check(ctx, cfg, tr.Started, ep, addr)
				})
			}
		}
	}
	wg.Wait()
	shareSRV(tr.SRV)

	if tr.Mail != nil {
		warn(tr)
	}
	if tr.SRV != nil {
		warnSRV(tr, unknown)
	}
	if leftMail > 0 {
		tr.Warnings = append(tr.Warnings, fmt.Sprintf(
			"--tlsa left %d mail server addresses unchecked, past the %d it checks for a host or the %d in all; check them with openssl s_client -starttls smtp",
			leftMail, maxAddrs, maxChecks))
	}
	if leftSRV > 0 {
		tr.Warnings = append(tr.Warnings, fmt.Sprintf(
			"--tlsa left %d addresses of the servers of %s unchecked, past the %d it checks for a host or the %d in all; check them with openssl s_client",
			leftSRV, tr.SRV.Name, maxAddrs, maxChecks))
	}
}

// endpoints are the hosts to connect to: the mail hosts DANE covers first,
// then each SRV target DANE covers, once for a host and port. Unknown are the
// SRV targets DANE covers on a service this package cannot start TLS for.
func endpoints(tr *trace.Trace, cfg Config) (mail, srv []*endpoint, unknown []*trace.SRVTarget) {
	if m := tr.Mail; m != nil {
		for i := range m.Hosts {
			host := &m.Hosts[i]
			if host.DANE != trace.DANEVerified {
				continue
			}
			mail = append(mail, &endpoint{
				host: host.Name, port: cfg.Port, sni: host.Name, names: references(m, host),
				start: startSMTP, records: host.Records, addrs: host.Addrs, into: &host.Presented, who: sender,
			})
		}
	}
	s := tr.SRV
	if s == nil {
		return mail, nil, nil
	}
	seen := map[string]bool{}
	for i := range s.Targets {
		target := &s.Targets[i]
		key := strings.ToLower(target.Name) + " " + strconv.Itoa(int(target.Port))
		if target.DANE != trace.DANEVerified || seen[key] {
			continue
		}
		seen[key] = true
		start, ok := starterFor(s.Service(), target.Port)
		if !ok {
			unknown = append(unknown, target)
			continue
		}
		// The service domain is the name to ask for, and with the target
		// the names a certificate may hold under a signed SRV set (RFC 7673
		// 4.1).
		srv = append(srv, &endpoint{
			host: target.Name, port: target.Port, sni: s.Domain(), names: []string{target.Name, s.Domain()},
			start: start, domain: s.Domain(), records: target.Records, addrs: target.Proven(),
			into: &target.Presented, who: connector,
		})
	}
	return mail, srv, unknown
}

// shareSRV gives a target what the check found for an earlier one of the same
// host and port, which it connected to once for both.
func shareSRV(s *trace.SRV) {
	if s == nil {
		return
	}
	first := map[string][]trace.Presented{}
	for i := range s.Targets {
		target := &s.Targets[i]
		key := strings.ToLower(target.Name) + " " + strconv.Itoa(int(target.Port))
		if presented, ok := first[key]; ok && target.Presented == nil {
			target.Presented = slices.Clone(presented)
			continue
		}
		if target.Presented != nil {
			first[key] = target.Presented
		}
	}
}

// warn says which addresses a sender refuses, and in one line how many could
// not be checked at all.
func warn(tr *trace.Trace) {
	var unreached []trace.Presented
	asked := 0
	for _, host := range tr.Mail.Hosts {
		for _, p := range host.Presented {
			if p.State == trace.PresentedUnreached && p.Why == reached+private {
				tr.Warnings = append(tr.Warnings, fmt.Sprintf(
					"%s publishes %s, which is no public address, so a sender on the internet cannot deliver to it and --tlsa did not connect; publish its public address",
					host.Name, p.Addr))
				continue
			}
			asked++
			switch {
			case p.State == trace.PresentedUnreached:
				unreached = append(unreached, p)
			case p.State != trace.PresentedMismatch:
			case p.Why == unmatched:
				tr.Warnings = append(tr.Warnings, fmt.Sprintf(
					"%s at %s presents a certificate issued %s that no TLSA record of its matches, so a sender that checks DANE does not deliver to it; publish TLSA for the key it presents",
					host.Name, p.Addr, p.Since.Format(time.DateOnly)))
			default:
				tr.Warnings = append(tr.Warnings, fmt.Sprintf(
					"a sender that checks DANE does not deliver to %s at %s: %s; fix its TLS or its TLSA set", host.Name, p.Addr, p.Why))
			}
		}
	}
	if len(unreached) == 0 {
		return
	}
	which := fmt.Sprintf("%d of the %d mail server addresses", len(unreached), asked)
	if len(unreached) == asked {
		which = "any of the mail servers"
	}
	tr.Warnings = append(tr.Warnings, fmt.Sprintf(
		"--tlsa could not check %s (%s); port 25 may be blocked from here, so try from a network that lets it out",
		which, strings.TrimPrefix(unreached[0].Why, reached)))
}

// warnSRV says which SRV targets a client that checks DANE refuses, which
// could not be checked, and which run a service --tlsa cannot start TLS for.
// An address that is no public one is said by --srv already.
func warnSRV(tr *trace.Trace, unknown []*trace.SRVTarget) {
	s := tr.SRV
	var unreached []trace.Presented
	asked := 0
	seen := map[string]bool{}
	for _, target := range s.Targets {
		key := strings.ToLower(target.Name) + " " + strconv.Itoa(int(target.Port))
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, p := range target.Presented {
			if p.State == trace.PresentedUnreached && p.Why == reached+private {
				continue
			}
			asked++
			switch {
			case p.State == trace.PresentedUnreached:
				unreached = append(unreached, p)
			case p.State != trace.PresentedMismatch:
			case p.Why == unmatched:
				tr.Warnings = append(tr.Warnings, fmt.Sprintf(
					"%s at %s presents on port %d a certificate issued %s that no TLSA record of its matches, so a client that checks DANE does not connect to it; publish TLSA for the key it presents",
					target.Name, p.Addr, target.Port, p.Since.Format(time.DateOnly)))
			default:
				tr.Warnings = append(tr.Warnings, fmt.Sprintf(
					"a client that checks DANE does not connect to %s at %s on port %d: %s; fix its TLS or its TLSA set",
					target.Name, p.Addr, target.Port, p.Why))
			}
		}
	}
	for _, target := range unknown {
		tr.Warnings = append(tr.Warnings, fmt.Sprintf(
			"--tlsa did not check %s on port %d, since it does not know how %s starts TLS; check it with openssl s_client",
			target.Name, target.Port, cmp.Or(s.Service(), "the service")))
	}
	if len(unreached) == 0 {
		return
	}
	which := fmt.Sprintf("%d of the %d addresses of the servers of %s", len(unreached), asked, s.Name)
	if len(unreached) == asked {
		which = "any of the servers of " + s.Name
	}
	tr.Warnings = append(tr.Warnings, fmt.Sprintf(
		"--tlsa could not check %s (%s); their ports may be blocked from here, so try from a network that lets them out",
		which, strings.TrimPrefix(unreached[0].Why, reached)))
}

// references are the names a DANE-TA match has to find in the certificate
// (RFC 7672 3.2.2): the TLSA base domain, the MX host, and the next-hop domain
// as asked and as its aliases end. The base is the name the TLSA lookup was
// built on, never where an alias of the TLSA set itself leads.
func references(m *trace.Mail, host *trace.MailHost) []string {
	var names []string
	if host.TLSA != nil {
		names = append(names, strings.TrimPrefix(host.TLSA.Name, "_25._tcp."))
	}
	names = append(names, host.Name, m.Name)
	if m.MX.Alias != "" {
		names = append(names, m.MX.Alias)
	}
	return names
}

// check connects to one address and decides by what it presents.
func check(ctx context.Context, cfg Config, at time.Time, ep *endpoint, addr netip.Addr) trace.Presented {
	presented := trace.Presented{Addr: addr}
	chain, err := handshake(ctx, cfg, ep, netip.AddrPortFrom(addr, ep.port))
	var refused *noSTARTTLS
	switch {
	case errors.As(err, &refused):
		// The refusal is the server's text, and as long as it likes.
		presented.State, presented.Why = trace.PresentedMismatch, trace.Printable(refused.why+", so "+ep.who.doesNot, trace.MaxErr)
		return presented
	case err != nil:
		presented.State, presented.Why = trace.PresentedUnreached, reached+trace.Printable(err.Error(), trace.MaxErr)
		return presented
	}

	leaf := chain[0]
	presented.Subject, presented.Since = leaf.Subject.String(), leaf.NotBefore.UTC()
	var why []string
	for i, record := range ep.records {
		if !record.Usable {
			continue
		}
		if reason := match(record, chain, ep.names, at); reason != "" {
			why = append(why, reason)
			continue
		}
		presented.Matched = append(presented.Matched, i)
	}
	if len(presented.Matched) > 0 {
		presented.State, presented.Why = trace.PresentedMatch, ep.who.does
		return presented
	}
	// A record that matched but failed a check after says more than one
	// that matched nothing.
	presented.State, presented.Why = trace.PresentedMismatch, unmatched
	for _, reason := range why {
		if reason != unmatched {
			presented.Why = reason
			break
		}
	}
	return presented
}

// reached begins why an address could not be checked.
const reached = "could not be checked from here: "

// private is why an address Allow refused was not dialled.
const private = "it is no public address"

// unmatched is why a record matched nothing in the chain.
const unmatched = "no TLSA record matches the certificate or key it presents"

// noSTARTTLS is a server that will not start TLS, which a client that checks
// DANE takes as a reason not to connect to it (RFC 7672 2.2, RFC 7673 4).
type noSTARTTLS struct{ why string }

func (e *noSTARTTLS) Error() string { return e.why }

// handshake starts TLS with the server the way its service does and returns
// the chain it presents, leaf first. It is not verified: the TLSA set is what
// decides.
func handshake(ctx context.Context, cfg Config, ep *endpoint, addr netip.AddrPort) ([]*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	conn, err := cfg.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	// The deadline bounds a server that is slow; this bounds one that is
	// cancelled with the rest of the run.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	limited := &bounded{Conn: conn, left: maxRead}
	if ep.start.begin != nil {
		if err := ep.start.begin(limited, ep.domain); err != nil {
			return nil, err
		}
	}

	// Anything the server sent before TLS and was not read as its answer is
	// dropped, as a client drops it, rather than read as the handshake.
	secured := tls.Client(limited, &tls.Config{
		ServerName: strings.TrimSuffix(ep.sni, "."),
		// The TLSA set is the trust here, not the system's roots.
		InsecureSkipVerify: true,
	})
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("the TLS handshake: %w", err)
	}
	chain := secured.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("the TLS handshake left no certificate")
	}
	if ep.start.quit != "" {
		_, _ = secured.Write([]byte(ep.start.quit))
	}
	return chain, nil
}

// match is why one record does not match the chain, empty where it does.
func match(record trace.TLSARecord, chain []*x509.Certificate, names []string, at time.Time) string {
	want, err := hex.DecodeString(record.Data)
	if err != nil {
		return unmatched
	}
	switch record.Usage {
	case 3:
		// Only the leaf, and neither its names nor its dates (RFC 7672
		// 3.1.1).
		if !associated(record, chain[0], want) {
			return unmatched
		}
		return ""
	case 2:
		for i, cert := range chain {
			if !associated(record, cert, want) {
				continue
			}
			return anchored(chain, i, names, at)
		}
	}
	return unmatched
}

// anchored is why the leaf does not chain to the trust anchor at chain[i], or
// does not name the server (RFC 7672 3.1.2, 3.2.2), empty where it does both.
func anchored(chain []*x509.Certificate, i int, names []string, at time.Time) string {
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(chain[i])
	for _, cert := range chain[1:i] {
		intermediates.AddCert(cert)
	}
	leaf := chain[0]
	if i > 0 {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at}); err != nil {
			return "a DANE-TA record matches an issuer it presents, but the chain does not hold: " + err.Error()
		}
	} else if at.Before(leaf.NotBefore) || at.After(leaf.NotAfter) {
		return "a DANE-TA record matches the certificate it presents, which is not valid at the time"
	}
	if !named(leaf, names) {
		return fmt.Sprintf("a DANE-TA record matches, but the certificate names none of %s", strings.Join(trimmed(names), ", "))
	}
	return ""
}

// associated reports whether the record's data is the certificate's, or its
// key's, under the record's matching type.
func associated(record trace.TLSARecord, cert *x509.Certificate, want []byte) bool {
	var data []byte
	switch record.Selector {
	case 0:
		data = cert.Raw
	case 1:
		data = cert.RawSubjectPublicKeyInfo
	default:
		return false
	}
	switch record.Matching {
	case 0:
	case 1:
		sum := sha256.Sum256(data)
		data = sum[:]
	case 2:
		sum := sha512.Sum512(data)
		data = sum[:]
	default:
		return false
	}
	return bytes.Equal(data, want)
}

// named reports whether the certificate names one of names (RFC 7672 3.2.3):
// its DNS names where it has any, its common name where it has none, with a
// wildcard standing for one whole first label.
func named(cert *x509.Certificate, names []string) bool {
	presented := cert.DNSNames
	if len(presented) == 0 && cert.Subject.CommonName != "" {
		presented = []string{cert.Subject.CommonName}
	}
	for _, name := range trimmed(names) {
		for _, id := range presented {
			if identifies(strings.ToLower(id), name) {
				return true
			}
		}
	}
	return false
}

func identifies(id, name string) bool {
	if id == name {
		return true
	}
	rest, ok := strings.CutPrefix(id, "*.")
	if !ok {
		return false
	}
	_, parent, ok := strings.Cut(name, ".")
	return ok && parent == rest
}

// trimmed are names lowercased and without the trailing dot, as a
// certificate writes them.
func trimmed(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, strings.ToLower(strings.TrimSuffix(name, ".")))
	}
	return out
}

// bounded is a connection that reads no more than left bytes.
type bounded struct {
	net.Conn
	left int
}

func (b *bounded) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, fmt.Errorf("the server sent more than %d KiB", maxRead>>10)
	}
	n, err := b.Conn.Read(p[:min(len(p), b.left)])
	b.left -= n
	return n, err
}
