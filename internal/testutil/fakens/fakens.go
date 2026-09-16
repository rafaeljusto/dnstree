// Package fakens serves a synthetic delegation hierarchy from in-process
// authoritative servers on loopback, so the engine can be tested offline.
//
// It is the one place besides the resolver and the DNSSEC packages that needs
// the DNS codec: a fake nameserver has to speak the wire format.
package fakens

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

// Behaviour makes a server misbehave. Every knob mirrors something that happens
// in the wild and that the resolver has to survive.
type Behaviour struct {
	Drop        bool          // never answer, so the client times out
	Refuse      bool          // answer REFUSED
	Lame        bool          // answer NOERROR with neither AA nor a referral
	TruncateUDP bool          // set TC over UDP, answer in full over TCP
	FormErrEDNS bool          // answer FORMERR to any query carrying EDNS0
	Delay       time.Duration // answer this late
}

// Config describes one fake nameserver.
type Config struct {
	// Origin is the apex of the zone served, and the origin relative names in
	// Zone are read against.
	Origin string

	// Zone is the zone in presentation format, one record per line.
	Zone string

	// IPv6 listens on ::1 instead of 127.0.0.1.
	IPv6 bool

	Behaviour Behaviour
}

// Query is what a server was asked, recorded so that tests can assert on
// retries and on the EDNS0 the resolver advertised.
type Query struct {
	Name    string
	Type    uint16
	Proto   string // udp or tcp
	UDPSize uint16 // zero when the query carried no EDNS0
	DO      bool
}

// Server is a fake authoritative nameserver on loopback, listening on the same
// port for UDP and TCP.
type Server struct {
	// Addr is the address the server listens on.
	Addr netip.AddrPort

	origin    string
	records   []dns.RR
	behaviour Behaviour

	mu      sync.Mutex
	queries []Query
}

// New starts a nameserver for cfg and stops it when the test ends.
func New(tb testing.TB, cfg Config) *Server {
	tb.Helper()

	server := &Server{
		origin:    dnsutil.Fqdn(cfg.Origin),
		behaviour: cfg.Behaviour,
	}

	parser := dns.NewZoneParser(strings.NewReader(cfg.Zone), server.origin, "")
	parser.SetDefaultTTL(3600)
	for rr, err := range parser.RRs() {
		if err != nil {
			tb.Fatalf("fakens: parsing the %s zone: %v", server.origin, err)
		}
		if rr == nil {
			break
		}
		server.records = append(server.records, rr)
	}

	host := "127.0.0.1"
	if cfg.IPv6 {
		host = "[::1]"
	}
	packetConn, listener, err := listen(host)
	if err != nil {
		tb.Fatalf("fakens: listening on %s: %v", host, err)
	}
	server.Addr = netip.MustParseAddrPort(packetConn.LocalAddr().String())

	for _, start := range []func(*dns.Server){
		func(s *dns.Server) { s.PacketConn = packetConn },
		func(s *dns.Server) { s.Listener = listener },
	} {
		cancel, _, err := dnstest.Server("", func(s *dns.Server) {
			start(s)
			s.Handler = server
		})
		if err != nil {
			tb.Fatalf("fakens: starting the %s server: %v", server.origin, err)
		}
		tb.Cleanup(cancel)
	}
	return server
}

// Queries returns what the server was asked, oldest first.
func (s *Server) Queries() []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Query(nil), s.queries...)
}

// listen binds UDP and TCP to the same loopback port. The kernel hands out one
// port per protocol, so the TCP bind can lose a race with another process; a
// few attempts make that vanishingly unlikely.
func listen(host string) (net.PacketConn, net.Listener, error) {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		var packetConn net.PacketConn
		if packetConn, err = net.ListenPacket("udp", host+":0"); err != nil {
			continue
		}

		var listener net.Listener
		if listener, err = net.Listen("tcp", packetConn.LocalAddr().String()); err != nil {
			packetConn.Close()
			continue
		}
		return packetConn, listener, nil
	}
	return nil, nil, fmt.Errorf("no free port for both UDP and TCP: %w", err)
}

// ServeDNS implements [dns.Handler].
func (s *Server) ServeDNS(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	// The server only unpacks the header and the question before handing the
	// message over; the EDNS0 fields need the rest of it.
	if err := req.Unpack(); err != nil {
		return
	}

	name, qtype := dnsutil.Question(req)
	s.mu.Lock()
	s.queries = append(s.queries, Query{
		Name:    name,
		Type:    qtype,
		Proto:   dnsutil.Network(w),
		UDPSize: req.UDPSize,
		DO:      req.Security,
	})
	s.mu.Unlock()

	if s.behaviour.Drop {
		return
	}
	if s.behaviour.Delay > 0 {
		select {
		case <-time.After(s.behaviour.Delay):
		case <-ctx.Done():
			return
		}
	}

	reply := dnsutil.SetReply(new(dns.Msg), req)
	reply.UDPSize = req.UDPSize

	switch {
	case s.behaviour.FormErrEDNS && req.UDPSize > 0:
		reply.Rcode = dns.RcodeFormatError
		reply.UDPSize = 0
	case s.behaviour.Refuse:
		reply.Rcode = dns.RcodeRefused
	case s.behaviour.Lame:
		// NOERROR, no AA, nothing to follow: the server is not serving this zone.
	default:
		s.respond(reply, name, qtype)
	}

	if s.behaviour.TruncateUDP && dnsutil.Network(w) == "udp" {
		dnsutil.Truncate(reply)
	}
	reply.WriteTo(w)
}

// respond fills in the reply the way an authoritative server would: an answer,
// a referral, NODATA or NXDOMAIN.
func (s *Server) respond(reply *dns.Msg, name string, qtype uint16) {
	if !dnsutil.IsBelow(s.origin, name) {
		reply.Rcode = dns.RcodeRefused // out of bailiwick
		return
	}

	if delegation := s.delegation(name); len(delegation) > 0 {
		reply.Ns = delegation
		reply.Extra = s.glue(delegation)
		return // a referral carries no AA
	}

	reply.Authoritative = true
	var answer, owned []dns.RR
	for _, rr := range s.records {
		if !dns.EqualName(rr.Header().Name, name) {
			continue
		}
		owned = append(owned, rr)
		if dns.RRToType(rr) == qtype {
			answer = append(answer, rr)
		}
	}

	switch {
	case len(answer) > 0:
		reply.Answer = answer
	case len(owned) > 0 || s.hasChildren(name):
		reply.Ns = s.soa() // NODATA, including the empty non-terminal
	default:
		reply.Rcode = dns.RcodeNameError
		reply.Ns = s.soa()
	}
}

// delegation returns the NS RRset of the deepest zone cut between the apex and
// name, which is what makes this server refer the client further down.
func (s *Server) delegation(name string) []dns.RR {
	cut := ""
	for _, rr := range s.records {
		owner := rr.Header().Name
		switch {
		case dns.RRToType(rr) != dns.TypeNS:
		case dns.EqualName(owner, s.origin): // the apex NS set is not a cut
		case !dnsutil.IsBelow(owner, name):
		case dnsutil.Labels(owner) > dnsutil.Labels(cut):
			cut = owner
		}
	}
	if cut == "" {
		return nil
	}

	var delegation []dns.RR
	for _, rr := range s.records {
		if dns.RRToType(rr) == dns.TypeNS && dns.EqualName(rr.Header().Name, cut) {
			delegation = append(delegation, rr)
		}
	}
	return delegation
}

// glue returns the addresses of the delegated nameservers that this zone is
// allowed to hand out, meaning the in-bailiwick ones.
func (s *Server) glue(delegation []dns.RR) []dns.RR {
	var glue []dns.RR
	for _, ns := range delegation {
		target := ns.(*dns.NS).Ns
		if !dnsutil.IsBelow(ns.Header().Name, target) {
			continue
		}
		for _, rr := range s.records {
			switch dns.RRToType(rr) {
			case dns.TypeA, dns.TypeAAAA:
				if dns.EqualName(rr.Header().Name, target) {
					glue = append(glue, rr)
				}
			}
		}
	}
	return glue
}

func (s *Server) soa() []dns.RR {
	for _, rr := range s.records {
		if dns.RRToType(rr) == dns.TypeSOA && dns.EqualName(rr.Header().Name, s.origin) {
			return []dns.RR{rr}
		}
	}
	return nil
}

// hasChildren reports whether name is an empty non-terminal: it owns no record
// of its own, but names below it do.
func (s *Server) hasChildren(name string) bool {
	for _, rr := range s.records {
		if owner := rr.Header().Name; !dns.EqualName(owner, name) && dnsutil.IsBelow(name, owner) {
			return true
		}
	}
	return false
}
