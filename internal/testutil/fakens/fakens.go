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
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// DefaultPort is the port a declared address is assumed to listen on, matching
// what the resolver dials.
const DefaultPort = 53

// Behaviour makes a server misbehave. Every knob mirrors something that happens
// in the wild and that the resolver has to survive.
type Behaviour struct {
	Drop        bool          // never answer, so the client times out
	Refuse      bool          // answer REFUSED
	Lame        bool          // answer NOERROR with neither AA nor a referral
	TruncateUDP bool          // set TC over UDP, answer in full over TCP
	FormErrEDNS bool          // answer FORMERR to any query carrying EDNS0
	Delay       time.Duration // answer this late

	// OutOfBailiwickGlue hands out addresses for nameservers outside the zone
	// delegated, the way the root servers do for the gTLD servers. A resolver
	// that trusts them can be walked off a cliff.
	OutOfBailiwickGlue bool

	// The ways a signed zone can break its own chain of trust.
	NoDS         bool // the parent vouches for nobody, leaving the zone unsigned
	NoDNSKEY     bool // the keys cannot be fetched at all
	StrayDNSKEY  bool // the keys served are not the ones the DS points at
	BadSignature bool // the signatures over the records do not verify

	// BadKeySignature breaks the other link: the key set the DS points at is
	// there, but it did not sign itself.
	BadKeySignature bool
}

// Config describes one fake nameserver.
type Config struct {
	// Name is the server's own DNS name, as its parent's NS record spells it.
	Name string

	// Origin is the apex of the zone served, and the origin relative names in
	// Zone are read against.
	Origin string

	// Zone is the zone in presentation format, one record per line.
	Zone string

	// Declared is the address the zones of a [Hierarchy] hand out as glue for
	// this server. The real socket is on loopback; the hierarchy's transport
	// maps one to the other.
	Declared string

	// Host is the loopback address to listen on, 127.0.0.1 by default.
	Host string

	// DNSSEC signs the zone and answers with the signatures when they are asked
	// for.
	DNSSEC bool

	// TLS and DoH serve the same zone over the encrypted transports, each on a
	// port of its own.
	TLS bool
	DoH bool

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
	// Addr is the address the server really listens on.
	Addr netip.AddrPort

	// Declared is the address its parent hands out as glue, unset outside a
	// [Hierarchy].
	Declared netip.Addr

	// TLSAddr and DoHAddr are where the encrypted transports listen, when they
	// were asked for.
	TLSAddr netip.AddrPort
	DoHAddr netip.AddrPort

	name      string
	origin    string
	signer    *signer
	behaviour Behaviour

	// zone is read by the handlers and written when a child publishes its DS,
	// so it is replaced whole rather than appended to.
	zone atomic.Pointer[[]dns.RR]

	mu      sync.Mutex
	queries []Query
}

// New starts a nameserver for cfg and stops it when the test ends.
func New(tb testing.TB, cfg Config) *Server {
	tb.Helper()

	server := &Server{
		name:      dnsutil.Fqdn(cfg.Name),
		origin:    dnsutil.Fqdn(cfg.Origin),
		behaviour: cfg.Behaviour,
	}
	if cfg.DNSSEC {
		server.signer = newSigner(tb, server.origin, cfg.Behaviour)
	}
	if cfg.Declared != "" {
		declared, err := netip.ParseAddr(cfg.Declared)
		if err != nil {
			tb.Fatalf("fakens: declared address %q: %v", cfg.Declared, err)
		}
		server.Declared = declared
	}

	var zone []dns.RR
	parser := dns.NewZoneParser(strings.NewReader(cfg.Zone), server.origin, "")
	parser.SetDefaultTTL(3600)
	for rr, err := range parser.RRs() {
		if err != nil {
			tb.Fatalf("fakens: parsing the %s zone: %v", server.origin, err)
		}
		if rr == nil {
			break
		}
		zone = append(zone, rr)
	}
	server.zone.Store(&zone)

	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
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
			// Whatever cannot be parsed is the client's problem, not something
			// to dump over the test output.
			s.MsgInvalidFunc = func(*dns.Msg, error) {}
		})
		if err != nil {
			tb.Fatalf("fakens: starting the %s server: %v", server.origin, err)
		}
		tb.Cleanup(cancel)
	}

	if cfg.TLS {
		server.listenTLS(tb, host)
	}
	if cfg.DoH {
		server.listenDoH(tb, host)
	}
	return server
}

// Nameserver is the server as the resolver should be told about it: the
// declared address when there is one, the real socket otherwise.
func (s *Server) Nameserver() trace.Server {
	server := trace.Server{Name: s.name, IP: s.Addr.Addr(), Port: s.Addr.Port()}
	if s.Declared.IsValid() {
		server.IP, server.Port = s.Declared, DefaultPort
	}
	return server
}

// records is the zone as it stands.
func (s *Server) records() []dns.RR { return *s.zone.Load() }

// publish adds a record to the zone, which only happens when a signed child
// hands over its DS. The slice is copied so that a handler reading it never
// sees it change underneath.
func (s *Server) publish(rr dns.RR) {
	current := s.records()
	updated := make([]dns.RR, len(current), len(current)+1)
	copy(updated, current)
	s.zone.Store(new(append(updated, rr)))
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
	for range 5 {
		var packetConn net.PacketConn
		if packetConn, err = net.ListenPacket("udp", net.JoinHostPort(host, "0")); err != nil {
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
	s.serve(ctx, w, req)
}

// ServeHTTP answers DNS over HTTPS, where the message arrives whole and needs
// no further unpacking.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	s.serve(r.Context(), dnshttp.NewResponseWriter(w, r, local), req)
}

// serve answers one query, however it arrived.
func (s *Server) serve(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
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
		if req.Security {
			s.signReply(reply)
		}
	}

	if s.behaviour.TruncateUDP && dnsutil.Network(w) == "udp" {
		dnsutil.Truncate(reply)
	}
	_, _ = reply.WriteTo(w)
}

// respond fills in the reply the way an authoritative server would: an answer,
// a referral, NODATA or NXDOMAIN.
func (s *Server) respond(reply *dns.Msg, name string, qtype uint16) {
	if !dnsutil.IsBelow(s.origin, name) {
		reply.Rcode = dns.RcodeRefused // out of bailiwick
		return
	}

	if delegation := s.delegation(name); len(delegation) > 0 {
		// The delegated NS RRset is never signed by the parent; the DS is what
		// the parent puts its name to.
		reply.Ns = delegation
		reply.Ns = append(reply.Ns, s.ds(delegation[0].Header().Name)...)
		reply.Extra = s.glue(delegation)
		return // a referral carries no AA
	}

	if s.signer != nil && qtype == dns.TypeDNSKEY && dns.EqualName(name, s.origin) {
		reply.Authoritative = true
		if !s.behaviour.NoDNSKEY {
			reply.Answer = s.signer.dnskeys()
		}
		return
	}

	reply.Authoritative = true
	var answer, owned []dns.RR
	for _, rr := range s.records() {
		if !dns.EqualName(rr.Header().Name, name) {
			continue
		}
		owned = append(owned, rr)
		if dns.RRToType(rr) == qtype {
			answer = append(answer, rr)
		}
	}

	// An alias answers for every type, and chasing it is the client's job.
	if len(answer) == 0 && qtype != dns.TypeCNAME {
		for _, rr := range owned {
			if dns.RRToType(rr) == dns.TypeCNAME {
				reply.Answer = []dns.RR{rr}
				return
			}
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
	for _, rr := range s.records() {
		owner := rr.Header().Name
		switch {
		case dns.RRToType(rr) != dns.TypeNS:
		case dns.EqualName(owner, s.origin): // the apex NS set is not a cut
		case !dnsutil.IsBelow(owner, name):
		case cut == "" || dnsutil.Labels(owner) > dnsutil.Labels(cut):
			cut = owner
		}
	}
	if cut == "" {
		return nil
	}

	var delegation []dns.RR
	for _, rr := range s.records() {
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
		if !dnsutil.IsBelow(ns.Header().Name, target) && !s.behaviour.OutOfBailiwickGlue {
			continue
		}
		for _, rr := range s.records() {
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

// ds are the records this zone publishes to vouch for a child of its own.
func (s *Server) ds(zone string) []dns.RR {
	var published []dns.RR
	for _, rr := range s.records() {
		if dns.RRToType(rr) == dns.TypeDS && dns.EqualName(rr.Header().Name, zone) {
			published = append(published, rr)
		}
	}
	return published
}

// signReply adds a signature for every RRset a signed zone is handing out. The
// NS RRset of a delegation is left alone: it belongs to the child.
func (s *Server) signReply(reply *dns.Msg) {
	if s.signer == nil {
		return
	}

	reply.Answer = s.signed(reply.Answer)
	reply.Ns = s.signed(reply.Ns)
}

func (s *Server) signed(section []dns.RR) []dns.RR {
	signed := section
	for _, rrset := range rrsets(section) {
		switch dns.RRToType(rrset[0]) {
		case dns.TypeNS:
			if !dns.EqualName(rrset[0].Header().Name, s.origin) {
				continue // a delegation, signed by nobody
			}
		case dns.TypeRRSIG:
			continue // already carries its own signature
		}
		if signature := s.signer.signRRset(rrset); signature != nil {
			signed = append(signed, signature)
		}
	}
	return signed
}

func (s *Server) soa() []dns.RR {
	for _, rr := range s.records() {
		if dns.RRToType(rr) == dns.TypeSOA && dns.EqualName(rr.Header().Name, s.origin) {
			return []dns.RR{rr}
		}
	}
	return nil
}

// hasChildren reports whether name is an empty non-terminal: it owns no record
// of its own, but names below it do.
func (s *Server) hasChildren(name string) bool {
	for _, rr := range s.records() {
		if owner := rr.Header().Name; !dns.EqualName(owner, name) && dnsutil.IsBelow(name, owner) {
			return true
		}
	}
	return false
}
