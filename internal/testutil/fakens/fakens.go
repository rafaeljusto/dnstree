// Package fakens serves a synthetic delegation hierarchy from in-process
// authoritative servers on loopback, so the engine can be tested offline.
//
// It is the one place besides the resolver and the DNSSEC packages that needs
// the DNS codec: a fake nameserver has to speak the wire format.
package fakens

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	NoDenial     bool // and does not sign the claim that it has nobody to vouch for
	NoDNSKEY     bool // the keys cannot be fetched at all
	StrayDNSKEY  bool // the keys served are not the ones the DS points at
	BadSignature bool // the signatures over the records do not verify

	// BadKeySignature breaks the other link: the key set the DS points at is
	// there, but it did not sign itself.
	BadKeySignature bool

	// SignatureLeft is how long the signatures the zone hands out have left to
	// run, out of a life of SignatureLife, or the fourteen days the library
	// signs for where that is zero. Little left of a long life is a zone whose
	// signer has stopped re-signing it. Zero leaves both to the library.
	SignatureLeft time.Duration
	SignatureLife time.Duration

	// CDS is what the zone asks its parent to publish, in the CDS and CDNSKEY
	// records at its apex (RFC 7344): nothing when it is empty, the key the
	// parent already vouches for with CDSCurrent, a key of the next rollover
	// with CDSNext, no DS at all with CDSDelete, or a CDS and a CDNSKEY for two
	// different keys with CDSMismatched. Only a signed zone publishes one.
	CDS CDS

	// DenyEmptyNonTerminal answers NXDOMAIN for a name that owns nothing but
	// has names below it, which RFC 8020 makes a claim that nothing is below it
	// either. It is what breaks a resolver that minimises its questions.
	DenyEmptyNonTerminal bool

	// Extended attaches an RFC 8914 extended error to every answer, which is
	// how a server says why it answered as it did. Paired with Refuse it is a
	// filtering resolver; on its own it is a server explaining itself.
	Extended *ExtendedError

	// EchoSubnet answers a query carrying a client subnet with that subnet and
	// SubnetScope, the way a server that tailors its answers by network does. A
	// server without it ignores the subnet, which is also worth testing.
	EchoSubnet  bool
	SubnetScope uint8

	// NSID is what the server calls itself when a query asks (RFC 5001), in the
	// bytes an operator would have written into it; the wire carries them hex
	// encoded. A server with none published answers a query that asks with
	// nothing, which is the other case worth testing.
	NSID string

	// Cookies is how the server answers a DNS cookie (RFC 7873). The zero
	// value ignores it, the way a server that does not support them does.
	Cookies Cookies
}

// Cookies is how a server answers a DNS cookie.
type Cookies int

// The ways a server can answer a cookie.
const (
	CookieIgnore      Cookies = iota
	CookieSupport             // the client cookie back, with one of its own
	CookieRequire             // BADCOOKIE until it is sent the cookie it handed out
	CookieRefuse              // BADCOOKIE even to the cookie it handed out
	CookieWrongClient         // a client cookie other than the one it was sent
	CookieMalformed           // the client cookie back, and no cookie of its own
)

// CDS is what a zone asks its parent to publish.
type CDS int

// What a zone can ask its parent to publish.
const (
	CDSNone CDS = iota
	CDSCurrent
	CDSNext
	CDSDelete
	CDSMismatched
)

// ExtendedError is what a server says about its own answer (RFC 8914).
type ExtendedError struct {
	Code uint16
	Text string
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

	// Denial is how the zone proves a child of it has no DS. The zero value is
	// the opt-out NSEC3 the large TLDs publish.
	Denial Denial

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
	Cookie  string // the cookie the query carried, hex encoded
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

	name       string
	origin     string
	signer     *signer
	behaviour  Behaviour
	denialKind Denial

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
		name:       dnsutil.Fqdn(cfg.Name),
		origin:     dnsutil.Fqdn(cfg.Origin),
		behaviour:  cfg.Behaviour,
		denialKind: cfg.Denial,
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

	records := parse(tb, server.origin, cfg.Zone)
	if server.signer != nil {
		records = append(records, parse(tb, server.origin, server.signer.signals(tb, cfg.Behaviour.CDS))...)
	}
	server.zone.Store(&records)

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
// declared address when there is one, the real socket otherwise. A declared
// address carries no port, the way real glue does not, so the transport says
// where to knock and the hierarchy maps it onto the right socket.
func (s *Server) Nameserver() trace.Server {
	if s.Declared.IsValid() {
		return trace.Server{Name: s.name, IP: s.Declared}
	}
	return trace.Server{Name: s.name, IP: s.Addr.Addr(), Port: s.Addr.Port()}
}

// parse reads a zone in presentation format, against the origin it belongs to.
func parse(tb testing.TB, origin, zone string) []dns.RR {
	tb.Helper()

	var records []dns.RR
	parser := dns.NewZoneParser(strings.NewReader(zone), origin, "")
	parser.SetDefaultTTL(3600)
	for rr, err := range parser.All() {
		if err != nil {
			tb.Fatalf("fakens: parsing the %s zone: %v", origin, err)
		}
		if rr == nil {
			break
		}
		records = append(records, rr)
	}
	return records
}

// Replace gives the server another zone to serve from the next query onwards,
// which is how a test watches something change under a walk. The zone goes in
// whole, so a handler part way through an answer finishes out of the zone it
// started in and never sees half of each.
//
// What the old zone published on behalf of a signed child is lost with it, so
// a hierarchy whose DS records were handed over at the start is not one to do
// this to.
func (s *Server) Replace(tb testing.TB, zone string) {
	tb.Helper()
	s.zone.Store(new(parse(tb, s.origin, zone)))
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
		Cookie:  sentCookie(req),
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
	s.echo(reply, req)

	switch {
	case s.cookie(reply, req):
		reply.Rcode = dns.RcodeBadCookie
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

// echo puts the EDNS0 options the server was set up to answer with into the
// reply: its account of the answer, and the client subnet it took into
// account. Both need EDNS0 to ride in, so a query that carried none gets
// neither, exactly as in the wild.
func (s *Server) echo(reply, req *dns.Msg) {
	if req.UDPSize == 0 {
		return
	}

	if ede := s.behaviour.Extended; ede != nil {
		reply.Pseudo = append(reply.Pseudo, &dns.EDE{InfoCode: ede.Code, ExtraText: ede.Text})
	}
	if s.behaviour.NSID != "" && asks[*dns.NSID](req) {
		reply.Pseudo = append(reply.Pseudo, &dns.NSID{Nsid: hex.EncodeToString([]byte(s.behaviour.NSID))})
	}
	if !s.behaviour.EchoSubnet {
		return
	}
	for _, rr := range req.Pseudo {
		if subnet, ok := rr.(*dns.SUBNET); ok {
			reply.Pseudo = append(reply.Pseudo, &dns.SUBNET{
				Family:  subnet.Family,
				Netmask: subnet.Netmask,
				Scope:   s.behaviour.SubnetScope,
				Address: subnet.Address,
			})
		}
	}
}

// cookie answers the cookie a query carried, and reports whether the answer
// is BADCOOKIE instead of the one asked for.
func (s *Server) cookie(reply, req *dns.Msg) (refused bool) {
	raw, err := hex.DecodeString(sentCookie(req))
	if s.behaviour.Cookies == CookieIgnore || err != nil || len(raw) < 8 {
		return false
	}

	client := raw[:8]
	sum := sha256.Sum256(append([]byte(s.name), client...))
	own := sum[:8]
	answer := append(bytes.Clone(client), own...)
	switch s.behaviour.Cookies {
	case CookieWrongClient:
		answer[0] ^= 0xff
	case CookieMalformed:
		answer = client
	}
	reply.Pseudo = append(reply.Pseudo, &dns.COOKIE{Cookie: hex.EncodeToString(answer)})

	switch s.behaviour.Cookies {
	case CookieRequire:
		return !bytes.Equal(raw[8:], own)
	case CookieRefuse:
		return true
	}
	return false
}

// sentCookie is the cookie a query carried, empty when it carried none.
func sentCookie(req *dns.Msg) string {
	for _, rr := range req.Pseudo {
		if cookie, ok := rr.(*dns.COOKIE); ok {
			return cookie.Cookie
		}
	}
	return ""
}

// asks reports whether the query carried an EDNS0 option of this type. A server
// answers with an identifier because it was asked for one, never unprompted.
func asks[T dns.RR](req *dns.Msg) bool {
	for _, rr := range req.Pseudo {
		if _, ok := rr.(T); ok {
			return true
		}
	}
	return false
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
		child := delegation[0].Header().Name
		reply.Ns = delegation
		published := s.ds(child)
		reply.Ns = append(reply.Ns, published...)
		if len(published) == 0 {
			// No DS is a claim of its own, and a signed parent signs it.
			reply.Ns = append(reply.Ns, s.denial(child, false)...)
		}
		reply.Extra = s.glue(delegation)
		return // a referral carries no AA
	}

	// The parent side of a cut answering for a DS it does not hold denies it
	// rather than saying the name is not there.
	if s.signer != nil && qtype == dns.TypeDS && !dns.EqualName(name, s.origin) &&
		dnsutil.IsBelow(s.origin, name) && len(s.ds(name)) == 0 {
		reply.Authoritative = true
		reply.Ns = append(s.soa(), s.denial(name, false)...)
		return
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
	case len(owned) > 0 || s.hasChildren(name) && !s.behaviour.DenyEmptyNonTerminal:
		// NODATA, including the empty non-terminal: the name is there and the
		// type is not, and a signed zone says so rather than only implying it.
		reply.Ns = append(s.soa(), s.denial(name, false)...)
	default:
		reply.Rcode = dns.RcodeNameError
		reply.Ns = append(s.soa(), s.denial(name, true)...)
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
