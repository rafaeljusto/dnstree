// Package resolver walks the delegation chain from the root down to the
// authoritative servers, classifying every response and recording each hop in
// the trace.
package resolver

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"codeberg.org/miekg/dns/svcb"

	"github.com/rafaeljusto/dnstree/v2/internal/roothints"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

const (
	// DefaultPort is where nameservers listen, when neither the transport nor
	// the server itself says otherwise.
	DefaultPort = 53

	// maxParallel bounds the fanout of All: quick enough to be worth it, few
	// enough to stay polite to one zone's servers.
	maxParallel = 4

	// maxSideResolution is how deep nameserver names may be chased before the
	// walk gives up on them.
	maxSideResolution = 2

	// maxSkipped is how many of a zone's remaining nameservers are drawn once
	// one of them has answered. The root alone offers twenty-six.
	maxSkipped = 3
)

// Config is how a resolution is run.
type Config struct {
	// Transport carries every query. Required.
	Transport transport.Transport

	// TCP fetches an answer that came back truncated. Nil leaves the TC bit
	// alone, and the hop keeps whatever fitted in the datagram.
	TCP transport.Transport

	// Fallback carries a hop the main transport could not. Authoritative
	// servers rarely speak DoT or DoH, so without one every such hop is an
	// error rather than an answer.
	Fallback transport.Transport

	// Roots is where a walk starts, usually RootServers(roothints.Default()).
	// Required.
	Roots []trace.Server

	// UDPSize advertises an EDNS0 buffer, zero asks without EDNS0.
	UDPSize uint16

	// DNSSEC sets the DO bit and follows the chain of trust down.
	DNSSEC bool

	// Anchors are the DS records the chain starts from. Empty means the ones
	// embedded in the binary. Only read when DNSSEC is set.
	Anchors roothints.Anchors

	// All asks every nameserver of a zone instead of stopping at the first one
	// that answers, looking up every one named outside the zone to do it. The
	// walk still follows a single path down, and the lookups of those names
	// ask one server a zone, as a resolver would.
	All bool

	// Family restricts the walk to IPv4 (4) or IPv6 (6) servers. Zero uses
	// whatever a delegation offers.
	Family int

	// Retries is how many more times a server that stayed silent is asked
	// before the walk moves on to the next one.
	Retries int

	// Log records every hop as it is made. Nil keeps quiet.
	Log *slog.Logger

	// Stepped is called each time a hop joins the trace, from the goroutine
	// doing the walking, so a caller may read the whole trace inside it. It is
	// how a live drawing keeps up with a walk.
	Stepped func(*trace.Trace)

	// Discovered is handed the address of each server the walk is about to ask,
	// as it asks it. Metadata that takes a while to look up can start here and
	// run behind the walk, instead of after it where the wait is the reader's.
	// It is called from several goroutines at once.
	Discovered func(netip.Addr)

	// Asking is handed each query as it goes out and returns the function to
	// call when it comes back; a nil return is fine. It is what tells a live
	// drawing that a walk is waiting rather than stuck, which Stepped cannot:
	// nothing joins the trace until the answer is in. --all has several queries
	// out at once, so it is called from several goroutines.
	Asking func(zone string, server trace.Server) (done func())

	// CheckNS asks the zone it ends in for its own NS RRset and warns when that
	// does not match what the parent delegated. It costs one more query.
	CheckNS bool

	// CheckDS asks the zone the walk ends in for the CDS and CDNSKEY records
	// it publishes, and holds them against the DS its parent holds. It costs
	// two queries, and needs DNSSEC: a request nobody signed is nobody's.
	CheckDS bool

	// Serial asks every nameserver of the zone the walk ends in for that zone's
	// start of authority, and holds the answers against each other. It costs a
	// query per nameserver, and it is the only way from outside to see a
	// secondary that is serving an older copy of a zone: it answers everything
	// correctly, and answers it out of date.
	Serial bool

	// CheckTransfer asks every nameserver of the zone the walk ends in for the
	// whole zone (AXFR), as a stranger would, and records whether it hands it
	// over. Only the start of the reply is read, and none of it is kept. It
	// needs TCP, and costs a query per nameserver.
	CheckTransfer bool

	// CheckRecursion asks every nameserver of the zone the walk ends in to
	// look up a name outside its zones, and records whether it does: an
	// authoritative server that resolves for anyone is an open resolver. It
	// costs a query per nameserver.
	CheckRecursion bool

	// CheckEDNS asks every nameserver of the zone the walk ends in for the
	// zone's SOA in the shapes RFC 8906 tests: EDNS0 alone, then an EDNS
	// version, an option and a flag nobody has defined yet, which it has to
	// answer politely. It costs up to four queries per nameserver address.
	CheckEDNS bool

	// NSID asks every server which of itself is answering (RFC 5001). An
	// anycast address is a great many machines, and this is the only thing in a
	// reply that tells them apart. It costs no query of its own.
	NSID bool

	// Cookie sends a DNS cookie to every server (RFC 7873) and records how it
	// answered. Like a client that supports them, the walk sends each server
	// back the cookie it handed out. It costs no query of its own, except a
	// second try at a server that answers BADCOOKIE.
	Cookie bool

	// Subnet rides along on every query as the client subnet of RFC 7871, so
	// that a server which tailors its answers is asked the question somebody
	// inside that prefix would be asking. The zero value sends none, which is
	// what keeps an ordinary walk from telling every server on the way down
	// where the person running it sits.
	Subnet netip.Prefix

	// Minimise asks each zone for no more of the name than it needs to say
	// where the next cut is (RFC 9156), the way resolvers do by default now. It
	// is what finds a server that denies a name only because nothing is at it
	// yet: a resolver that minimises stops there, and one that does not never
	// asks the question.
	Minimise bool

	// CAA looks for the CAA set that decides which certificate authorities may
	// issue for the name, climbing from it towards the root the way an
	// authority does (RFC 8659). Each name on the way costs a query, asked of
	// the zone the walk found it in.
	CAA bool

	// Mail looks up the MX hosts of the name and the TLSA set of each, the
	// way a sending server that checks DANE does (RFC 7672), and the MTA-STS,
	// TLS-RPT and DMARC policies beside them. Each lookup is a walk of its own
	// from the deepest zone the run has entered that the name sits in.
	Mail bool

	// SVCB follows the name's HTTPS records, or its SVCB records where those
	// are the question, to the servers a client would connect to (RFC 9460):
	// down the aliases, then to the addresses of every target, which are held
	// against the hints the records carry. Each lookup is a walk of its own,
	// like the mail check's.
	SVCB bool

	// Deps follows every nameserver of every zone the walk was referred to,
	// and of every zone those lookups are referred to in turn, to find all the
	// zones the name depends on. Each lookup is a walk of its own, like the
	// mail check's, and costs a query or more of the budget.
	Deps bool

	// Down says why a server is to be treated as unreachable, empty for one
	// that is not. A server it names is drawn among its zone's but never
	// asked, the way one of the wrong family is, and the walk goes wherever
	// it would go next. Nil leaves every server up.
	Down func(trace.Server) string

	// Try replaces the delegation of one zone, wherever the walk comes to
	// it, with nameservers of the run's choosing, so that a zone can be walked
	// as it would be once moved to them. The referral is kept as the parent
	// gave it, DS included. Nil walks the DNS as it is.
	Try *trace.Trial

	// At is the moment the walk is read as made at: its start, and the clock
	// its signatures and anchors are judged against. The zero value is now; a
	// walk replayed from a capture is given the time the capture was made.
	At time.Time

	Budget Budget
}

// Resolver answers queries by walking the delegation chain itself, never
// asking a recursive server.
type Resolver struct {
	cfg Config
}

// New checks a configuration and returns the resolver for it.
func New(cfg Config) (*Resolver, error) {
	if cfg.Transport == nil {
		return nil, errors.New("resolver: no transport to query with")
	}
	if len(cfg.Roots) == 0 {
		return nil, errors.New("resolver: no root servers to start from")
	}
	switch cfg.Family {
	case 0, 4, 6:
	default:
		return nil, fmt.Errorf("resolver: address family %d is neither 4 nor 6", cfg.Family)
	}

	// Without EDNS0 an answer has 512 bytes to fit in, which a root referral
	// already does not. A server that cannot parse it is asked again without.
	if cfg.UDPSize == 0 {
		cfg.UDPSize = transport.DefaultUDPSize
	}
	if cfg.DNSSEC {
		if len(cfg.Anchors) == 0 {
			anchors, err := roothints.DefaultAnchors()
			if err != nil {
				return nil, fmt.Errorf("resolver: reading the trust anchors: %w", err)
			}
			cfg.Anchors = anchors
		}
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Resolver{cfg: cfg}, nil
}

// RootServers turns root hints into the servers a walk starts from.
func RootServers(hints *roothints.Hints) []trace.Server {
	var servers []trace.Server
	for _, hint := range hints.Servers {
		for _, addr := range hint.Addrs {
			servers = append(servers, trace.Server{Name: hint.Name, IP: addr})
		}
	}
	return servers
}

// Askable says why name and qtype cannot be walked, nil when they can, so
// that a run of several questions can refuse one before walking any of them.
func Askable(name, qtype string) error {
	_, _, err := question(name, qtype)
	return err
}

func question(name, qtype string) (string, uint16, error) {
	qname := dnsutil.Fqdn(name)
	if !dnsutil.IsName(qname) {
		return "", 0, fmt.Errorf("%q is not a domain name", name)
	}
	rrtype, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		return "", 0, fmt.Errorf("%q is not a query type", strings.ToUpper(qtype))
	}
	return qname, rrtype, nil
}

// Resolve follows the delegation chain for name and qtype. The trace it returns
// holds everything that was learned, including the failures; an error means the
// question itself could not be asked.
func (r *Resolver) Resolve(ctx context.Context, name, qtype string) (*trace.Trace, error) {
	qname, rrtype, err := question(name, qtype)
	if err != nil {
		return nil, err
	}
	qtype = strings.ToUpper(qtype)

	run := &run{
		cfg:      r.cfg,
		counters: newCounters(r.cfg.Budget),
		chased:   map[string]bool{dnsutil.Canonical(qname): true},
		missing:  map[*trace.Step]*trace.Dangling{},
		trace: &trace.Trace{
			Question: trace.Question{Name: qname, Type: qtype, Class: "IN"},
			Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		},
	}

	if r.cfg.Cookie {
		run.secret = make([]byte, 16)
		_, _ = rand.Read(run.secret) // never fails, as of Go 1.24
		run.cookies = map[netip.Addr]string{}
	}

	run.trace.Trial = r.cfg.Try
	run.began = time.Now()
	run.trace.Started = cmp.Or(r.cfg.At, run.began)
	run.trace.Timed = true
	end := run.walk(ctx, qname, rrtype, run.trace.Root, 0)
	if r.cfg.Try != nil && !run.tried {
		run.warnf("", "the walk never came to a delegation of %s, so --try-ns changed nothing; name the zone a referral on the way delegates",
			r.cfg.Try.Zone)
	}
	if r.cfg.CAA {
		run.climb(ctx, cmp.Or(end, run.trace.Root))
	}
	if r.cfg.Mail {
		run.mail(ctx, cmp.Or(end, run.trace.Root))
	}
	if r.cfg.SVCB {
		run.svcb(ctx, cmp.Or(end, run.trace.Root), end)
	}
	if r.cfg.Deps {
		run.deps(ctx, cmp.Or(end, run.trace.Root))
	}
	run.bootstrap(ctx)
	run.trace.Elapsed = time.Since(run.began)
	return run.trace, nil
}

// hop is a step and the message behind it. The trace deliberately keeps no DNS
// records of its own, but the chain of trust has to see the real thing.
type hop struct {
	step *trace.Step
	resp *dns.Msg
}

// run is the state of one resolution.
type run struct {
	cfg      Config
	trace    *trace.Trace
	counters *counters

	// began is when the walk started on the clock, which every step's start is
	// measured from even when the trace says it was made at another time.
	began time.Time

	// chased are the names a CNAME has already pointed at, so that a chain
	// cannot bite its own tail.
	chased map[string]bool

	// missing is what each NXDOMAIN a walk ended on says is not there, until
	// the walk that asked for a nameserver or an alias target claims it.
	missing map[*trace.Step]*trace.Dangling

	// secret is what the client cookies of this run are derived from, and
	// cookies the server cookies handed out so far, by address.
	secret  []byte
	cookies map[netip.Addr]string

	// cuts are the zones the walk for the question entered, which the CAA
	// lookups and the asides are asked of, and climbing is set while the CAA ones are
	// being made.
	cuts     []cut
	climbing bool

	// aside is set while the lookups a check makes after the walk are being
	// made, whose walks keep the zones they enter for the ones after them, and
	// asideStopped once a budget of the run has cut one of them short.
	aside, asideStopped bool

	// tried is whether the walk came to the delegation --try-ns replaces.
	tried bool

	// boot is the request for a first DS that --check-ds found, whose signals
	// are looked up once the walk is over.
	boot *bootstrapping

	// mu guards the warnings and the cookies, which the fanout writes to from
	// several goroutines.
	mu sync.Mutex
}

// attach hangs a step under its parent and tells whoever is watching. Every
// hop joins the trace through here, and always from the walking goroutine, so
// a watcher reading the trace never races the walk that is building it.
func (r *run) attach(parent, step *trace.Step) {
	parent.Children = append(parent.Children, step)
	if r.cfg.Stepped != nil {
		r.cfg.Stepped(r.trace)
	}
}

// fail records why the walk stopped and returns the step that says so.
func (r *run) fail(parent *trace.Step, zone, reason string) *trace.Step {
	step := &trace.Step{Zone: zone, Kind: trace.KindError, Err: reason}
	r.attach(parent, step)
	return step
}

// warnOnceIn is warnIn for what more than one walk of a run can come across:
// an alias walks the delegations above its target again, and --all asks after
// every nameserver.
func (r *run) warnOnceIn(area trace.Area, zone, format string, args ...any) {
	warning := fmt.Sprintf(format, args...)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.trace.Warnings, warning) {
		r.warn(trace.Concern{Area: area, Zone: zone}, warning)
	}
}

// warnf records a warning, and the area of the zone's health it is about where
// it is about one, for --check to grade.
func (r *run) warnf(area trace.Area, format string, args ...any) {
	r.warnIn(area, "", format, args...)
}

// warnIn is warnf for a warning about one zone of the many a walk passes
// through, which --check holds only against that zone.
func (r *run) warnIn(area trace.Area, zone, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warn(trace.Concern{Area: area, Zone: zone}, fmt.Sprintf(format, args...))
}

func (r *run) warn(concern trace.Concern, warning string) {
	r.trace.Warnings = append(r.trace.Warnings, warning)
	if concern.Area == "" {
		return
	}
	if r.trace.About == nil {
		r.trace.About = make(map[string]trace.Concern)
	}
	r.trace.About[warning] = concern
}

// cnameTarget is what the alias for qname points at.
func cnameTarget(records []trace.RR, qname string) string {
	for _, record := range records {
		if record.Type == "CNAME" && dns.EqualName(record.Name, qname) {
			return dnsutil.Fqdn(record.Data)
		}
	}
	return ""
}

// missing are the names of a that b does not carry, compared the way DNS
// compares names.
func missing(a, b []string) []string {
	var missing []string
	for _, name := range a {
		if !slices.ContainsFunc(b, func(other string) bool { return dns.EqualName(name, other) }) {
			missing = append(missing, name)
		}
	}
	return missing
}

func skipped(zone string, server trace.Server) *trace.Step {
	return &trace.Step{Zone: zone, Server: server, Kind: trace.KindSkipped}
}

func family(addr netip.Addr) int {
	if addr.Is4() {
		return 4
	}
	return 6
}

// glueServers is the next hop: every glued address of the delegation, in the
// order the nameservers were listed.
func glueServers(delegation *trace.Delegation) []trace.Server {
	var servers []trace.Server
	for _, name := range delegation.NS {
		for _, addr := range delegation.Glue[name] {
			servers = append(servers, trace.Server{Name: name, IP: addr})
		}
	}
	return servers
}

// dedupe drops the addresses that would be queried twice, which happens as soon
// as two nameserver names resolve to the same address.
func dedupe(servers []trace.Server) []trace.Server {
	seen := make(map[netip.AddrPort]bool, len(servers))
	unique := servers[:0:0]
	for _, server := range servers {
		addr := netip.AddrPortFrom(server.IP, server.Port)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		unique = append(unique, server)
	}
	return unique
}

// soa is the start of authority in a section, nil where there is none. A denial
// carries it in place of the records it has none of, and a zone asked for it
// outright answers with it; what is kept of it is what can be read from
// outside, which is the copy being served and how long a denial from it lives.
func soa(authority []dns.RR) *trace.SOA {
	for _, rr := range authority {
		if record, ok := rr.(*dns.SOA); ok {
			return &trace.SOA{Serial: record.Serial, TTL: record.Header().TTL, Minimum: record.Minttl}
		}
	}
	return nil
}

// records flattens a section to the text the renderers work with. Signatures
// are left out: a screenful of base64 says nothing a reader can check, and the
// DNSSEC verdict on the step is what a signature is worth knowing for.
func records(rrs []dns.RR) []trace.RR {
	var records []trace.RR
	for _, rr := range rrs {
		if dns.RRToType(rr) == dns.TypeRRSIG {
			continue
		}
		records = append(records, trace.RR{
			Name:    rr.Header().Name,
			TTL:     rr.Header().TTL,
			Type:    dnsutil.TypeToString(dns.RRToType(rr)),
			Data:    fmt.Sprint(rr.Data()),
			Service: service(rr),
		})
	}
	return records
}

// service decodes an HTTPS or SVCB record, and nothing else. The text of the
// record already carries every parameter; what is pulled out here is what the
// tool has something to say about.
func service(rr dns.RR) *trace.Service {
	var data rdata.SVCB
	switch rr := rr.(type) {
	case *dns.HTTPS:
		data = rr.SVCB.SVCB
	case *dns.SVCB:
		data = rr.SVCB
	default:
		return nil
	}

	decoded := &trace.Service{Priority: data.Priority, Target: dnsutil.Fqdn(data.Target)}
	for _, pair := range data.Value {
		switch pair := pair.(type) {
		case *svcb.ALPN:
			decoded.ALPN = pair.Alpn
		case *svcb.ECHCONFIG:
			decoded.ECH = len(pair.ECH) > 0
		case *svcb.PORT:
			decoded.Port = pair.Port
		case *svcb.IPV4HINT:
			decoded.Hints = append(decoded.Hints, pair.Hint...)
		case *svcb.IPV6HINT:
			decoded.Hints = append(decoded.Hints, pair.Hint...)
		}
	}
	return decoded
}
