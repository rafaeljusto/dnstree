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

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
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
	run.trace.Started = time.Now()
	run.trace.Timed = true
	end := run.walk(ctx, qname, rrtype, run.trace.Root, 0)
	if r.cfg.Try != nil && !run.tried {
		run.warnf("the walk never came to a delegation of %s, so --try-ns changed nothing; name the zone a referral on the way delegates",
			r.cfg.Try.Zone)
	}
	if r.cfg.CAA {
		run.climb(ctx, cmp.Or(end, run.trace.Root))
	}
	run.trace.Elapsed = time.Since(run.trace.Started)
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
	// lookups are asked of, and climbing is set while they are being made.
	cuts     []cut
	climbing bool

	// tried is whether the walk came to the delegation --try-ns replaces.
	tried bool

	// mu guards the warnings and the cookies, which the fanout writes to from
	// several goroutines.
	mu sync.Mutex
}

// walk follows referrals down from the root, one zone at a time, until
// something answers or the way down runs out. Every step it makes hangs under
// parent. side is how deep this walk is nested inside the resolution of a
// nameserver's name.
func (r *run) walk(ctx context.Context, qname string, qtype uint16, parent *trace.Step, side int) *trace.Step {
	zone, servers := ".", r.cfg.Roots

	// Every walk starts again from the anchors: a walk for an alias or for a
	// nameserver's name is its own resolution, and must not borrow the keys of
	// the one that needed it.
	var chain *dnssec.Chain
	if r.cfg.DNSSEC {
		chain = dnssec.New(r.cfg.Anchors)
	}
	var delegation []dns.RR // the authority section that led into this zone

	// reach is how many labels of the name the next question in this zone asks
	// for, which is all of them unless the walk is minimising. entered is
	// whether the chain has checked this zone yet: minimising asks one zone
	// several questions, and its keys are fetched once.
	reach, entered := r.reach(zone, qname), false

	// top is the walk for the question itself, whose zones the CAA lookups go
	// to, and recorded whether this zone has been kept for them.
	top := r.cfg.CAA && side == 0 && !r.climbing && dns.EqualName(qname, r.trace.Question.Name)
	recorded := false

	// referred is the step that pointed the walk into this zone, which the
	// minimised hops inside it hang below rather than replace.
	referred := parent

	// denied is the shorter name a server said was not there, which the walk
	// has gone on to ask about in full to see whether that was so.
	var denied *trace.Step

	// pending are the nameservers of the zone named outside it that have not
	// been looked up yet, which are what is left to try once every server
	// found so far has failed.
	var pending []string

	for depth := 0; ; {
		if depth >= r.counters.max.MaxDepth {
			return r.fail(parent, zone, "gave up after "+counted(r.counters.max.MaxDepth, "zone cut"))
		}

		asked, askedType, minimised := qname, qtype, reach < dnsutil.Labels(qname)
		if minimised {
			// RFC 9156 asks for an address rather than the NS set, which some
			// servers and middleboxes answer badly.
			asked, askedType = ancestor(qname, reach), dns.TypeA
		}

		hop := r.queryZone(ctx, zone, servers, parent, asked, askedType, minimised, side)
		if hop == nil && len(pending) > 0 {
			if servers, pending = r.resolveNames(ctx, referred, pending, side, r.every(side)); len(servers) > 0 {
				continue
			}
		}
		if hop == nil {
			abandoned(referred, parent, zone)
			if !r.counters.spent() { // the tree already says the budget gave out
				r.warnf("no server answered for %s", zone)
			}
			return nil
		}
		step := hop.step

		// A server of the zone has answered, so the zone can now be asked for
		// its keys. The verdict belongs on the step that pointed here. A step
		// that names no server never got that far; today only an exhausted
		// budget leaves one, and the budget stops the DNSKEY query too, but
		// saying so here does not rely on that and reads better than "the
		// DNSKEY set could not be fetched".
		if chain != nil && !entered {
			if !step.Server.IP.IsValid() {
				referred.DNSSEC = chain.Unchecked(zone, "no server of "+zone+" answered")
			} else {
				referred.DNSSEC = r.enterZone(ctx, chain, zone, step, delegation)
			}
			entered = true
		}
		if top && !recorded && step.Server.IP.IsValid() {
			r.record(zone, servers, chain)
			recorded = true
		}

		if denied != nil && step.Kind != trace.KindNXDomain && step.Kind != trace.KindFiltered && step.Server.IP.IsValid() {
			r.warnf("%s answered NXDOMAIN for %s, which has names below it, so a resolver that minimises its questions stops there (RFC 8020); it should answer NODATA",
				at(denied), denied.Asked.Name)
		}
		denied = nil

		if minimised && step.Kind != trace.KindReferral {
			switch step.Kind {
			case trace.KindNXDomain:
				// Nothing below a name that is not there exists either, but
				// servers that say so of an empty non-terminal are common
				// enough that resolvers ask again in full, and so does this.
				denied, reach = step, dnsutil.Labels(qname)
			case trace.KindAnswer, trace.KindCNAME, trace.KindNoData:
				reach++ // no cut here, so the same zone is asked one label further
			default:
				return step // filtered, or no server left to ask
			}
			parent = step
			continue
		}

		switch {
		case step.Kind == trace.KindCNAME && qtype != dns.TypeCNAME:
			r.checkApexAlias(step, zone, qname)
			if crossed := r.verify(ctx, chain, hop, qname, qtype); crossed != nil && top {
				r.record(crossed.zone, []trace.Server{step.Server}, chain)
			}
			return r.chaseCNAME(ctx, step, qname, qtype, side)
		case step.Kind != trace.KindReferral:
			last := zoneCut{zone: zone, step: referred, authority: delegation}
			if crossed := r.verify(ctx, chain, hop, qname, qtype); crossed != nil {
				last = *crossed
				if top {
					r.record(crossed.zone, []trace.Server{step.Server}, chain)
				}
			}
			r.compact(chain, hop, qname)
			r.denial(hop, zone, qname)
			if side == 0 && !r.climbing {
				r.checkECH(step)
				r.checkSubnet(step)
				r.checkNS(ctx, step, referred)
				r.checkDS(ctx, chain, step, last)
				if len(pending) > 0 && (r.cfg.Serial || r.cfg.CheckTransfer || r.cfg.CheckRecursion || r.cfg.CheckEDNS) {
					// The probes are about every nameserver, not the one the
					// walk needed, so the names it never looked up are now.
					resolved, _ := r.resolveNames(ctx, referred, pending, side, true)
					servers = append(servers, resolved...)
				}
				r.checkSerial(ctx, step, zone, servers)
				r.checkKeys(ctx, chain, step, zone, servers)
				r.checkExposure(ctx, step, zone, servers)
				r.checkEDNS(ctx, step, zone, servers)
			}
			return step

		}

		if crossed := r.crossReferral(ctx, chain, hop); crossed != nil && top {
			r.record(crossed.zone, []trace.Server{step.Server}, chain)
		}
		var next []trace.Server
		var rest []string
		if r.cfg.Try != nil && dns.EqualName(step.Delegation.Zone, r.cfg.Try.Zone) {
			next, rest = r.trialServers(ctx, step, side)
		} else {
			next, rest = r.nextServers(ctx, step, side)
		}
		if len(next) == 0 {
			if !r.counters.spent() {
				r.warnf("the delegation to %s came with no usable address", step.Delegation.Zone)
			}
			return step
		}
		pending = rest
		zone, servers, parent, referred = step.Delegation.Zone, next, step, step
		reach, entered, recorded = r.reach(zone, qname), false, false
		depth++
		delegation = nil
		if hop.resp != nil {
			delegation = hop.resp.Ns
		}
	}
}

// every reports whether a walk asks every nameserver of a zone. All is about
// the question itself: under it, the lookup of a nameserver's address fanning
// out to every server of every zone above it would spend the budget long
// before the zone the question is about was asked at all.
func (r *run) every(side int) bool {
	return r.cfg.All && side == 0
}

// reach is how many labels of qname the first question put to zone asks for:
// one more than the zone has when minimising, and the whole name otherwise.
func (r *run) reach(zone, qname string) int {
	if !r.cfg.Minimise {
		return dnsutil.Labels(qname)
	}
	return dnsutil.Labels(zone) + 1
}

// ancestor is the name made of the last labels of name.
func ancestor(name string, labels int) string {
	offset := 0
	for range dnsutil.Labels(name) - labels {
		offset, _ = dnsutil.Next(name, offset)
	}
	return name[offset:]
}

// enterZone fetches the keys of the zone the walk has reached and checks them
// against the DS its parent handed out. The query hangs under the hop that
// reached the zone; the verdict belongs further up, on the step that pointed
// here, because that is the one that published the DS.
func (r *run) enterZone(ctx context.Context, chain *dnssec.Chain, zone string, reached *trace.Step, delegation []dns.RR) *trace.DNSSECStatus {
	var keys []dns.RR
	// Once the chain has left secure there is no way back to it, so there is
	// nothing left to learn from the keys below. The budget is asked second:
	// a slot spent here is a query that never goes out.
	if chain.State() == trace.Secure && r.counters.query() == nil {
		hop := r.query(ctx, zone, reached.Server, zone, dns.TypeDNSKEY)
		hop.step.Aside = true
		hop.step.Records = nil // a key set is not something to read in a tree
		hop.step.Notes = append(hop.step.Notes, "DNSKEY of "+zone)
		r.attach(reached, hop.step)

		if hop.resp != nil {
			keys = hop.resp.Answer
		}
	}
	return chain.Enter(zone, delegation, keys)
}

// zoneCut is the zone cut the walk last crossed: the zone below it, the step that
// carries its verdict, and the authority its DS came in.
type zoneCut struct {
	zone      string
	step      *trace.Step
	authority []dns.RR
}

// verify checks the signatures over an answer, once the zone that gave it is
// known to be trustworthy. It hands back the cut it crossed on the way, where
// the answer came from below one no referral pointed at.
func (r *run) verify(ctx context.Context, chain *dnssec.Chain, hop *hop, qname string, qtype uint16) *zoneCut {
	if chain == nil || hop.resp == nil {
		return nil
	}
	crossed := r.crossCut(ctx, chain, hop, signerOf(hop.resp, qname), qname)
	// The authority section comes too: an answer with no records is denied
	// there rather than answered, and the denial is what makes it checkable.
	hop.step.DNSSEC = chain.Verify(hop.resp.Answer, hop.resp.Ns, hop.resp.Rcode, qname, qtype)
	return crossed
}

// crossReferral enters the zone a referral came from when the walk was never
// referred to it: a server holding both br. and net.br. hands out the
// delegations of net.br., signed with its keys, to a walk still holding those
// of br.
func (r *run) crossReferral(ctx context.Context, chain *dnssec.Chain, hop *hop) *zoneCut {
	if chain == nil || hop.resp == nil || hop.step.Delegation == nil {
		return nil
	}
	// The delegation's own name is the child's word; crossCut turns away
	// anything below it.
	cut, delegated := referralSigner(hop.resp), hop.step.Delegation.Zone
	if cut == "" || dns.EqualName(cut, delegated) {
		return nil
	}
	return r.crossCut(ctx, chain, hop, cut, delegated)
}

// crossCut enters a zone the walk was never referred to. A server authoritative
// for a child as well as for the zone it was asked about answers across the cut
// without a referral, which leaves the chain holding the parent's keys and the
// answer signed with the child's. The signatures name the zone to enter, and
// its DS comes from the same server, which serves the parent side of the cut.
func (r *run) crossCut(ctx context.Context, chain *dnssec.Chain, hop *hop, cut, qname string) *zoneCut {
	if chain.State() != trace.Secure {
		return nil
	}
	zone := hop.step.Zone
	if cut == "" || dns.EqualName(cut, zone) || !dnsutil.IsBelow(zone, cut) {
		return nil
	}
	// The signer is the server's word. A cut the name is not under is not one
	// this answer crossed, and entering it would trade the zone's keys for
	// those of any insecure delegation the server cared to name.
	if !dnsutil.IsBelow(cut, qname) {
		return nil
	}
	if err := r.counters.query(); err != nil {
		chain.Unchecked(cut, "the budget ran out before the DS of "+cut+" could be fetched")
		return nil
	}

	ds := r.query(ctx, zone, hop.step.Server, cut, dns.TypeDS)
	ds.step.Aside = true
	ds.step.Records = nil // the verdict is what the DS is worth reading for
	ds.step.Notes = append(ds.step.Notes, "DS of "+cut)
	r.attach(hop.step, ds.step)

	// A DS that never arrived is not a DS the parent does not publish, so the
	// cut is left unchecked rather than called insecure.
	if ds.resp == nil {
		ds.step.DNSSEC = chain.Unchecked(cut, "the DS of "+cut+" could not be fetched")
		return nil
	}

	// The verdict belongs on the step that published the DS, the way a
	// referral's does: it is the same zone cut, crossed without one. A DS that
	// is not there is denied in the authority section rather than answered, so
	// both are handed over.
	authority := append(append([]dns.RR{}, ds.resp.Answer...), ds.resp.Ns...)
	ds.step.DNSSEC = r.enterZone(ctx, chain, cut, hop.step, authority)
	return &zoneCut{zone: cut, step: ds.step, authority: authority}
}

// signerOf is the zone that signed a response, as its signatures name it. It is
// the only thing in a message that says a zone cut was crossed.
//
// An answer names its zone in the records that answer; an empty one has none to
// name it with, so the denial does it instead. Both a NODATA and an NXDOMAIN
// carry the zone's own SOA, and the signature over that is made by the apex of
// the zone that made the denial.
func signerOf(resp *dns.Msg, qname string) string {
	for _, rr := range resp.Answer {
		signature, ok := rr.(*dns.RRSIG)
		if !ok || !dns.EqualName(signature.Hdr.Name, qname) {
			continue
		}
		return dnsutil.Fqdn(signature.SignerName)
	}
	for _, rr := range resp.Ns {
		if signature, ok := rr.(*dns.RRSIG); ok && signature.TypeCovered == dns.TypeSOA {
			return dnsutil.Fqdn(signature.SignerName)
		}
	}
	return ""
}

// referralSigner is the zone that made a referral. The DS it carries, or the
// denial of one, is signed on the parent side of the cut.
func referralSigner(resp *dns.Msg) string {
	for _, rr := range resp.Ns {
		signature, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		switch signature.TypeCovered {
		case dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
			return dnsutil.Fqdn(signature.SignerName)
		}
	}
	return ""
}

// queryZone asks the servers of one zone. By default it stops at the first that
// is any use and shows the rest as unqueried; with All it asks every one of
// them. It returns nil when none of them was any use.
//
// minimised marks every hop as asking less than the whole name, which keeps what
// they come back with from being read as the resolution's answer.
func (r *run) queryZone(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16, minimised bool, side int) *hop {
	var usable []trace.Server
	for _, server := range dedupe(servers) {
		// A server of the wrong family is shown rather than hidden: a zone
		// reachable over one protocol only is worth seeing.
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			skipped := skipped(zone, server)
			skipped.Notes = []string{fmt.Sprintf("no IPv%d address", r.cfg.Family)}
			r.attach(parent, skipped)
			continue
		}
		if r.cfg.Down != nil {
			if why := r.cfg.Down(server); why != "" {
				skipped := skipped(zone, server)
				skipped.Notes = []string{why}
				r.attach(parent, skipped)
				continue
			}
		}
		usable = append(usable, server)
	}

	if r.every(side) {
		return r.queryAll(ctx, zone, usable, parent, qname, qtype, minimised)
	}
	return r.queryFirst(ctx, zone, usable, parent, qname, qtype, minimised)
}

// queryFirst is the default strategy: ask until one of them answers.
func (r *run) queryFirst(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16, minimised bool) *hop {
	for i, server := range servers {
		if err := r.counters.query(); err != nil {
			return &hop{step: r.fail(parent, zone, err.Error())}
		}

		hop := r.query(ctx, zone, server, qname, qtype)
		minimise(hop.step, minimised)
		r.attach(parent, hop.step)
		switch hop.step.Kind {
		case trace.KindLame, trace.KindTimeout, trace.KindError:
			continue
		}

		rest := servers[i+1:]
		for _, server := range rest[:min(len(rest), maxSkipped)] {
			r.attach(parent, skipped(zone, server))
		}
		if more := len(rest) - maxSkipped; more > 0 {
			summary := &trace.Step{Zone: zone, Kind: trace.KindSkipped,
				Notes: []string{fmt.Sprintf("and %d more not queried", more)}}
			r.attach(parent, summary)
		}
		return hop
	}
	return nil
}

// queryAll asks every server at once, a few at a time, and keeps them in the
// order they were delegated so that the tree stays the same between runs.
func (r *run) queryAll(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16, minimised bool) *hop {
	var budget error
	for i := range servers {
		if err := r.counters.query(); err != nil {
			servers, budget = servers[:i], err
			break
		}
	}

	hops := make([]*hop, len(servers))
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, server := range servers {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			hops[i] = r.query(ctx, zone, server, qname, qtype)
		})
	}
	wait.Wait()

	for _, hop := range hops {
		minimise(hop.step, minimised)
		r.attach(parent, hop.step)
	}
	if budget != nil {
		r.fail(parent, zone, budget.Error())
	}

	r.compareAnswers(zone, qname, qtype, hops)

	for _, hop := range hops {
		switch hop.step.Kind {
		case trace.KindLame, trace.KindTimeout, trace.KindError:
			continue
		}
		return hop
	}
	return nil
}

// minimise marks a hop that asked for less of the name than the walk is after,
// and says in its margin what it asked, since that is not the question above.
func minimise(step *trace.Step, minimised bool) {
	if !minimised {
		return
	}
	step.Minimised = true
	step.Notes = append(step.Notes, "minimised to "+step.Asked.Name)
}

// compareAnswers warns where the nameservers of one zone answer the same
// question differently. Only --all asks more than one of them, so only --all
// can see it: a walk that stops at the first server to answer has one answer
// and nothing to hold it against.
//
// A difference is not by itself a fault — a zone served by something that
// answers by where the question came from will do this honestly, and so will an
// RRset caught mid-change — but it is never nothing, and nothing else in a
// trace says it.
func (r *run) compareAnswers(zone, qname string, qtype uint16, hops []*hop) {
	typeName := dnsutil.TypeToString(qtype)

	name := naming(hops)
	var order []string
	saying := make(map[string][]string)
	for _, hop := range hops {
		switch hop.step.Kind {
		case trace.KindAnswer, trace.KindCNAME, trace.KindNoData, trace.KindNXDomain:
		default:
			continue // a server that said nothing is not a server that disagreed
		}
		what := said(hop.step, typeName)
		if _, seen := saying[what]; !seen {
			order = append(order, what)
		}
		saying[what] = append(saying[what], name(hop.step))
	}
	if len(order) < 2 {
		return
	}

	differing := make([]string, 0, len(order))
	for _, answer := range order {
		differing = append(differing, answer+" at "+strings.Join(saying[answer], " and "))
	}
	r.warnf("the nameservers of %s do not answer %s %s alike: %s",
		zone, qname, typeName, strings.Join(differing, ", "))
}

// said is what a hop said about the name, as one string to hold against
// another: the records where there are any, and what the hop was where there
// are none, since a name that is not there is an answer as much as a name that
// is. The records are sorted and deduplicated, so a server rotating an RRset
// between one question and the next is not a server that disagrees.
func said(step *trace.Step, qtype string) string {
	if data := trace.Answers(step.Records, qtype); len(data) > 0 {
		return strings.Join(data, " ")
	}
	return string(step.Kind)
}

// query is one hop: a single question to a single server, including whatever it
// took to get a whole answer out of it.
func (r *run) query(ctx context.Context, zone string, server trace.Server, qname string, qtype uint16) *hop {
	// Glue carries addresses and never ports, so the transport says where to
	// knock, unless the server was named with a port of its own.
	port := server.Port
	server.Port = cmp.Or(port, r.cfg.Transport.Port())
	if r.cfg.Discovered != nil {
		r.cfg.Discovered(server.IP)
	}
	if r.cfg.Asking != nil {
		if done := r.cfg.Asking(zone, server); done != nil {
			defer done()
		}
	}
	step := &trace.Step{
		Zone:   zone,
		Server: server,
		Proto:  r.cfg.Transport.Proto(),
		Asked:  trace.Question{Name: qname, Type: dnsutil.TypeToString(qtype)},
		Start:  time.Since(r.trace.Started),
	}

	udpSize := r.cfg.UDPSize
	carrier := r.cfg.Transport
	resp, err := r.exchange(ctx, step, carrier, qname, qtype, udpSize, port)

	// A server that does not speak the transport asked for is the ordinary case
	// for DoT and DoH, so plain DNS can be allowed to pick the hop up.
	if err != nil && r.cfg.Fallback != nil {
		if retry, fallbackErr := r.exchange(ctx, step, r.cfg.Fallback, qname, qtype, udpSize, port); fallbackErr == nil {
			step.Notes = append(step.Notes, step.Proto+" did not get through, asked over "+r.cfg.Fallback.Proto())
			step.Proto = r.cfg.Fallback.Proto()
			step.Server.Port = cmp.Or(port, r.cfg.Fallback.Port())
			carrier = r.cfg.Fallback
			resp, err = retry, nil
		}
	}
	if err != nil {
		// An error can quote the server, a TLS one the names on its certificate.
		step.Kind, step.Err = trace.KindError, trace.Printable(err.Error(), trace.MaxErr)
		switch {
		case errors.Is(err, context.Canceled):
			step.Err = "interrupted before the server answered" // the user's doing, not the server's
		case transport.IsTimeout(err):
			step.Kind = trace.KindTimeout
		}
		return &hop{step: step}
	}

	// A server that cannot parse EDNS0 gets the question again without it.
	if udpSize > 0 && (resp.Rcode == dns.RcodeFormatError || resp.Rcode == dns.RcodeNotImplemented) {
		udpSize = 0
		if retry, err := r.exchange(ctx, step, r.cfg.Transport, qname, qtype, udpSize, port); err == nil {
			resp = retry
			step.Notes = append(step.Notes, "retried without EDNS0")
		}
	}

	// A server that insists on a cookie of its own hands one out with
	// BADCOOKIE, and is asked again with it (RFC 7873 section 5.3). Once: a
	// server that turns down its own cookie has nothing more to say.
	var cookieRetried bool
	if resp.Rcode == dns.RcodeBadCookie && r.cookie(step.Server.IP) != "" {
		if state, _ := transport.EchoedCookie(resp, r.clientCookie(step.Server.IP)); state == trace.CookieSupported {
			if retry, err := r.exchange(ctx, step, carrier, qname, qtype, udpSize, port); err == nil {
				resp, cookieRetried = retry, true
				step.Notes = append(step.Notes, "asked again with the server's cookie")
			}
		}
	}

	// An answer that did not fit has to be fetched again over TCP.
	if resp.Truncated && r.cfg.TCP != nil && step.Proto != r.cfg.TCP.Proto() {
		retry, retryErr := r.exchange(ctx, step, r.cfg.TCP, qname, qtype, udpSize, port)
		if retryErr != nil {
			step.Notes = append(step.Notes,
				"truncated over "+step.Proto+", and "+r.cfg.TCP.Proto()+" did not get through")
		} else {
			step.Notes = append(step.Notes, "truncated over "+step.Proto)
			step.Proto = r.cfg.TCP.Proto()
			resp = retry
		}
	}

	// What arrived, and what it had to fit in. The limit is the transport's
	// rather than the question's, so it belongs to whichever attempt the hop
	// kept: an answer refetched over TCP was bounded by nothing, whatever the
	// datagram that failed before it advertised.
	step.Size = len(resp.Data)
	if step.Proto == transport.ProtoUDP {
		step.Limit = int(cmp.Or(udpSize, dns.MinMsgSize))
	}

	// What is left of a truncated message is not what the server holds, and
	// reading it as one would turn a dropped section into a statement about
	// the zone: a missing answer into NODATA, a missing NS set into a lame
	// server. The hop says the answer could not be fetched whole instead.
	if resp.Truncated {
		step.Rcode = dnsutil.RcodeToString(resp.Rcode)
		step.Extended = transport.Extended(resp)
		step.Flags.TC = true
		step.Kind = trace.KindError
		step.Err = "the answer did not fit and could not be fetched whole"
		if r.cfg.TCP == nil {
			step.Err += "; no TCP transport to fetch it with"
		}
		r.warnf("%s answered %s truncated, and the whole answer could not be fetched",
			step.Server.IP, qname)
		return &hop{step: step}
	}

	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	step.Extended = transport.Extended(resp)
	step.Subnet = transport.EchoedSubnet(resp)
	step.NSID = transport.EchoedNSID(resp)
	step.ReportTo = transport.ReportChannel(resp)
	if r.cfg.Cookie && udpSize > 0 && transport.CarriesCookie(step.Proto) {
		step.Cookie, _ = transport.EchoedCookie(resp, r.clientCookie(step.Server.IP))
		switch {
		case step.Cookie == trace.CookieSupported && resp.Rcode == dns.RcodeBadCookie && cookieRetried:
			step.Cookie = trace.CookieRejected
		case step.Cookie == trace.CookieMismatch:
			r.warnf("%s answered with a client cookie other than the one sent, so the answer may not be its own",
				step.Server.IP)
		}
	}
	step.Flags = trace.Flags{
		AA:   resp.Authoritative,
		TC:   resp.Truncated,
		AD:   resp.AuthenticatedData,
		DO:   resp.Security,
		EDNS: resp.UDPSize > 0,
	}
	step.Kind, step.Delegation = classify(resp, zone, qname, qtype, step.Extended)

	switch step.Kind {
	case trace.KindAnswer, trace.KindCNAME:
		step.Records = records(resp.Answer)
	case trace.KindNoData, trace.KindNXDomain:
		step.SOA = soa(resp.Ns)
	}
	return &hop{step: step, resp: resp}
}

// exchange sends one message and adds what it cost to the step. A server that
// stays silent is asked again, since a lost datagram is not an answer.
//
// Shape, where it is given, changes the query before it is sent.
func (r *run) exchange(ctx context.Context, step *trace.Step, carrier transport.Transport, qname string, qtype uint16, udpSize, port uint16, shape ...func(*dns.Msg)) (*dns.Msg, error) {
	server := netip.AddrPortFrom(step.Server.IP, cmp.Or(port, carrier.Port()))

	var err error
	silences := -1 // the note that counts them, once there is one
	for attempt := 0; ; attempt++ {
		var req *dns.Msg
		if req, err = transport.NewQuery(qname, qtype, udpSize, r.cfg.DNSSEC); err != nil {
			return nil, err
		}
		transport.WithSubnet(req, r.cfg.Subnet)
		for _, change := range shape {
			change(req)
		}
		if r.cfg.NSID {
			transport.WithNSID(req)
		}
		cookie := r.cfg.Cookie && transport.CarriesCookie(carrier.Proto())
		if cookie {
			transport.WithCookie(req, r.clientCookie(server.Addr()), r.cookie(server.Addr()))
		}

		var (
			resp *dns.Msg
			rtt  time.Duration
		)
		resp, rtt, err = carrier.Exchange(ctx, req, server, step.Server.Name)
		step.RTT += rtt
		if cookie && err == nil {
			r.remember(server.Addr(), resp)
		}

		r.cfg.Log.Debug("asked a nameserver",
			"zone", step.Zone, "server", server, "proto", carrier.Proto(),
			"name", qname, "type", qtype, "rtt", rtt, "error", err)

		if err == nil || attempt >= r.cfg.Retries || !transport.IsTimeout(err) {
			return resp, err
		}
		if silences < 0 {
			silences = len(step.Notes)
			step.Notes = append(step.Notes, "asked again after a silence")
		} else {
			step.Notes[silences] = fmt.Sprintf("asked again after %d silences", attempt+1)
		}
	}
}

// clientCookie is the client half of the cookie a server is sent.
func (r *run) clientCookie(server netip.Addr) string {
	return transport.ClientCookie(r.secret, server)
}

// cookie is the server cookie a server handed out, empty before it has.
func (r *run) cookie(server netip.Addr) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cookies[server]
}

// remember keeps the server cookie a reply handed out, so that the server is
// sent it next time. Only a reply to our own client cookie can hand one out.
func (r *run) remember(server netip.Addr, resp *dns.Msg) {
	state, cookie := transport.EchoedCookie(resp, r.clientCookie(server))
	if state != trace.CookieSupported {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cookies[server] = cookie
}

// nextServers is where the walk goes after a referral: the glue when there is
// any, and otherwise the addresses of the nameservers named outside the zone,
// resolved on their own. It hands back the names it has not looked up yet, for
// the walk to try if every server it has so far fails. All looks them all up
// at once, since it asks every nameserver there is.
func (r *run) nextServers(ctx context.Context, step *trace.Step, side int) ([]trace.Server, []string) {
	delegation := step.Delegation

	for _, name := range delegation.NS {
		if addressShaped(name) {
			r.warnOnce("%s delegates to %s, which is an address written as a name, and nothing resolves it; name the nameserver instead (RFC 1035 section 3.3.11)",
				delegation.Zone, name)
		}
	}
	if len(delegation.GlueLess) > 0 {
		r.warnf("%s delegates to %s inside the zone, with no glue to reach them",
			delegation.Zone, strings.Join(delegation.GlueLess, ", "))
	}
	servers, pending := glueServers(delegation), delegation.OutOfBailiwick
	if len(pending) == 0 {
		return servers, nil
	}
	if side >= maxSideResolution {
		if len(servers) == 0 {
			r.warnf("the nameservers of %s are named too far away to keep chasing", delegation.Zone)
		}
		return servers, nil
	}
	if len(servers) > 0 && !r.every(side) {
		return servers, pending
	}
	resolved, pending := r.resolveNames(ctx, step, pending, side, r.every(side))
	return append(servers, resolved...), pending
}

// trialServers is where the walk goes after the referral --try-ns replaces:
// the servers it named, rather than the ones the parent did. The referral is
// left as the parent gave it, and marked, so that what was replaced is drawn.
// A nameserver named without an address is looked up the way one named outside
// its zone is.
func (r *run) trialServers(ctx context.Context, step *trace.Step, side int) ([]trace.Server, []string) {
	trial := r.cfg.Try
	r.tried = true
	step.Notes = append(step.Notes, "replaced by --try-ns")

	var (
		servers []trace.Server
		names   []string
	)
	for _, name := range trial.NS {
		addrs, given := trial.Addrs[name]
		if !given {
			names = append(names, name)
			continue
		}
		for _, addr := range addrs {
			server := trace.Server{Name: name, IP: addr}
			if _, err := netip.ParseAddr(name); err == nil {
				server.Name = "" // named by its address alone
			}
			servers = append(servers, server)
		}
	}
	if len(names) == 0 || side >= maxSideResolution {
		return servers, nil
	}
	if len(servers) > 0 && !r.every(side) {
		return servers, names
	}
	resolved, pending := r.resolveNames(ctx, step, names, side, r.every(side))
	return append(servers, resolved...), pending
}

// resolveNames looks up the addresses of nameservers named outside the zone
// they serve, each with a walk of its own under the referral that named them.
// It stops at the first that has any unless every is set, and hands back the
// names it did not get to.
func (r *run) resolveNames(ctx context.Context, step *trace.Step, names []string, side int, every bool) ([]trace.Server, []string) {
	rrtype, typeName := uint16(dns.TypeA), "A"
	if r.cfg.Family == 6 {
		rrtype, typeName = dns.TypeAAAA, "AAAA"
	}

	var servers []trace.Server
	for i, name := range names {
		// Past the budget, one walk has already said it gave up; the rest
		// would only say it again.
		if i > 0 && r.counters.spent() {
			return servers, names[i:]
		}
		root := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true,
			Notes: []string{"resolving " + name}}
		r.attach(step, root)

		result := r.walk(ctx, name, rrtype, root, side+1)
		if target := aliasUnder(root, name); target != "" {
			r.warnAliasedNS(step.Delegation.Zone, name, target)
		}
		if result == nil {
			continue
		}
		claim(result, r.orphan(result), trace.DanglingNameserver, step.Delegation.Zone, step.Delegation.Zone)
		for _, record := range result.Records {
			// A server may answer with more than was asked for. Only the
			// records the name itself owns are addresses of that nameserver.
			if record.Type != typeName || !dns.EqualName(record.Name, name) {
				continue
			}
			// The model keeps rdata as text, and an address is its own text.
			if addr, err := netip.ParseAddr(record.Data); err == nil {
				servers = append(servers, trace.Server{Name: name, IP: addr})
			}
		}
		if len(servers) > 0 && !every {
			return servers, names[i+1:] // one nameserver we can reach is enough to go on
		}
	}
	return servers, nil
}

// chaseCNAME starts again from the root for the name the alias points at, as a
// branch under the answer that gave it.
func (r *run) chaseCNAME(ctx context.Context, step *trace.Step, qname string, qtype uint16, side int) *trace.Step {
	target := cnameTarget(step.Records, qname)
	if target == "" {
		r.warnf("%s is an alias for a name the answer did not carry", qname)
		return step
	}
	// Names are compared the way DNS compares them: B.x and b.x are one name,
	// and a loop spelled in both would otherwise run until the budget ended it.
	if r.chased[dnsutil.Canonical(target)] {
		r.warnf("the alias chain for %s comes back to %s", qname, target)
		return step
	}
	if err := r.counters.cname(); err != nil {
		return r.fail(step, step.Zone, err.Error())
	}
	r.chased[dnsutil.Canonical(target)] = true

	root := &trace.Step{Zone: ".", Kind: trace.KindZone, Notes: []string{"resolving " + target}}
	r.attach(step, root)
	result := r.walk(ctx, target, qtype, root, side)
	if result != nil {
		claim(result, r.orphan(result), trace.DanglingAlias, qname, step.Zone)
	}
	return result
}

// compact turns a NODATA into the NXDOMAIN it is, where the zone signed a
// record at the name saying it is not there (RFC 9824). Online signers answer
// every missing name this way, and read as a NODATA it is a name that exists,
// which --expect and every sentence about it would repeat. One nothing signed
// stays a NODATA: it is only a server's word.
func (r *run) compact(chain *dnssec.Chain, hop *hop, qname string) {
	step := hop.step
	if chain == nil || hop.resp == nil || step.Kind != trace.KindNoData {
		return
	}
	claimed, proved := chain.Compact(hop.resp.Ns, qname)
	switch {
	case proved && step.DNSSEC != nil && step.DNSSEC.State == trace.Secure:
		step.Kind, step.Compact = trace.KindNXDomain, true
		step.DNSSEC.Reason = "proved that " + qname + " does not exist"
		step.Notes = append(step.Notes, "compact denial, RFC 9824")
	case claimed:
		step.Notes = append(step.Notes, "NXNAME, unproved")
	}
}

// checkECH warns when an answer publishes an encrypted client hello that
// nothing here could vouch for. ECH hides the name a client is about to ask
// for, and the configuration doing the hiding rides in this very answer:
// whatever can rewrite the answer can drop the configuration out of it, and a
// client that finds none falls back to sending the name in the clear. Only a
// signature says that did not happen on the way.
func (r *run) checkECH(step *trace.Step) {
	name := ""
	for _, record := range step.Records {
		if record.Service != nil && record.Service.ECH {
			name = record.Name
			break
		}
	}
	if name == "" {
		return
	}

	switch {
	case !r.cfg.DNSSEC:
		r.warnf("%s publishes an ECH configuration, and without --dnssec nothing here checked that it arrived as the zone wrote it", name)
	case step.DNSSEC == nil:
		r.warnf("%s publishes an ECH configuration in an answer whose signatures were never checked", name)
	case step.DNSSEC.State != trace.Secure:
		r.warnf("%s publishes an ECH configuration in an answer that is %s, so a client cannot tell whether it was stripped on the way",
			name, step.DNSSEC.State)
	}
}

// checkSubnet warns when the server that answered ignored the client subnet.
// The answer is then whatever that server tells everybody, rather than what it
// would tell somebody inside the prefix, which is the only reason to have sent
// one.
func (r *run) checkSubnet(step *trace.Step) {
	if !r.cfg.Subnet.IsValid() || step.Subnet != nil {
		return
	}
	who := step.Server.Name
	if who == "" {
		who = step.Server.IP.String()
	}
	r.warnf("%s ignored the client subnet, so this answer is not tailored to %s", who, r.cfg.Subnet)
}

// checkNS asks the zone that answered for its own NS RRset and warns when it
// disagrees with what the parent delegated. Only the parent's view is visible
// from above, so the two drift apart unnoticed.
func (r *run) checkNS(ctx context.Context, answer *trace.Step, parent *trace.Step) {
	if !r.cfg.CheckNS || parent.Delegation == nil {
		return
	}
	delegated := parent.Delegation
	if err := r.counters.query(); err != nil {
		return
	}

	step := r.query(ctx, delegated.Zone, answer.Server, delegated.Zone, dns.TypeNS).step
	step.Aside = true
	step.Notes = append(step.Notes, "parent/child NS check")
	r.attach(answer, step)

	child := make([]string, 0, len(step.Records))
	for _, record := range step.Records {
		if record.Type == "NS" && dns.EqualName(record.Name, delegated.Zone) {
			if len(child) == 0 {
				delegated.ZoneTTL = record.TTL // an RRset carries one TTL
			}
			child = append(child, record.Data)
		}
	}
	step.Records = nil // the comparison is the point, not the records

	if len(child) == 0 {
		r.warnf("%s did not return its own NS records", delegated.Zone)
	} else {
		if missing := missing(delegated.NS, child); len(missing) > 0 {
			r.warnf("%s delegates to %s, which the zone itself does not list",
				delegated.Zone, strings.Join(missing, ", "))
		}
		if extra := missing(child, delegated.NS); len(extra) > 0 {
			r.warnf("%s lists %s, which the delegation does not carry",
				delegated.Zone, strings.Join(extra, ", "))
		}
	}
	r.checkGlue(ctx, step, answer.Server, parent.Zone, delegated)
}

// checkGlue asks the zone for the addresses of the nameservers named inside
// it, and holds them against the glue its parent handed out. Glue is a copy,
// made when the nameserver was registered, and nothing tells the registry when
// the zone renumbers one: resolvers go on trying the old address first, and
// whoever holds it next answers for the zone.
//
// A nameserver named outside the zone is not the zone's to say anything about,
// and one with no glue at all is warned about where the referral is followed.
// The questions go out together and hang under the NS check once they are all
// back, from the goroutine doing the walking.
func (r *run) checkGlue(ctx context.Context, check *trace.Step, server trace.Server, parent string, delegated *trace.Delegation) {
	type question struct {
		name   string
		rrtype uint16
	}
	var questions []question
	for _, name := range delegated.NS {
		if len(delegated.Glue[name]) == 0 || !dnsutil.IsBelow(delegated.Zone, name) {
			continue
		}
		questions = append(questions, question{name, dns.TypeA}, question{name, dns.TypeAAAA})
	}

	var budget error
	for i := range questions {
		if err := r.counters.query(); err != nil {
			questions, budget = questions[:i], err
			break
		}
	}

	hops := make([]*hop, len(questions))
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, q := range questions {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			hops[i] = r.query(ctx, delegated.Zone, server, q.name, q.rrtype)
		})
	}
	wait.Wait()

	for i, hop := range hops {
		q, step := questions[i], hop.step
		step.Aside = true
		step.Notes = append(step.Notes, "glue check: "+dnsutil.TypeToString(q.rrtype)+" of "+q.name)
		held := addresses(step.Records, q.name, q.rrtype)
		if step.Kind == trace.KindCNAME {
			r.warnAliasedNS(delegated.Zone, q.name, cnameTarget(step.Records, q.name))
		}
		step.Records = nil // the comparison is the point, and it is on the delegation
		r.attach(check, step)

		if step.Kind != trace.KindAnswer && step.Kind != trace.KindNoData {
			continue // a server that did not say is not a zone that disagrees
		}
		if delegated.ZoneAddrs == nil {
			delegated.ZoneAddrs = make(map[string][]netip.Addr)
		}
		delegated.ZoneAddrs[q.name] = append(delegated.ZoneAddrs[q.name], held...)
		glue := delegated.Glue[q.name]
		r.compareGlue(parent, delegated.Zone, q.name,
			ofFamily(glue, q.rrtype), ofFamily(glue, otherFamily(q.rrtype)), held, q.rrtype)
	}
	if budget != nil {
		r.warnf("the budget ran out before the glue of %s could be checked", delegated.Zone)
	}
}

// warnAliasedNS says a nameserver's name is an alias. A resolver looking up
// the address of a nameserver is not required to follow one (RFC 2181 section
// 10.3), so the zone resolves through some resolvers and not others, and this
// walk, which does not follow it, may not reach the zone at all.
func (r *run) warnAliasedNS(zone, name, target string) {
	r.warnOnce("%s delegates to %s, which is an alias for %s; name the nameserver by its own name, since resolvers need not follow an alias to find one (RFC 2181 section 10.3)",
		zone, name, target)
}

// checkApexAlias warns about an alias at the top of a zone. An alias may not
// share its name with anything else (RFC 1034 section 3.6.2), and the apex
// always holds the zone's SOA and NS, so one there hides them from whoever asks.
// A provider that flattens an alias there answers with the addresses instead,
// and that is never seen here.
func (r *run) checkApexAlias(step *trace.Step, zone, qname string) {
	if !step.Flags.AA || !dns.EqualName(zone, qname) || zone == "." {
		return
	}
	r.warnOnce("%s is an alias at the top of its zone, which hides the zone's SOA and NS from every resolver that asks (RFC 1034 section 3.6.2); serve the records there rather than an alias",
		zone)
}

// aliasUnder is what name is an alias for, as the walk below root found it,
// and empty where it found no alias for it.
func aliasUnder(root *trace.Step, name string) string {
	for _, step := range root.Children {
		if step.Kind == trace.KindCNAME && !step.Aside {
			if target := cnameTarget(step.Records, name); target != "" {
				return target
			}
		}
		if target := aliasUnder(step, name); target != "" {
			return target
		}
	}
	return ""
}

// addressShaped reports whether a nameserver's name is an address written as
// one, which looks right to a person and is a name nobody can resolve.
func addressShaped(name string) bool {
	_, err := netip.ParseAddr(strings.TrimSuffix(name, "."))
	return err == nil
}

// compareGlue warns where the glue of one family disagrees with what the zone
// gives. The order is no part of it: both are sets.
func (r *run) compareGlue(parent, zone, name string, glue, other, held []netip.Addr, rrtype uint16) {
	slices.SortFunc(glue, netip.Addr.Compare)
	slices.SortFunc(held, netip.Addr.Compare)
	glue, held = slices.Compact(glue), slices.Compact(held)
	switch {
	case slices.Equal(glue, held):
	case len(glue) == 0 && len(other) > 0:
		r.warnf("%s hands out no %s address for %s, which %s gives as %s; have the registrar add it to the glue",
			parent, familyName(rrtype), name, zone, joinAddrs(held))
	case len(held) == 0:
		r.warnf("%s hands out %s for %s, which %s itself does not give; have the registrar remove it from the glue",
			parent, joinAddrs(glue), name, zone)
	default:
		r.warnf("%s hands out %s for %s, which %s itself gives as %s; have the registrar update the glue",
			parent, joinAddrs(glue), name, zone, joinAddrs(held))
	}
}

// addresses are the addresses of one type that name owns among records.
func addresses(records []trace.RR, name string, rrtype uint16) []netip.Addr {
	var found []netip.Addr
	for _, record := range records {
		if record.Type != dnsutil.TypeToString(rrtype) || !dns.EqualName(record.Name, name) {
			continue
		}
		if addr, err := netip.ParseAddr(record.Data); err == nil {
			found = append(found, addr)
		}
	}
	return found
}

// ofFamily are the addresses an A or an AAAA query would be answered with.
func ofFamily(addrs []netip.Addr, rrtype uint16) []netip.Addr {
	var found []netip.Addr
	for _, addr := range addrs {
		if addr.Is4() == (rrtype == dns.TypeA) {
			found = append(found, addr)
		}
	}
	return found
}

func otherFamily(rrtype uint16) uint16 {
	if rrtype == dns.TypeA {
		return dns.TypeAAAA
	}
	return dns.TypeA
}

func familyName(rrtype uint16) string {
	if rrtype == dns.TypeA {
		return "IPv4"
	}
	return "IPv6"
}

func joinAddrs(addrs []netip.Addr) string {
	text := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		text = append(text, addr.String())
	}
	return strings.Join(text, " and ")
}

// checkDS asks the zone the walk ended in what it wants its parent to publish,
// and holds that against what the parent does publish. A zone rolls its key by
// putting the new one in its CDS and waiting for the parent to notice, so the
// two disagreeing is a rollover stuck halfway, and nothing else in a walk says
// so: the chain is secure throughout.
//
// The request counts only once the zone's own keys have signed it, the way a
// parent that acts on it checks it (RFC 7344 4.1). An unsigned one is anyone's,
// and a zone that proves it has none is asking for nothing.
func (r *run) checkDS(ctx context.Context, chain *dnssec.Chain, answer *trace.Step, last zoneCut) {
	// The root has no parent to ask anything of.
	if !r.cfg.CheckDS || chain == nil || last.step.DNSSEC == nil || last.zone == "." {
		return
	}
	zone, verdict := last.zone, last.step.DNSSEC
	// Only a zone the chain entered secure has keys to check the request with.
	// Anywhere else the verdict already says why, and the request is left.
	if verdict.State != trace.Secure || chain.State() != trace.Secure || !dns.EqualName(chain.Zone(), zone) {
		verdict.Signal = &trace.Signal{State: trace.SignalUnchecked,
			Reason: "the chain of trust did not reach " + zone + " secure"}
		return
	}

	var fetched [2][]dns.RR
	for i, qtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY} {
		records, reason := r.fetchSigned(ctx, chain, answer, zone, qtype)
		if reason != "" {
			verdict.Signal = &trace.Signal{State: trace.SignalUnchecked, Reason: reason}
			r.warnf("the request %s makes of its parent could not be checked: %s", zone, reason)
			return
		}
		fetched[i] = records
	}

	signal := dnssec.Signal(last.authority, zone, fetched[0], fetched[1])
	verdict.Signal = signal
	switch signal.State {
	case trace.SignalPending:
		r.warnf("%s asks its parent for a DS it does not publish (%s), so a key rollover is waiting on the parent; if it has waited longer than the parent polls, ask the registrar why",
			zone, signal.Reason)
	case trace.SignalDelete:
		r.warnf("%s asks its parent to remove its DS (RFC 8078), which leaves it unsigned once the parent acts; if that is not the plan, remove its CDS and CDNSKEY",
			zone)
	case trace.SignalInconsistent:
		r.warnf("the CDS and CDNSKEY of %s do not describe the same keys (%s), so a parent acts on neither; publish both from one key set",
			zone, signal.Reason)
	}
}

// fetchSigned asks the server that answered for one of the zone's records at
// its apex, and hands back the ones the zone's keys signed. It says why where
// there is nothing it can vouch for: an answer that did not come, or did not
// verify. A zone that proves it has none of them hands back nothing.
func (r *run) fetchSigned(ctx context.Context, chain *dnssec.Chain, answer *trace.Step, zone string, qtype uint16) ([]dns.RR, string) {
	name := dnsutil.TypeToString(qtype)
	if err := r.counters.query(); err != nil {
		return nil, "the budget ran out before the " + name + " could be fetched"
	}

	hop := r.query(ctx, zone, answer.Server, zone, qtype)
	hop.step.Aside = true
	hop.step.Records = nil // the comparison is the point, and it is on the verdict
	hop.step.Notes = append(hop.step.Notes, name+" of "+zone)
	r.attach(answer, hop.step)

	if hop.resp == nil || (hop.step.Kind != trace.KindAnswer && hop.step.Kind != trace.KindNoData) {
		return nil, "the " + name + " could not be fetched"
	}
	status := chain.Verify(hop.resp.Answer, hop.resp.Ns, hop.resp.Rcode, zone, qtype)
	if status.State != trace.Secure {
		return nil, "the " + name + " is " + string(status.State) + ": " + status.Reason
	}
	return hop.resp.Answer, ""
}

// checkSerial asks every nameserver of the zone the walk ended in which copy of
// that zone it is serving. Only the parent's list says who they all are, and a
// walk stops at the first that answers, so a secondary left behind by a zone
// transfer is invisible to everything else here: it answers the question
// correctly, out of an older zone.
//
// The queries go out together and join the trace afterwards, the way --all's
// do, because a step may only be attached from the goroutine doing the walking.
func (r *run) checkSerial(ctx context.Context, answer *trace.Step, zone string, servers []trace.Server) {
	if !r.cfg.Serial {
		return
	}

	var usable []trace.Server
	for _, server := range dedupe(servers) {
		// A server of the wrong family was never asked the question either, so
		// holding the zone against it here would be holding it against a
		// nameserver this walk has nothing to say about.
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		usable = append(usable, server)
	}

	var budget error
	for i := range usable {
		if err := r.counters.query(); err != nil {
			usable, budget = usable[:i], err
			break
		}
	}

	hops := make([]*hop, len(usable))
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, server := range usable {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			hops[i] = r.query(ctx, zone, server, zone, dns.TypeSOA)
		})
	}
	wait.Wait()

	for _, hop := range hops {
		step := hop.step
		if hop.resp != nil {
			step.SOA = soa(hop.resp.Answer)
		}
		step.Aside = true
		step.Records = nil // the serial is the point, and it is on the step
		step.Notes = append(step.Notes, serialNote(zone, step.SOA))
		r.attach(answer, step)
	}
	if budget != nil {
		r.warnf("the budget ran out before every nameserver of %s could be asked for its serial", zone)
	}
	r.compareSerials(zone, hops)
}

// checkKeys asks every nameserver of the zone the walk ended in for the keys it
// publishes and the key it signs with, and warns where one signs with a key
// another does not publish. A validating resolver fetches the keys from one
// server, keeps them, and checks what every other server says against them, so
// a zone signed by two providers at once (RFC 8901), a rollover done on some
// servers only, or an anycast site left behind fails for some resolvers some of
// the time — and a walk asking one server sees nothing wrong.
//
// It takes --all, which is what says the whole set is wanted, and a zone the
// chain reached secure, since only then are its keys worth comparing. The
// questions go out together and join the trace afterwards, from the goroutine
// doing the walking.
func (r *run) checkKeys(ctx context.Context, chain *dnssec.Chain, answer *trace.Step, zone string, servers []trace.Server) {
	if !r.cfg.All || chain == nil || chain.State() != trace.Secure || !dns.EqualName(chain.Zone(), zone) {
		return
	}

	type question struct {
		server trace.Server
		rrtype uint16
	}
	var questions []question
	for _, server := range dedupe(servers) {
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		if r.cfg.Down != nil && r.cfg.Down(server) != "" {
			continue
		}
		questions = append(questions, question{server, dns.TypeDNSKEY}, question{server, dns.TypeSOA})
	}

	var budget error
	for i := range questions {
		if err := r.counters.query(); err != nil {
			questions, budget = questions[:i], err
			break
		}
	}

	hops := make([]*hop, len(questions))
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, q := range questions {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			hops[i] = r.query(ctx, zone, q.server, zone, q.rrtype)
		})
	}
	wait.Wait()

	// What each server publishes and signs with, by address, in the order the
	// servers were delegated. One name can stand for several addresses, and
	// an anycast site left behind is one address of it.
	var order []netip.AddrPort
	named := make(map[string]int)
	label := make(map[netip.AddrPort]string)
	published := make(map[netip.AddrPort][]uint16)
	signing := make(map[netip.AddrPort][]uint16)
	for i, hop := range hops {
		step := hop.step
		step.Aside = true
		step.Records = nil // the comparison is the point
		addr := netip.AddrPortFrom(step.Server.IP, step.Server.Port)
		if _, seen := label[addr]; !seen {
			order = append(order, addr)
			label[addr] = at(step)
			named[at(step)]++
		}
		switch {
		case hop.resp == nil || step.Kind != trace.KindAnswer:
			step.Notes = append(step.Notes, "keys check: "+dnsutil.TypeToString(questions[i].rrtype)+" of "+zone)
		case questions[i].rrtype == dns.TypeDNSKEY:
			tags := keyTags(hop.resp.Answer, zone)
			published[addr] = tags
			step.Notes = append(step.Notes, "keys check: publishes "+joinTags(tags))
		default:
			tags := signerTags(hop.resp.Answer, zone, dns.TypeSOA)
			signing[addr] = tags
			step.Notes = append(step.Notes, "keys check: signs with "+joinTags(tags))
		}
		r.attach(answer, step)
	}
	for addr, name := range label {
		if named[name] > 1 {
			label[addr] = name + " at " + addr.Addr().String()
		}
	}

	// One warning a key, however many addresses sign with it or lack it: a
	// large zone has dozens, and one site left behind is one fault.
	var tags []uint16
	for _, signer := range order {
		for _, tag := range signing[signer] {
			if !slices.Contains(tags, tag) {
				tags = append(tags, tag)
			}
		}
	}
	for _, tag := range tags {
		var signers, lacking []string
		for _, addr := range order {
			if slices.Contains(signing[addr], tag) {
				signers = append(signers, label[addr])
			}
			if keys, asked := published[addr]; asked && !slices.Contains(keys, tag) {
				lacking = append(lacking, label[addr])
			}
		}
		if len(lacking) == 0 {
			continue
		}
		r.warnf("the nameservers of %s do not publish the same keys: %s %s key %d, which %s %s with, so a resolver that took the keys from %s rejects what %s answers; publish every signer's keys from every nameserver (RFC 8901)",
			zone, strings.Join(lacking, " and "), verb(lacking, "lacks", "lack"), tag,
			strings.Join(signers, " and "), verb(signers, "signs", "sign"),
			orList(lacking), orList(signers))
	}
	if budget != nil {
		r.warnf("the budget ran out before every nameserver of %s could be asked for its keys", zone)
	}
}

// keyTags are the tags of the zone keys a DNSKEY answer publishes, sorted.
func keyTags(answer []dns.RR, zone string) []uint16 {
	var tags []uint16
	for _, rr := range answer {
		if key, ok := rr.(*dns.DNSKEY); ok && dns.EqualName(key.Hdr.Name, zone) {
			tags = append(tags, key.KeyTag())
		}
	}
	slices.Sort(tags)
	return slices.Compact(tags)
}

// signerTags are the tags of the keys the zone's signatures over one type name,
// sorted. They are what the server says it signed with, and checking them is
// the walk's job: this only holds one server's word against another's.
func signerTags(answer []dns.RR, zone string, covered uint16) []uint16 {
	var tags []uint16
	for _, rr := range answer {
		if signature, ok := rr.(*dns.RRSIG); ok && signature.TypeCovered == covered && dns.EqualName(signature.SignerName, zone) {
			tags = append(tags, signature.KeyTag)
		}
	}
	slices.Sort(tags)
	return slices.Compact(tags)
}

// verb is the form of a verb that agrees with a list of names.
func verb(names []string, one, many string) string {
	if len(names) == 1 {
		return one
	}
	return many
}

// orList is a list of names as "any of them" reads.
func orList(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return "any of " + strings.Join(names, ", ")
}

func joinTags(tags []uint16) string {
	if len(tags) == 0 {
		return "none"
	}
	text := make([]string, 0, len(tags))
	for _, tag := range tags {
		text = append(text, fmt.Sprint(tag))
	}
	return strings.Join(text, " ")
}

// checkExposure asks every nameserver of the zone the walk ended in for what it
// should keep from strangers: the whole zone, and a lookup of somebody else's
// name. Like checkSerial the questions go out together and join the trace
// afterwards, from the goroutine doing the walking.
//
// The root is left alone. Its servers hand the zone to anyone on purpose (RFC
// 8806), and a name outside the root's zones does not exist to be asked.
func (r *run) checkExposure(ctx context.Context, answer *trace.Step, zone string, servers []trace.Server) {
	if (!r.cfg.CheckTransfer && !r.cfg.CheckRecursion) || zone == "." {
		return
	}

	// A transfer is a stream over TCP (RFC 5936). A walk over DoT can ask it
	// over TLS, which is how XoT carries one (RFC 9103); DoH carries none.
	transfer := r.cfg.TCP
	if transfer == nil {
		switch r.cfg.Transport.Proto() {
		case transport.ProtoTCP, transport.ProtoDoT:
			transfer = r.cfg.Transport
		}
	}
	checkTransfer := r.cfg.CheckTransfer
	if checkTransfer && transfer == nil {
		checkTransfer = false
		r.warnf("zone transfers of %s were not checked: they need tcp, and %s carries none; walk with --udp, --tcp or --dot to check them",
			zone, r.cfg.Transport.Proto())
	}

	type probe struct {
		server trace.Server
		kind   trace.ProbeKind
	}
	var probes []probe
	for _, server := range dedupe(servers) {
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		if checkTransfer {
			probes = append(probes, probe{server, trace.ProbeTransfer})
		}
		if r.cfg.CheckRecursion {
			probes = append(probes, probe{server, trace.ProbeRecursion})
		}
	}

	var budget error
	for i := range probes {
		if err := r.counters.query(); err != nil {
			probes, budget = probes[:i], err
			break
		}
	}

	steps := make([]*trace.Step, len(probes))
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, p := range probes {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			switch p.kind {
			case trace.ProbeTransfer:
				steps[i] = r.probe(ctx, zone, p.server, transfer, zone, dns.TypeAXFR, p.kind, false, transferred)
			case trace.ProbeRecursion:
				steps[i] = r.probe(ctx, zone, p.server, r.cfg.Transport, ".", dns.TypeNS, p.kind, true, recursed)
			}
		})
	}
	wait.Wait()

	for _, step := range steps {
		r.attach(answer, step)
	}
	if budget != nil {
		r.warnf("the budget ran out before every nameserver of %s could be checked for what it gives strangers", zone)
	}
}

// probe asks one server one of the questions checkExposure puts, and reads the
// answer with open. Whatever came back is dropped once it has been read: the
// zone a server should not have handed over is not ours to keep or draw.
func (r *run) probe(ctx context.Context, zone string, server trace.Server, carrier transport.Transport,
	qname string, qtype uint16, kind trace.ProbeKind, recurse bool, open func(*dns.Msg, string) bool) *trace.Step {

	port := server.Port
	server.Port = cmp.Or(port, carrier.Port())
	if r.cfg.Asking != nil {
		if done := r.cfg.Asking(zone, server); done != nil {
			defer done()
		}
	}
	step := &trace.Step{
		Zone:   zone,
		Server: server,
		Proto:  carrier.Proto(),
		Asked:  trace.Question{Name: qname, Type: dnsutil.TypeToString(qtype)},
		Start:  time.Since(r.trace.Started),
		Aside:  true,
		Probe:  &trace.Probe{Kind: kind, State: trace.ProbeUnchecked},
	}
	desire := func(req *dns.Msg) { req.RecursionDesired = recurse }

	udpSize := r.cfg.UDPSize
	resp, err := r.exchange(ctx, step, carrier, qname, qtype, udpSize, port, desire)

	// A lookup can go wherever the walk's own questions went, plain DNS
	// included. A transfer cannot: the fallback is a datagram.
	if err != nil && kind == trace.ProbeRecursion && r.cfg.Fallback != nil {
		if retry, fallbackErr := r.exchange(ctx, step, r.cfg.Fallback, qname, qtype, udpSize, port, desire); fallbackErr == nil {
			step.Notes = append(step.Notes, carrier.Proto()+" did not get through, asked over "+r.cfg.Fallback.Proto())
			carrier = r.cfg.Fallback
			step.Proto = carrier.Proto()
			step.Server.Port = cmp.Or(port, carrier.Port())
			resp, err = retry, nil
		}
	}
	if err == nil && udpSize > 0 && (resp.Rcode == dns.RcodeFormatError || resp.Rcode == dns.RcodeNotImplemented) {
		if retry, retryErr := r.exchange(ctx, step, carrier, qname, qtype, 0, port, desire); retryErr == nil {
			resp = retry
			step.Notes = append(step.Notes, "retried without EDNS0")
		}
	}
	if err == nil && resp.Truncated && r.cfg.TCP != nil && carrier.Proto() != r.cfg.TCP.Proto() {
		if retry, retryErr := r.exchange(ctx, step, r.cfg.TCP, qname, qtype, udpSize, port, desire); retryErr == nil {
			resp = retry
			step.Proto = r.cfg.TCP.Proto()
			step.Notes = append(step.Notes, "truncated over "+carrier.Proto())
		}
	}
	switch {
	case err != nil:
		step.Kind, step.Err = trace.KindError, trace.Printable(err.Error(), trace.MaxErr)
		if transport.IsTimeout(err) {
			step.Kind = trace.KindTimeout
		}
		// A connection taken and then reset once the AXFR was in is how some
		// providers refuse a transfer, Route 53 among them. One never taken
		// says nothing of what the server would have done, and stays unchecked,
		// and so does a reset over TLS, which may have come before the AXFR.
		if kind == trace.ProbeTransfer && carrier.Proto() == transport.ProtoTCP && transport.IsReset(err) {
			step.Probe.State = trace.ProbeClosed
			step.Notes = append(step.Notes, "reset, which is how some servers refuse a transfer")
		}
		return step
	case resp.Truncated:
		// What is missing from a truncated reply could be the very records
		// that would have said it was open.
		step.Kind, step.Err = trace.KindError, "the answer did not fit and could not be fetched whole"
		return step
	}

	step.Kind = trace.KindAnswer
	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	step.Size = len(resp.Data)
	step.Flags = trace.Flags{AA: resp.Authoritative, EDNS: resp.UDPSize > 0}
	step.Probe.State = trace.ProbeClosed
	if open(resp, zone) {
		step.Probe.State = trace.ProbeOpen
	}
	return step
}

// ednsFlag and ednsOption are what RFC 8906 sends as the flag and the option
// nobody has defined: sections 8.2.4 and 8.2.3, as dig's +ednsflags=0x40 and
// +ednsopt=100 put them.
const (
	ednsFlag   = 0x40
	ednsOption = 100
)

// checkEDNS puts the questions of RFC 8906 to every nameserver of the zone the
// walk ended in. Every server is asked the baseline first, and only one that
// passed it is asked the rest: a server that cannot answer EDNS0, or does not
// serve the zone, would fail them all for the same reason. The servers are
// asked side by side and join the trace afterwards, from the goroutine doing
// the walking.
func (r *run) checkEDNS(ctx context.Context, answer *trace.Step, zone string, servers []trace.Server) {
	if !r.cfg.CheckEDNS {
		return
	}

	var (
		asked  []trace.Server
		budget error
	)
	for _, server := range dedupe(servers) {
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		if budget = r.counters.query(); budget != nil {
			break
		}
		asked = append(asked, server)
	}
	steps := make([][]*trace.Step, len(asked))
	askEach(asked, func(i int, server trace.Server) {
		steps[i] = []*trace.Step{r.askEDNS(ctx, zone, server, trace.EDNSPlain)}
	})

	// The rest cost three queries a server, spent whole or not at all.
	var passed []int
	for i, hops := range steps {
		if budget != nil || hops[0].EDNS.State != trace.EDNSOK {
			continue
		}
		for range 3 {
			if budget = r.counters.query(); budget != nil {
				break
			}
		}
		if budget == nil {
			passed = append(passed, i)
		}
	}
	askEach(passed, func(_ int, i int) {
		for _, kind := range []trace.EDNSKind{trace.EDNSVersion, trace.EDNSOption, trace.EDNSFlag} {
			step := r.askEDNS(ctx, zone, asked[i], kind)
			if step.Kind == trace.KindTimeout {
				// The baseline got through, so silence here is the answer.
				step.EDNS.State, step.EDNS.Fault = trace.EDNSBroken, trace.EDNSSilent
			}
			steps[i] = append(steps[i], step)
		}
	})

	for _, hops := range steps {
		for _, step := range hops {
			r.attach(answer, step)
		}
	}
	if budget != nil {
		r.warnf("the budget ran out before every nameserver of %s could be checked for how it handles edns; raise --max-queries to check them all", zone)
	}
}

// askEach runs ask for every item side by side, no more than maxParallel
// at once, and returns when all of them have.
func askEach[T any](items []T, ask func(int, T)) {
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, item := range items {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			ask(i, item)
		})
	}
	wait.Wait()
}

// askEDNS asks one server for the zone's SOA in one of the shapes checkEDNS
// tests, and reads the reply against RFC 8906. It never asks again without
// EDNS0, which would hide the very thing being tested.
func (r *run) askEDNS(ctx context.Context, zone string, server trace.Server, kind trace.EDNSKind) *trace.Step {
	carrier := r.cfg.Transport
	port := server.Port
	server.Port = cmp.Or(port, carrier.Port())
	if r.cfg.Asking != nil {
		if done := r.cfg.Asking(zone, server); done != nil {
			defer done()
		}
	}
	step := &trace.Step{
		Zone:   zone,
		Server: server,
		Proto:  carrier.Proto(),
		Asked:  trace.Question{Name: zone, Type: "SOA"},
		Start:  time.Since(r.trace.Started),
		Aside:  true,
		EDNS:   &trace.EDNSTest{Kind: kind, State: trace.EDNSUnchecked},
	}
	shape := func(req *dns.Msg) {
		switch kind {
		case trace.EDNSVersion:
			req.Version = 1
		case trace.EDNSOption:
			req.Pseudo = append(req.Pseudo, &dns.ERFC3597{EDNS0Code: ednsOption})
		case trace.EDNSFlag:
			req.Z = ednsFlag
		}
	}

	udpSize := r.cfg.UDPSize
	resp, err := r.exchange(ctx, step, carrier, zone, dns.TypeSOA, udpSize, port, shape)
	if err != nil && r.cfg.Fallback != nil {
		if retry, fallbackErr := r.exchange(ctx, step, r.cfg.Fallback, zone, dns.TypeSOA, udpSize, port, shape); fallbackErr == nil {
			step.Notes = append(step.Notes, carrier.Proto()+" did not get through, asked over "+r.cfg.Fallback.Proto())
			carrier = r.cfg.Fallback
			step.Proto = carrier.Proto()
			step.Server.Port = cmp.Or(port, carrier.Port())
			resp, err = retry, nil
		}
	}
	if err == nil && resp.Truncated && r.cfg.TCP != nil && carrier.Proto() != r.cfg.TCP.Proto() {
		if retry, retryErr := r.exchange(ctx, step, r.cfg.TCP, zone, dns.TypeSOA, udpSize, port, shape); retryErr == nil {
			resp = retry
			step.Proto = r.cfg.TCP.Proto()
			step.Notes = append(step.Notes, "truncated over "+carrier.Proto())
		}
	}
	switch {
	case err != nil:
		step.Kind, step.Err = trace.KindError, trace.Printable(err.Error(), trace.MaxErr)
		if transport.IsTimeout(err) {
			step.Kind = trace.KindTimeout
		}
		return step
	case resp.Truncated:
		// What a truncated reply leaves out is no fault of the server's.
		step.Kind, step.Err = trace.KindError, "the answer did not fit and could not be fetched whole"
		return step
	}

	step.Kind = trace.KindAnswer
	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	if resp.Rcode == dns.RcodeBadVers {
		step.Rcode = "BADVERS" // the library names 16 after TSIG's BADSIG
	}
	step.Size = len(resp.Data)
	step.Flags = trace.Flags{AA: resp.Authoritative, EDNS: resp.UDPSize > 0}
	step.EDNS.State, step.EDNS.Fault = trace.EDNSOK, ednsFault(resp, zone, kind)
	if step.EDNS.Fault == "" {
		return step
	}
	// A baseline refused, or answered without the SOA, is a server that does
	// not serve the zone (RFC 8906 8.1.1), which says nothing about EDNS. Only
	// FORMERR and NOTIMP are a server that cannot parse it.
	lame := step.EDNS.Fault == trace.EDNSNoSOA ||
		step.EDNS.Fault == trace.EDNSRcode && resp.Rcode != dns.RcodeFormatError && resp.Rcode != dns.RcodeNotImplemented
	if kind == trace.EDNSPlain && lame {
		step.EDNS.State, step.EDNS.Fault = trace.EDNSUnchecked, ""
		step.Notes = append(step.Notes, "does not serve the zone")
		return step
	}
	step.EDNS.State = trace.EDNSBroken
	return step
}

// ednsFault is what a reply got wrong against what RFC 8906 section 8 expects
// of it, empty when nothing. Every shape is answered with an OPT record of
// version 0; an unknown version is BADVERS without the answer (RFC 6891
// 6.1.3), and everything else NOERROR with the SOA, the unknown option or flag
// ignored rather than copied back.
func ednsFault(resp *dns.Msg, zone string, kind trace.EDNSKind) trace.EDNSFault {
	want := dns.RcodeSuccess
	if kind == trace.EDNSVersion {
		want = dns.RcodeBadVers
	}
	switch {
	case int(resp.Rcode) != want:
		return trace.EDNSRcode
	case resp.UDPSize == 0:
		return trace.EDNSNoOPT
	case resp.Version != 0:
		return trace.EDNSBadVers
	}

	carries := false
	for _, rr := range resp.Answer {
		if dns.RRToType(rr) == dns.TypeSOA && dns.EqualName(rr.Header().Name, zone) {
			carries = true
		}
	}
	switch kind {
	case trace.EDNSVersion:
		if carries {
			return trace.EDNSAnswer
		}
		return ""
	case trace.EDNSFlag:
		if resp.Z&ednsFlag != 0 {
			return trace.EDNSEchoed
		}
	case trace.EDNSOption:
		for _, rr := range resp.Pseudo {
			if unknown, ok := rr.(*dns.ERFC3597); ok && unknown.EDNS0Code == ednsOption {
				return trace.EDNSEchoed
			}
		}
	}
	if !carries {
		return trace.EDNSNoSOA
	}
	return ""
}

// transferred reports whether a reply to an AXFR is the zone: a transfer opens
// with the zone's own SOA (RFC 5936 2.2). A refusal, or anything else, is not.
func transferred(resp *dns.Msg, zone string) bool {
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return false
	}
	first := resp.Answer[0]
	return dns.RRToType(first) == dns.TypeSOA && dns.EqualName(first.Header().Name, zone)
}

// recursed reports whether a reply to the root's NS set, asked of a server
// that does not serve the root, is a lookup done for us. It goes by what came
// back and not by RA, which servers set without recursing. An authoritative
// answer is a server holding a copy of the root, which is not a resolver.
func recursed(resp *dns.Msg, _ string) bool {
	if resp.Rcode != dns.RcodeSuccess || resp.Authoritative {
		return false
	}
	for _, rr := range resp.Answer {
		if dns.RRToType(rr) == dns.TypeNS && dns.EqualName(rr.Header().Name, ".") {
			return true
		}
	}
	return false
}

// serialNote labels the aside for a reader of the tree. A server that answered
// with no SOA is labelled by what it was asked rather than by what it gave,
// since the step itself already says how the query went.
func serialNote(zone string, soa *trace.SOA) string {
	if soa == nil {
		return "SOA of " + zone
	}
	return fmt.Sprintf("SOA of %s: %d", zone, soa.Serial)
}

// compareSerials warns where the nameservers of a zone do not hold the same
// copy of it. Which serial is the newer one is deliberately not claimed: serial
// arithmetic wraps (RFC 1982), and a walk that named the wrong one as behind
// would send somebody to restart the wrong server.
func (r *run) compareSerials(zone string, hops []*hop) {
	name := naming(hops)
	var order []uint32
	serving := make(map[uint32][]string)
	for _, hop := range hops {
		if hop.step.SOA == nil {
			continue
		}
		serial := hop.step.SOA.Serial
		if _, seen := serving[serial]; !seen {
			order = append(order, serial)
		}
		serving[serial] = append(serving[serial], name(hop.step))
	}
	if len(order) < 2 {
		return
	}

	held := make([]string, 0, len(order))
	for _, serial := range order {
		held = append(held, fmt.Sprintf("%d at %s", serial, strings.Join(serving[serial], " and ")))
	}
	r.warnf("the nameservers of %s are serving different copies of it: %s", zone, strings.Join(held, ", "))
}

// at is a server as a reader would name it.
func at(step *trace.Step) string {
	if step.Server.Name != "" {
		return step.Server.Name
	}
	return step.Server.IP.String()
}

// naming names the servers of a sweep, with the address where one name stands
// for several: anycast sites behind one name can disagree, and naming only the
// host would put it on both sides.
func naming(hops []*hop) func(*trace.Step) string {
	addrs := make(map[string]map[netip.Addr]bool)
	for _, hop := range hops {
		name := at(hop.step)
		if addrs[name] == nil {
			addrs[name] = make(map[netip.Addr]bool)
		}
		addrs[name][hop.step.Server.IP] = true
	}
	return func(step *trace.Step) string {
		name := at(step)
		if len(addrs[name]) > 1 {
			return name + " (" + step.Server.IP.String() + ")"
		}
		return name
	}
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

// warnOnce is warnf for what more than one walk of a run can come across: an
// alias walks the delegations above its target again, and --all asks after
// every nameserver.
func (r *run) warnOnce(format string, args ...any) {
	warning := fmt.Sprintf(format, args...)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.trace.Warnings, warning) {
		r.trace.Warnings = append(r.trace.Warnings, warning)
	}
}

func (r *run) warnf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trace.Warnings = append(r.trace.Warnings, fmt.Sprintf(format, args...))
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
		found := false
		for _, other := range b {
			if dns.EqualName(name, other) {
				found = true
				break
			}
		}
		if !found {
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
		}
	}
	return decoded
}
