// Package resolver walks the delegation chain from the root down to the
// authoritative servers, classifying every response and recording each hop in
// the trace.
package resolver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"codeberg.org/miekg/dns/svcb"

	"github.com/rafaeljusto/dnstree/internal/dnssec"
	"github.com/rafaeljusto/dnstree/internal/roothints"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
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
	// that answers. The walk still follows a single path down.
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

	// Serial asks every nameserver of the zone the walk ends in for that zone's
	// start of authority, and holds the answers against each other. It costs a
	// query per nameserver, and it is the only way from outside to see a
	// secondary that is serving an older copy of a zone: it answers everything
	// correctly, and answers it out of date.
	Serial bool

	// NSID asks every server which of itself is answering (RFC 5001). An
	// anycast address is a great many machines, and this is the only thing in a
	// reply that tells them apart. It costs no query of its own.
	NSID bool

	// Subnet rides along on every query as the client subnet of RFC 7871, so
	// that a server which tailors its answers is asked the question somebody
	// inside that prefix would be asking. The zero value sends none, which is
	// what keeps an ordinary walk from telling every server on the way down
	// where the person running it sits.
	Subnet netip.Prefix

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

// Resolve follows the delegation chain for name and qtype. The trace it returns
// holds everything that was learned, including the failures; an error means the
// question itself could not be asked.
func (r *Resolver) Resolve(ctx context.Context, name, qtype string) (*trace.Trace, error) {
	qname := dnsutil.Fqdn(name)
	if !dnsutil.IsName(qname) {
		return nil, fmt.Errorf("resolver: %q is not a domain name", name)
	}
	qtype = strings.ToUpper(qtype)
	rrtype, ok := dns.StringToType[qtype]
	if !ok {
		return nil, fmt.Errorf("resolver: unknown query type %q", qtype)
	}

	run := &run{
		cfg:      r.cfg,
		counters: newCounters(r.cfg.Budget),
		chased:   map[string]bool{qname: true},
		trace: &trace.Trace{
			Question: trace.Question{Name: qname, Type: qtype, Class: "IN"},
			Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		},
	}

	start := time.Now()
	run.walk(ctx, qname, rrtype, run.trace.Root, 0)
	run.trace.Elapsed = time.Since(start)
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

	// mu guards the warnings, which the fanout writes to from several goroutines.
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

	for depth := 0; ; depth++ {
		if depth >= r.counters.max.MaxDepth {
			return r.fail(parent, zone, fmt.Sprintf("gave up after %d zone cuts", r.counters.max.MaxDepth))
		}

		hop := r.queryZone(ctx, zone, servers, parent, qname, qtype)
		if hop == nil {
			r.warnf("no server answered for %s", zone)
			return nil
		}
		step := hop.step

		// A server of the zone has answered, so the zone can now be asked for
		// its keys. The verdict belongs on the step that pointed here. A step
		// that names no server never got that far; today only an exhausted
		// budget leaves one, and the budget stops the DNSKEY query too, but
		// saying so here does not rely on that and reads better than "the
		// DNSKEY set could not be fetched".
		if chain != nil {
			if !step.Server.IP.IsValid() {
				parent.DNSSEC = chain.Unchecked(zone, "no server of "+zone+" answered")
			} else {
				parent.DNSSEC = r.enterZone(ctx, chain, zone, step, delegation)
			}
		}

		switch {
		case step.Kind == trace.KindCNAME && qtype != dns.TypeCNAME:
			r.verify(ctx, chain, hop, qname, qtype)
			return r.chaseCNAME(ctx, step, qname, qtype, side)
		case step.Kind != trace.KindReferral:
			r.verify(ctx, chain, hop, qname, qtype)
			if side == 0 {
				r.checkECH(step)
				r.checkSubnet(step)
				r.checkNS(ctx, step, parent)
				r.checkSerial(ctx, step, zone, servers)
			}
			return step

		}

		next := r.nextServers(ctx, step, side)
		if len(next) == 0 {
			r.warnf("the delegation to %s came with no usable address", step.Delegation.Zone)
			return step
		}
		zone, servers, parent = step.Delegation.Zone, next, step
		delegation = nil
		if hop.resp != nil {
			delegation = hop.resp.Ns
		}
	}
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

// verify checks the signatures over an answer, once the zone that gave it is
// known to be trustworthy.
func (r *run) verify(ctx context.Context, chain *dnssec.Chain, hop *hop, qname string, qtype uint16) {
	if chain == nil || hop.resp == nil {
		return
	}
	r.crossCut(ctx, chain, hop, qname)
	// The authority section comes too: an answer with no records is denied
	// there rather than answered, and the denial is what makes it checkable.
	hop.step.DNSSEC = chain.Verify(hop.resp.Answer, hop.resp.Ns, hop.resp.Rcode, qname, qtype)
}

// crossCut enters a zone the walk was never referred to. A server authoritative
// for a child as well as for the zone it was asked about answers across the cut
// without a referral, which leaves the chain holding the parent's keys and the
// answer signed with the child's. The signatures name the zone to enter, and
// its DS comes from the same server, which serves the parent side of the cut.
func (r *run) crossCut(ctx context.Context, chain *dnssec.Chain, hop *hop, qname string) {
	if chain.State() != trace.Secure {
		return
	}
	zone := hop.step.Zone
	cut := signerOf(hop.resp, qname)
	if cut == "" || dns.EqualName(cut, zone) || !dnsutil.IsBelow(zone, cut) {
		return
	}
	if err := r.counters.query(); err != nil {
		chain.Unchecked(cut, "the budget ran out before the DS of "+cut+" could be fetched")
		return
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
		return
	}

	// The verdict belongs on the step that published the DS, the way a
	// referral's does: it is the same zone cut, crossed without one. A DS that
	// is not there is denied in the authority section rather than answered, so
	// both are handed over.
	ds.step.DNSSEC = r.enterZone(ctx, chain, cut, hop.step,
		append(append([]dns.RR{}, ds.resp.Answer...), ds.resp.Ns...))
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

// queryZone asks the servers of one zone. By default it stops at the first that
// is any use and shows the rest as unqueried; with All it asks every one of
// them. It returns nil when none of them was any use.
func (r *run) queryZone(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16) *hop {
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
		usable = append(usable, server)
	}

	if r.cfg.All {
		return r.queryAll(ctx, zone, usable, parent, qname, qtype)
	}
	return r.queryFirst(ctx, zone, usable, parent, qname, qtype)
}

// queryFirst is the default strategy: ask until one of them answers.
func (r *run) queryFirst(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16) *hop {
	for i, server := range servers {
		if err := r.counters.query(); err != nil {
			return &hop{step: r.fail(parent, zone, err.Error())}
		}

		hop := r.query(ctx, zone, server, qname, qtype)
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
func (r *run) queryAll(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16) *hop {
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
		saying[what] = append(saying[what], at(hop.step))
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
	}

	udpSize := r.cfg.UDPSize
	resp, err := r.exchange(ctx, step, r.cfg.Transport, qname, qtype, udpSize, port)

	// A server that does not speak the transport asked for is the ordinary case
	// for DoT and DoH, so plain DNS can be allowed to pick the hop up.
	if err != nil && r.cfg.Fallback != nil {
		if retry, fallbackErr := r.exchange(ctx, step, r.cfg.Fallback, qname, qtype, udpSize, port); fallbackErr == nil {
			step.Notes = append(step.Notes, step.Proto+" did not get through, asked over "+r.cfg.Fallback.Proto())
			step.Proto = r.cfg.Fallback.Proto()
			step.Server.Port = cmp.Or(port, r.cfg.Fallback.Port())
			resp, err = retry, nil
		}
	}
	if err != nil {
		step.Kind, step.Err = trace.KindError, err.Error()
		if transport.IsTimeout(err) {
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
func (r *run) exchange(ctx context.Context, step *trace.Step, carrier transport.Transport, qname string, qtype uint16, udpSize, port uint16) (*dns.Msg, error) {
	server := netip.AddrPortFrom(step.Server.IP, cmp.Or(port, carrier.Port()))

	var err error
	for attempt := 0; ; attempt++ {
		var req *dns.Msg
		if req, err = transport.NewQuery(qname, qtype, udpSize, r.cfg.DNSSEC); err != nil {
			return nil, err
		}
		transport.WithSubnet(req, r.cfg.Subnet)
		if r.cfg.NSID {
			transport.WithNSID(req)
		}

		var (
			resp *dns.Msg
			rtt  time.Duration
		)
		resp, rtt, err = carrier.Exchange(ctx, req, server, step.Server.Name)
		step.RTT += rtt

		r.cfg.Log.Debug("asked a nameserver",
			"zone", step.Zone, "server", server, "proto", carrier.Proto(),
			"name", qname, "type", qtype, "rtt", rtt, "error", err)

		if err == nil || attempt >= r.cfg.Retries || !transport.IsTimeout(err) {
			return resp, err
		}
		step.Notes = append(step.Notes, "asked again after a silence")
	}
}

// nextServers is where the walk goes after a referral: the glue when there is
// any, and otherwise the addresses of the nameservers named outside the zone,
// resolved on their own.
func (r *run) nextServers(ctx context.Context, step *trace.Step, side int) []trace.Server {
	delegation := step.Delegation

	if len(delegation.GlueLess) > 0 {
		r.warnf("%s delegates to %s inside the zone, with no glue to reach them",
			delegation.Zone, strings.Join(delegation.GlueLess, ", "))
	}
	if servers := glueServers(delegation); len(servers) > 0 {
		return servers
	}
	if len(delegation.OutOfBailiwick) == 0 {
		return nil
	}
	if side >= maxSideResolution {
		r.warnf("the nameservers of %s are named too far away to keep chasing", delegation.Zone)
		return nil
	}

	rrtype, typeName := uint16(dns.TypeA), "A"
	if r.cfg.Family == 6 {
		rrtype, typeName = dns.TypeAAAA, "AAAA"
	}

	var servers []trace.Server
	for _, name := range delegation.OutOfBailiwick {
		root := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true,
			Notes: []string{"resolving " + name}}
		r.attach(step, root)

		result := r.walk(ctx, name, rrtype, root, side+1)
		if result == nil {
			continue
		}
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
		if len(servers) > 0 {
			return servers // one nameserver we can reach is enough to go on
		}
	}
	return servers
}

// chaseCNAME starts again from the root for the name the alias points at, as a
// branch under the answer that gave it.
func (r *run) chaseCNAME(ctx context.Context, step *trace.Step, qname string, qtype uint16, side int) *trace.Step {
	target := cnameTarget(step.Records, qname)
	if target == "" {
		r.warnf("%s is an alias for a name the answer did not carry", qname)
		return step
	}
	if r.chased[target] {
		r.warnf("the alias chain for %s comes back to %s", qname, target)
		return step
	}
	if err := r.counters.cname(); err != nil {
		return r.fail(step, step.Zone, err.Error())
	}
	r.chased[target] = true

	root := &trace.Step{Zone: ".", Kind: trace.KindZone, Notes: []string{"resolving " + target}}
	r.attach(step, root)
	return r.walk(ctx, target, qtype, root, side)
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
			child = append(child, record.Data)
		}
	}
	step.Records = nil // the comparison is the point, not the records

	if len(child) == 0 {
		r.warnf("%s did not return its own NS records", delegated.Zone)
		return
	}
	if missing := missing(delegated.NS, child); len(missing) > 0 {
		r.warnf("%s delegates to %s, which the zone itself does not list",
			delegated.Zone, strings.Join(missing, ", "))
	}
	if extra := missing(child, delegated.NS); len(extra) > 0 {
		r.warnf("%s lists %s, which the delegation does not carry",
			delegated.Zone, strings.Join(extra, ", "))
	}
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
		serving[serial] = append(serving[serial], at(hop.step))
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
