package resolver

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// walk follows referrals down from the root, one zone at a time, until
// something answers or the way down runs out. Every step it makes hangs under
// parent. side is how deep this walk is nested inside the resolution of a
// nameserver's name.
func (r *run) walk(ctx context.Context, qname string, qtype uint16, parent *trace.Step, side int) *trace.Step {
	return r.walkFrom(ctx, nil, qname, qtype, parent, side)
}

// walkFrom is walk starting from a zone the run has already entered, with the
// servers and the chain of trust it had there, or from the root for nil.
func (r *run) walkFrom(ctx context.Context, from *cut, qname string, qtype uint16, parent *trace.Step, side int) *trace.Step {
	zone, servers := ".", r.cfg.Roots

	// Every walk starts again from the anchors: a walk for an alias or for a
	// nameserver's name is its own resolution, and must not borrow the keys of
	// the one that needed it. One started from a zone the run entered keeps
	// the chain it had there on purpose: those keys are that zone's own.
	var chain *dnssec.Chain
	if r.cfg.DNSSEC {
		chain = dnssec.New(r.cfg.Anchors)
		if !r.cfg.At.IsZero() {
			chain.At(r.cfg.At)
		}
	}
	var delegation []dns.RR // the authority section that led into this zone

	// reach is how many labels of the name the next question in this zone asks
	// for, which is all of them unless the walk is minimising. entered is
	// whether the chain has checked this zone yet: minimising asks one zone
	// several questions, and its keys are fetched once.
	reach, entered := r.reach(zone, qname), false
	if from != nil {
		zone, servers, chain = from.zone, from.servers, from.chain.Clone()
		reach, entered = r.reach(zone, qname), true
	}

	// top is a walk whose zones the CAA lookups and the asides go to: the one
	// for the question, and those the asides make. recorded is whether this
	// zone has been kept for them.
	top := side == 0 && (r.aside ||
		(r.cfg.CAA || r.cfg.Mail || r.cfg.SVCB || r.cfg.Deps) && !r.climbing && dns.EqualName(qname, r.trace.Question.Name))
	recorded := from != nil

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
				r.warnIn(trace.AreaServers, zone, "no server answered for %s", zone)
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
			r.warnIn(trace.AreaServers, denied.Zone, "%s answered NXDOMAIN for %s, which has names below it, so a resolver that minimises its questions stops there (RFC 8020); it should answer NODATA",
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
			r.denial(ctx, chain, hop, zone, qname)
			if side == 0 && !r.climbing && !r.aside {
				r.checkECH(step)
				r.checkSubnet(step)
				r.checkNS(ctx, chain, step, referred)
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
				r.warnIn(trace.AreaDelegation, step.Delegation.Zone, "the delegation to %s came with no usable address", step.Delegation.Zone)
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
// before the zone the question is about was asked at all. Nor does it reach
// the asides, which the client they stand for asks of one.
func (r *run) every(side int) bool {
	return r.cfg.All && side == 0 && !r.aside
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
	// The DO bit rides in EDNS0, so an answer without it never had room for a
	// signature: say so, rather than blame the zone's signing.
	if hop.step.DNSSEC.State == trace.Bogus && hop.resp.UDPSize == 0 && !signedAny(hop.resp) {
		hop.step.DNSSEC.Reason = "the server answered without EDNS0, so it could not carry the signatures"
	}
	return crossed
}

// signedAny reports whether a response carries a signature anywhere.
func signedAny(resp *dns.Msg) bool {
	return slices.ContainsFunc(slices.Concat(resp.Answer, resp.Ns), func(rr dns.RR) bool {
		return dns.RRToType(rr) == dns.TypeRRSIG
	})
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
			skipped.Notes = []string{fmt.Sprintf("left out by -%d", r.cfg.Family)}
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
	servers, budget := afford(r.counters, servers)
	hops := askAll(servers, func(server trace.Server) *hop { return r.query(ctx, zone, server, qname, qtype) })

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
	r.warnIn(trace.AreaConsistency, zone, "the nameservers of %s do not answer %s %s alike: %s",
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

// nextServers is where the walk goes after a referral: the glue when there is
// any, and otherwise the addresses of the nameservers named outside the zone,
// resolved on their own. It hands back the names it has not looked up yet, for
// the walk to try if every server it has so far fails. All looks them all up
// at once, since it asks every nameserver there is.
func (r *run) nextServers(ctx context.Context, step *trace.Step, side int) ([]trace.Server, []string) {
	delegation := step.Delegation

	for _, name := range delegation.NS {
		if addressShaped(name) {
			r.warnOnceIn(trace.AreaDelegation, delegation.Zone, "%s delegates to %s, which is an address written as a name, and nothing resolves it; name the nameserver instead (RFC 1035 section 3.3.11)",
				delegation.Zone, name)
		}
	}
	if len(delegation.GlueLess) > 0 {
		r.warnIn(trace.AreaDelegation, delegation.Zone, "%s delegates to %s inside the zone, with no glue to reach them",
			delegation.Zone, strings.Join(delegation.GlueLess, ", "))
	}
	servers, pending := glueServers(delegation), delegation.OutOfBailiwick
	if len(pending) == 0 {
		return servers, nil
	}
	if side >= maxSideResolution {
		if len(servers) == 0 {
			r.warnIn(trace.AreaDelegation, delegation.Zone, "the nameservers of %s are named too far away to keep chasing", delegation.Zone)
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
		r.claim(ctx, result, r.orphan(result), trace.DanglingNameserver, step.Delegation.Zone, step.Delegation.Zone)
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
		r.warnf(trace.AreaAnswer, "%s is an alias for a name the answer did not carry", qname)
		return step
	}
	// Names are compared the way DNS compares them: B.x and b.x are one name,
	// and a loop spelled in both would otherwise run until the budget ended it.
	if r.chased[dnsutil.Canonical(target)] {
		r.warnf(trace.AreaAnswer, "the alias chain for %s comes back to %s", qname, target)
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
		r.claim(ctx, result, r.orphan(result), trace.DanglingAlias, qname, step.Zone)
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
	for _, record := range step.Records {
		if record.Service != nil && record.Service.ECH {
			r.warnECH(record.Name, step.DNSSEC)
			return
		}
	}
}

// warnECH says that name publishes an ECH configuration status does not vouch
// for.
func (r *run) warnECH(name string, status *trace.DNSSECStatus) {
	switch {
	case !r.cfg.DNSSEC:
		r.warnf(trace.AreaDNSSEC, "%s publishes an ECH configuration, and without --dnssec nothing here checked that it arrived as the zone wrote it", name)
	case status == nil:
		r.warnf(trace.AreaDNSSEC, "%s publishes an ECH configuration in an answer whose signatures were never checked", name)
	case status.State != trace.Secure:
		r.warnf(trace.AreaDNSSEC, "%s publishes an ECH configuration in an answer that is %s, so a client cannot tell whether it was stripped on the way",
			name, status.State)
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
	r.warnf("", "%s ignored the client subnet, so this answer is not tailored to %s", who, r.cfg.Subnet)
}
