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

// CSYNC flags (RFC 7477 2.1.1.2).
const (
	csyncImmediate  = 1 << 0
	csyncSOAMinimum = 1 << 1
)

// checkCSYNC asks the zone whether it wants its parent to copy its NS set or
// its glue (RFC 7477), and works out what a parent acting on it would change
// in the delegation the walk was handed. child is the zone's own NS set, empty
// where it could not be had.
//
// A parent copies only what the zone's keys signed (RFC 7477 3), so without a
// chain that reached the zone secure the record is a claim, and is said to be.
func (r *run) checkCSYNC(ctx context.Context, chain *dnssec.Chain, check *trace.Step, server trace.Server, delegated *trace.Delegation, child []string) {
	zone := delegated.Zone
	csync := &trace.CSYNC{}
	delegated.CSYNC = csync

	hop := r.fetchApex(ctx, check, server, zone, dns.TypeCSYNC)
	switch {
	case hop == nil:
		csync.State, csync.Reason = trace.CSYNCUnchecked, "the budget ran out before it could be fetched"
		return
	case hop.resp == nil || hop.step.Kind != trace.KindAnswer && hop.step.Kind != trace.KindNoData:
		csync.State, csync.Reason = trace.CSYNCUnchecked, "it could not be fetched"
		return
	}
	var record *dns.CSYNC
	for _, rr := range hop.resp.Answer {
		if found, ok := rr.(*dns.CSYNC); ok && dns.EqualName(found.Hdr.Name, zone) {
			record = found
			break
		}
	}
	if record == nil {
		csync.State = trace.CSYNCNone
		return
	}
	csync.Serial = record.Serial
	csync.Immediate = record.Flags&csyncImmediate != 0
	csync.SOAMinimum = record.Flags&csyncSOAMinimum != 0
	for _, rrtype := range record.TypeBitMap {
		csync.Types = append(csync.Types, dnsutil.TypeToString(rrtype))
	}

	switch {
	case !r.cfg.DNSSEC:
		csync.State, csync.Reason = trace.CSYNCUnchecked, "only --dnssec checks the signature a parent needs"
	case chain == nil || chain.State() != trace.Secure || !dns.EqualName(chain.Zone(), zone):
		csync.State, csync.Reason = trace.CSYNCUnproven, "the chain of trust did not reach "+zone+" secure"
	default:
		status := chain.Verify(hop.resp.Answer, hop.resp.Ns, hop.resp.Rcode, zone, dns.TypeCSYNC)
		if status.State != trace.Secure {
			csync.State, csync.Reason = trace.CSYNCUnproven, "it is "+string(status.State)+": "+status.Reason
		}
	}
	if csync.State == "" {
		r.judgeCSYNC(ctx, check, server, csync, zone)
	}

	hollow := r.csyncChanges(ctx, check, server, csync, delegated, child)
	r.warnCSYNC(csync, zone, hollow)
}

// judgeCSYNC decides when a parent would act on a CSYNC whose signature held.
func (r *run) judgeCSYNC(ctx context.Context, check *trace.Step, server trace.Server, csync *trace.CSYNC, zone string) {
	if !csync.Immediate {
		csync.State, csync.Reason = trace.CSYNCManual, "it waits for whoever runs the parent to approve it"
		return
	}
	csync.State = trace.CSYNCReady
	if !csync.SOAMinimum {
		return
	}
	hop := r.fetchApex(ctx, check, server, zone, dns.TypeSOA)
	var soa *dns.SOA
	if hop != nil && hop.resp != nil {
		for _, rr := range hop.resp.Answer {
			if found, ok := rr.(*dns.SOA); ok && dns.EqualName(found.Hdr.Name, zone) {
				soa = found
			}
		}
	}
	if soa == nil {
		csync.State, csync.Reason = trace.CSYNCUnchecked, "the SOA its serial is held against could not be fetched"
		return
	}
	csync.ZoneSerial = soa.Serial
	if serialBefore(soa.Serial, csync.Serial) {
		csync.State = trace.CSYNCWaiting
		csync.Reason = fmt.Sprintf("the zone serves serial %d, short of the %d it waits for", soa.Serial, csync.Serial)
	}
}

// serialBefore reports whether serial a comes before b, in the arithmetic of
// RFC 1982 that lets a serial wrap.
func serialBefore(a, b uint32) bool {
	return a != b && int32(b-a) > 0
}

// csyncChanges is what a parent copying what the CSYNC names would change: the
// NS set for the zone's own, and the glue of the nameservers named inside the
// zone for the addresses the zone gives them. It returns the nameservers the
// CSYNC asks glue for that the zone gives no address of the types it names.
func (r *run) csyncChanges(ctx context.Context, check *trace.Step, server trace.Server, csync *trace.CSYNC, delegated *trace.Delegation, child []string) []string {
	zone := delegated.Zone
	targets := delegated.NS
	if slices.Contains(csync.Types, "NS") && len(child) > 0 {
		for _, name := range missing(child, delegated.NS) {
			csync.Changes = append(csync.Changes, trace.DelegationChange{Add: true, Type: "NS", Name: name})
		}
		for _, name := range missing(delegated.NS, child) {
			csync.Changes = append(csync.Changes, trace.DelegationChange{Type: "NS", Name: name})
		}
		targets = child
	}

	var families []uint16
	for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if slices.Contains(csync.Types, dnsutil.TypeToString(rrtype)) {
			families = append(families, rrtype)
		}
	}
	if len(families) == 0 {
		return nil
	}

	// --check-ns asked for the addresses of the nameservers that came with
	// glue; one the zone adds has none yet, and is asked here.
	type question struct {
		name   string
		rrtype uint16
	}
	var inside []string
	var questions []question
	for _, name := range targets {
		if !dnsutil.IsBelow(zone, name) || slices.ContainsFunc(inside, func(seen string) bool { return dns.EqualName(seen, name) }) {
			continue
		}
		inside = append(inside, name)
		if _, asked := delegated.ZoneAddrs[name]; asked {
			continue
		}
		for _, rrtype := range families {
			questions = append(questions, question{name, rrtype})
		}
	}
	questions, budget := afford(r.counters, questions)
	hops := askAll(questions, func(q question) *hop { return r.query(ctx, zone, server, q.name, q.rrtype) })
	for i, hop := range hops {
		q, step := questions[i], hop.step
		step.Aside = true
		step.Notes = append(step.Notes, "csync check: "+dnsutil.TypeToString(q.rrtype)+" of "+q.name)
		held := addresses(step.Records, q.name, q.rrtype)
		step.Records = nil // the comparison is the point, and it is on the CSYNC
		r.attach(check, step)
		if step.Kind != trace.KindAnswer && step.Kind != trace.KindNoData && step.Kind != trace.KindNXDomain {
			continue // a server that did not say is not a zone that gives nothing
		}
		if delegated.ZoneAddrs == nil {
			delegated.ZoneAddrs = make(map[string][]netip.Addr)
		}
		delegated.ZoneAddrs[q.name] = append(delegated.ZoneAddrs[q.name], held...)
	}
	if budget != nil {
		r.warnf(trace.AreaDelegation, "the budget ran out before the addresses the CSYNC of %s asks for could be checked", zone)
	}

	var hollow []string
	for _, name := range inside {
		held, asked := delegated.ZoneAddrs[name]
		if !asked {
			continue // not answered, which says nothing of the zone
		}
		gives := false
		for _, rrtype := range families {
			glue, own := ofFamily(delegated.Glue[name], rrtype), ofFamily(held, rrtype)
			gives = gives || len(own) > 0
			for _, addr := range addrsMissing(own, glue) {
				csync.Changes = append(csync.Changes, trace.DelegationChange{Add: true, Type: dnsutil.TypeToString(rrtype), Name: name, Data: addr.String()})
			}
			for _, addr := range addrsMissing(glue, own) {
				csync.Changes = append(csync.Changes, trace.DelegationChange{Type: dnsutil.TypeToString(rrtype), Name: name, Data: addr.String()})
			}
		}
		if !gives {
			hollow = append(hollow, name)
		}
	}
	return hollow
}

// addrsMissing are the addresses of a that b does not hold, sorted.
func addrsMissing(a, b []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, addr := range a {
		if !slices.Contains(b, addr) && !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// warnCSYNC says what keeps a parent from acting on a CSYNC, or from finding
// anything to copy.
func (r *run) warnCSYNC(csync *trace.CSYNC, zone string, hollow []string) {
	switch csync.State {
	case trace.CSYNCUnproven:
		r.warnf(trace.AreaDelegation, "the CSYNC of %s is not one a parent acts on (%s); a parent copies only what the zone's keys signed (RFC 7477 section 3)",
			zone, csync.Reason)
	case trace.CSYNCWaiting:
		r.warnf(trace.AreaDelegation, "the CSYNC of %s waits for serial %d and the zone serves %d, so a parent copies nothing until the serial reaches it; publish a CSYNC with a serial the zone has reached",
			zone, csync.Serial, csync.ZoneSerial)
	}
	if len(hollow) > 0 {
		r.warnf(trace.AreaDelegation, "the CSYNC of %s asks its parent to copy the addresses of %s, which the zone does not give; add them, or take A and AAAA off the CSYNC",
			zone, strings.Join(hollow, ", "))
	}
	var other []string
	for _, name := range csync.Types {
		if name != "NS" && name != "A" && name != "AAAA" {
			other = append(other, name)
		}
	}
	if len(other) > 0 {
		r.warnf(trace.AreaDelegation, "the CSYNC of %s names %s, which a parent does not copy: RFC 7477 defines only NS, A and AAAA",
			zone, strings.Join(other, ", "))
	}
}

// fetchApex asks server for one of the zone's records at its apex, and hangs
// the hop under under as an aside. It is nil where the budget ran out first.
func (r *run) fetchApex(ctx context.Context, under *trace.Step, server trace.Server, zone string, qtype uint16) *hop {
	if err := r.counters.query(); err != nil {
		return nil
	}
	hop := r.query(ctx, zone, server, zone, qtype)
	hop.step.Aside = true
	hop.step.Records = nil // the comparison is the point, and it is on the verdict
	hop.step.Notes = append(hop.step.Notes, dnsutil.TypeToString(qtype)+" of "+zone)
	r.attach(under, hop.step)
	return hop
}

// bootstrapping is a zone's request for its first DS, kept from the walk for
// the lookups of its signals that follow it.
type bootstrapping struct {
	zone   string
	ns     []string
	under  *trace.Step
	signal *trace.Signal

	// asked is what the zone itself publishes, by type, each record reduced to
	// a form two copies of it can be compared in.
	asked map[uint16][]string
}

// requestFirst reads what a zone the parent holds no DS for asks of it. The
// zone has no keys anyone vouches for, so its CDS and CDNSKEY are taken as
// served, and it is the signals under its nameservers, looked up once the walk
// is over, that decide whether a parent would believe them (RFC 9615 4.2).
func (r *run) requestFirst(ctx context.Context, answer *trace.Step, last zoneCut) {
	zone, verdict := last.zone, last.step.DNSSEC
	fetched := map[uint16][]dns.RR{}
	for _, qtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY} {
		name := dnsutil.TypeToString(qtype)
		hop := r.fetchApex(ctx, answer, answer.Server, zone, qtype)
		reason := ""
		switch {
		case hop == nil:
			reason = "the budget ran out before the " + name + " could be fetched"
		case hop.resp == nil || hop.step.Kind != trace.KindAnswer && hop.step.Kind != trace.KindNoData:
			reason = "the " + name + " could not be fetched"
		}
		if reason != "" {
			verdict.Signal = &trace.Signal{State: trace.SignalUnchecked, Reason: reason}
			r.warnf(trace.AreaDNSSEC, "the request %s makes of its parent could not be checked: %s", zone, reason)
			return
		}
		fetched[qtype] = hop.resp.Answer
	}

	signal := dnssec.Signal(last.authority, zone, fetched[dns.TypeCDS], fetched[dns.TypeCDNSKEY])
	verdict.Signal = signal
	switch signal.State {
	case trace.SignalInconsistent:
		r.warnf(trace.AreaDNSSEC, "the CDS and CDNSKEY of %s do not describe the same keys (%s), so a parent acts on neither; publish both from one key set",
			zone, signal.Reason)
		return
	case trace.SignalPending:
	default:
		return // nothing asked for, or no DS where there is none already
	}

	b := &bootstrapping{zone: zone, under: answer, signal: signal, asked: map[uint16][]string{}}
	for qtype, records := range fetched {
		for _, rr := range records {
			if dns.EqualName(rr.Header().Name, zone) {
				if key := requestKey(rr); key != "" {
					b.asked[qtype] = append(b.asked[qtype], key)
				}
			}
		}
	}
	signal.Bootstrap = &trace.Bootstrap{State: trace.BootstrapUnchecked, Reason: "its signals were not looked up"}
	if last.step.Delegation == nil {
		signal.Bootstrap.Reason = "the walk was handed no delegation to name its nameservers"
		return
	}
	b.ns = last.step.Delegation.NS
	r.boot = b
}

// bootstrap looks up the signal under every nameserver of a zone asking for
// its first DS, and decides as a parent that bootstraps would: every signal
// under a nameserver named outside the zone has to validate and say what the
// zone does, type by type, an empty set beside a full one included.
func (r *run) bootstrap(ctx context.Context) {
	b := r.boot
	if b == nil {
		return
	}
	r.aside, r.asideStopped = true, false
	defer func() { r.aside = false }()

	result := b.signal.Bootstrap
	result.State, result.Reason = "", ""
	outside := 0
	for _, ns := range b.ns {
		signal := trace.BootstrapSignal{NS: ns}
		name := "_dsboot." + b.zone + "_signal." + ns
		switch {
		case dnsutil.IsBelow(b.zone, ns):
			signal.State, signal.Reason = trace.SignalingUnasked, "it is named inside the zone, which is not secure yet"
		case !dnsutil.IsName(name):
			outside++
			signal.State, signal.Reason = trace.SignalingUnasked, "the name to look it up at would be longer than 255 octets"
		default:
			outside++
			signal.Name = name
			r.signalUnder(ctx, b, &signal)
		}
		result.Signals = append(result.Signals, signal)
	}

	if outside == 0 {
		result.State, result.Reason = trace.BootstrapRefused, "every nameserver is named inside the zone, so no operator can vouch for it"
		r.warnf(trace.AreaDNSSEC, "%s asks for its first DS, but every nameserver of it is named inside it, so nothing can vouch for the request (RFC 9615 section 4.2); it needs a nameserver named elsewhere, or a DS added by hand",
			b.zone)
		return
	}

	by := map[trace.SignalingState][]string{}
	for _, signal := range result.Signals {
		if signal.State == trace.SignalingUnasked && signal.Name == "" && dnsutil.IsBelow(b.zone, signal.NS) {
			continue // not one a parent asks
		}
		by[signal.State] = append(by[signal.State], signal.NS)
	}
	refusing := []struct {
		state  trace.SignalingState
		reason string
		advice string
	}{
		{trace.SignalingMissing, "no signal under %s", "%s asks for its first DS, but nothing is published under %s, so a parent that bootstraps adds none (RFC 9615); have the operator of every nameserver publish the zone's CDS and CDNSKEY there"},
		{trace.SignalingDiffers, "the signal under %s asks for something else", "the bootstrap signal for %s under %s does not say what the zone does, so a parent that bootstraps adds no DS; publish the zone's own CDS and CDNSKEY there"},
		{trace.SignalingUnproven, "the signal under %s does not validate", "the bootstrap signal for %s under %s does not validate, so it proves nothing; the operator's zone has to be signed and secure (RFC 9615 section 3.1)"},
		{trace.SignalingUnasked, "the signal under %s cannot be asked for", "%s cannot bootstrap through %s: the name to look its signal up at would be longer than 255 octets"},
	}
	for _, refuse := range refusing {
		names := by[refuse.state]
		if len(names) == 0 {
			continue
		}
		if result.State == "" {
			result.State, result.Reason = trace.BootstrapRefused, fmt.Sprintf(refuse.reason, strings.Join(names, ", "))
		}
		r.warnf(trace.AreaDNSSEC, refuse.advice, b.zone, strings.Join(names, ", "))
	}
	if result.State != "" {
		return
	}
	if failed := by[trace.SignalingFailed]; len(failed) > 0 {
		result.State, result.Reason = trace.BootstrapUnchecked, "the signal under "+strings.Join(failed, ", ")+" could not be looked up"
		r.warnf(trace.AreaDNSSEC, "the bootstrap signals of %s could not all be checked: %s", b.zone, result.Reason)
		return
	}
	result.State = trace.BootstrapReady
}

// signalUnder looks up the CDS and CDNSKEY under one nameserver and holds them
// against the zone's own.
func (r *run) signalUnder(ctx context.Context, b *bootstrapping, signal *trace.BootstrapSignal) {
	found := map[uint16][]string{}
	var tags []uint16
	for _, qtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY} {
		result, lookup, stopped := r.look(ctx, b.under, signal.Name, qtype, "bootstrap")
		if signal.Lookup == nil || lookup.Err != "" || lookup.DNSSEC != nil && lookup.DNSSEC.State != trace.Secure {
			signal.Lookup = &lookup
		}
		switch {
		case stopped:
			signal.State, signal.Reason = trace.SignalingFailed, "the budget ran out before it was looked up"
			return
		case lookup.Err != "":
			signal.State, signal.Reason = trace.SignalingFailed, "the "+dnsutil.TypeToString(qtype)+" lookup failed: "+lookup.Err
			return
		case lookup.DNSSEC == nil || lookup.DNSSEC.State != trace.Secure:
			signal.State, signal.Reason = trace.SignalingUnproven, "its "+dnsutil.TypeToString(qtype)+" is not secure"
			if lookup.DNSSEC != nil {
				signal.Reason = "its " + dnsutil.TypeToString(qtype) + " is " + string(lookup.DNSSEC.State) + ": " + lookup.DNSSEC.Reason
			}
			return
		}
		for _, record := range result.Records {
			if record.Type != dnsutil.TypeToString(qtype) || !dns.EqualName(record.Name, result.Asked.Name) {
				continue
			}
			rr, err := dns.New(". IN " + record.Type + " " + record.Data)
			if err != nil {
				continue
			}
			if key := requestKey(rr); key != "" {
				found[qtype] = append(found[qtype], key)
				tags = append(tags, keyTag(rr))
			}
		}
	}
	slices.Sort(tags)
	signal.Requested = slices.Compact(tags)

	if len(found[dns.TypeCDS]) == 0 && len(found[dns.TypeCDNSKEY]) == 0 {
		signal.State, signal.Reason = trace.SignalingMissing, "the operator's zone proves there is none"
		return
	}
	for _, qtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY} {
		if !sameSet(found[qtype], b.asked[qtype]) {
			signal.State = trace.SignalingDiffers
			signal.Reason = "its " + dnsutil.TypeToString(qtype) + " is not the zone's"
			return
		}
	}
	signal.State = trace.SignalingMatched
}

// requestKey is a CDS or CDNSKEY in a form two copies of it compare equal in:
// a digest is hex, which may be written in either case.
func requestKey(rr dns.RR) string {
	switch record := rr.(type) {
	case *dns.CDS:
		return fmt.Sprintf("%d %d %d %s", record.KeyTag, record.Algorithm, record.DigestType, strings.ToUpper(record.Digest))
	case *dns.CDNSKEY:
		return fmt.Sprintf("%d %d %d %s", record.Flags, record.Protocol, record.Algorithm, record.PublicKey)
	}
	return ""
}

func keyTag(rr dns.RR) uint16 {
	switch record := rr.(type) {
	case *dns.CDS:
		return record.KeyTag
	case *dns.CDNSKEY:
		return record.KeyTag()
	}
	return 0
}

// sameSet reports whether a and b hold the same strings, however many times
// and in whatever order.
func sameSet(a, b []string) bool {
	return !slices.ContainsFunc(a, func(s string) bool { return !slices.Contains(b, s) }) &&
		!slices.ContainsFunc(b, func(s string) bool { return !slices.Contains(a, s) })
}
