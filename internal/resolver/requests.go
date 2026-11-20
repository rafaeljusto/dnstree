package resolver

import (
	"cmp"
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

// A parent that acts on a zone's CDS, CDNSKEY or CSYNC asks every address of
// every nameserver for it, and acts on nothing unless the answers it got agree
// (RFC 9975). A walk reads the request from one server, so a provider that
// alone publishes a new key, or a secondary still serving the old one, is a
// request the parent will never act on and the walk would call ready.
//
// The questions go out together and join the trace afterwards, from the
// goroutine doing the walking, and each answer counts only where the zone's
// keys signed it.

// apexQuestion is one record type asked of one server.
type apexQuestion struct {
	server trace.Server
	rrtype uint16
}

// sweepable are the servers a sweep asks: each address once, of the family the
// walk uses, and none the run was told is down.
func (r *run) sweepable(servers []trace.Server) []trace.Server {
	var usable []trace.Server
	for _, server := range dedupe(servers) {
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		if r.cfg.Down != nil && r.cfg.Down(server) != "" {
			continue
		}
		usable = append(usable, server)
	}
	return usable
}

// sweep asks each server each type, in that order, and hangs every hop under
// answer as an aside. It hands back the hops it could pay for, with why it
// stopped where it could not pay for them all.
func (r *run) sweep(ctx context.Context, answer *trace.Step, zone string, servers []trace.Server, rrtypes ...uint16) ([]*hop, []apexQuestion, error) {
	var questions []apexQuestion
	for _, server := range servers {
		for _, rrtype := range rrtypes {
			questions = append(questions, apexQuestion{server, rrtype})
		}
	}
	questions, budget := afford(r.counters, questions)
	hops := askAll(questions, func(q apexQuestion) *hop { return r.query(ctx, zone, q.server, zone, q.rrtype) })
	for _, hop := range hops {
		hop.step.Aside = true
		hop.step.Records = nil // the comparison is the point, and it is on the request
		r.attach(answer, hop.step)
	}
	return hops, questions, budget
}

// signedAnswer is what one hop of a sweep came to: the records the zone's keys
// signed, or the state and reason it did not get that far.
func signedAnswer(chain *dnssec.Chain, hop *hop, zone string, rrtype uint16) ([]dns.RR, trace.ServerRequestState, string) {
	name := dnsutil.TypeToString(rrtype)
	if hop.resp == nil || hop.step.Kind != trace.KindAnswer && hop.step.Kind != trace.KindNoData {
		return nil, trace.ServerRequestUnanswered, "the " + name + " could not be fetched"
	}
	switch status := chain.Verify(hop.resp.Answer, hop.resp.Ns, hop.resp.Rcode, zone, rrtype); status.State {
	case trace.Secure:
	case trace.Indeterminate:
		// What this build cannot check is no reading, and never a difference.
		return nil, trace.ServerRequestUnanswered, "the " + name + " could not be checked: " + status.Reason
	default:
		return nil, trace.ServerRequestBogus, "the " + name + " is " + string(status.State) + ": " + status.Reason
	}
	return hop.resp.Answer, trace.ServerRequestRead, ""
}

// reading is one server's request while a sweep is judged: what it asks for,
// and the form its request is held against the others' in.
type reading struct {
	trace.ServerRequest
	same string
}

// agreeDS asks every server of the zone for its CDS and CDNSKEY. It is nil
// where there is only one address to ask.
func (r *run) agreeDS(ctx context.Context, chain *dnssec.Chain, answer *trace.Step, zone string, servers []trace.Server) *trace.Agreement {
	servers = r.sweepable(servers)
	if len(servers) < 2 {
		return nil
	}
	hops, questions, budget := r.sweep(ctx, answer, zone, servers, dns.TypeCDS, dns.TypeCDNSKEY)

	var readings []reading
	for i := 0; i+1 < len(hops); i += 2 {
		each := reading{ServerRequest: trace.ServerRequest{Server: questions[i].server, State: trace.ServerRequestRead}}
		var fetched [2][]dns.RR
		for j, rrtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY} {
			records, state, reason := signedAnswer(chain, hops[i+j], zone, rrtype)
			fetched[j] = records
			if state != trace.ServerRequestRead && each.State != trace.ServerRequestBogus {
				each.State, each.Reason = state, reason
			}
		}
		if each.State == trace.ServerRequestRead {
			request := dnssec.Requested(zone, fetched[0], fetched[1])
			switch {
			case request.Delete:
				each.Asks, each.same = "no DS at all", "delete"
			case request.Inconsistent != "":
				each.Asks, each.same = "keys its CDS and CDNSKEY disagree on ("+request.Inconsistent+")", "inconsistent"
			case len(request.Keys) == 0:
				each.Asks, each.same = "nothing", ""
			default:
				each.Asks, each.same = "keys "+joinTags(request.Tags), strings.Join(request.Keys, ",")
			}
		}
		hops[i].step.Notes = append(hops[i].step.Notes, "request check: CDS of "+zone)
		hops[i+1].step.Notes = append(hops[i+1].step.Notes, "request check: "+each.note())
		readings = append(readings, each)
	}
	// A server that cannot keep its own CDS and CDNSKEY in step is a request
	// no parent acts on, whatever the others say.
	split := func(each reading) bool { return each.same == "inconsistent" }
	agreement := agreed(readings, budget, split)

	switch agreement.State {
	case trace.AgreementDiffer:
		r.warnf(trace.AreaDNSSEC, "the nameservers of %s do not make the same request of the parent: %s; a parent acts on none of it (RFC 9975), so the DS stays as it is; publish the same CDS and CDNSKEY from every nameserver",
			zone, requestsSaid(readings, hops))
	case trace.AgreementPartial:
		r.warnPartial(trace.AreaDNSSEC, zone, "CDS and CDNSKEY", readings, hops, budget)
	}
	return agreement
}

// note is what one server's request says on its aside.
func (s reading) note() string {
	if s.State != trace.ServerRequestRead {
		return s.Reason
	}
	return "asks for " + s.Asks
}

// agreed weighs the readings of a sweep against each other. Only an answer
// counts: a server that did not answer is not a difference (RFC 9975 3), but
// one whose signature did not hold is, since a parent that checks it refuses
// the whole request.
func agreed(readings []reading, budget error, split func(reading) bool) *trace.Agreement {
	agreement := &trace.Agreement{State: trace.AgreementSame}
	var first *reading
	unanswered := false
	for i := range readings {
		each := &readings[i]
		agreement.Servers = append(agreement.Servers, each.ServerRequest)
		switch {
		case each.State == trace.ServerRequestUnanswered:
			unanswered = true
		case each.State == trace.ServerRequestBogus || split(*each):
			agreement.State = trace.AgreementDiffer
		case first == nil:
			first = each
		case first.same != each.same:
			agreement.State = trace.AgreementDiffer
		}
	}
	if budget != nil {
		agreement.Reason = "the budget ran out before every nameserver could be asked"
	}
	if agreement.State == trace.AgreementSame && (unanswered || budget != nil) {
		agreement.State = trace.AgreementPartial
	}
	return agreement
}

// requestsSaid is what each server of a sweep asks for, grouped by what it asks, in
// the order the servers were asked.
func requestsSaid(readings []reading, hops []*hop) string {
	name := naming(hops)
	label := func(server trace.Server) string {
		return name(&trace.Step{Server: server})
	}
	var order []string
	saying := make(map[string][]string)
	for _, each := range readings {
		var what string
		switch each.State {
		case trace.ServerRequestUnanswered:
			continue
		case trace.ServerRequestBogus:
			what = "serve% it with a signature that does not hold"
		default:
			what = "ask% for " + each.Asks
		}
		if _, seen := saying[what]; !seen {
			order = append(order, what)
		}
		saying[what] = append(saying[what], label(each.Server))
	}
	parts := make([]string, 0, len(order))
	for _, what := range order {
		servers := saying[what]
		parts = append(parts, strings.Join(servers, " and ")+" "+strings.Replace(what, "%", verb(servers, "s", ""), 1))
	}
	return strings.Join(parts, ", ")
}

// warnPartial says which servers a sweep got nothing from, where those that
// answered agree: a parent asks them again later, and until they answer the
// request waits.
func (r *run) warnPartial(area trace.Area, zone, what string, readings []reading, hops []*hop, budget error) {
	if budget != nil {
		r.warnf(area, "the budget ran out before every nameserver of %s could be asked for its %s, so whether they agree is not known", zone, what)
		return
	}
	name := naming(hops)
	var silent []string
	for _, each := range readings {
		if each.State == trace.ServerRequestUnanswered {
			silent = append(silent, name(&trace.Step{Server: each.Server}))
		}
	}
	r.warnf(area, "%s did not answer for the %s of %s, so a parent waits until it does before it acts (RFC 9975); if it stays silent, fix it or remove it from the delegation",
		strings.Join(silent, " and "), what, zone)
}

// agreeCSYNC asks every server of the zone for its CSYNC, and then each that
// has one for what it names: its SOA where the CSYNC waits for a serial, and
// its NS set where it asks for that to be copied. RFC 9975 3.2 has the flags
// and the types agree, each server's serial judged against its own SOA, and
// every NS set the same. The glue a CSYNC names is not asked of every server:
// it would be a question per nameserver name, per type, per server.
func (r *run) agreeCSYNC(ctx context.Context, chain *dnssec.Chain, answer *trace.Step, zone string, servers []trace.Server) *trace.Agreement {
	servers = r.sweepable(servers)
	if len(servers) < 2 {
		return nil
	}
	hops, questions, budget := r.sweep(ctx, answer, zone, servers, dns.TypeCSYNC)

	readings := make([]reading, len(hops))
	records := make([]*dns.CSYNC, len(hops))
	var follow []apexQuestion
	for i, hop := range hops {
		each := &readings[i]
		each.Server = questions[i].server
		got, state, reason := signedAnswer(chain, hop, zone, dns.TypeCSYNC)
		each.State, each.Reason = state, reason
		for _, rr := range got {
			if found, ok := rr.(*dns.CSYNC); ok && dns.EqualName(found.Hdr.Name, zone) {
				records[i] = found
				break
			}
		}
		follow = append(follow, named(each.Server, records[i])...)
	}

	// What each CSYNC names, asked of the server that published it.
	follow, spent := afford(r.counters, follow)
	followed := askAll(follow, func(q apexQuestion) *hop { return r.query(ctx, zone, q.server, zone, q.rrtype) })
	if budget == nil {
		budget = spent
	}
	type key struct {
		addr   netip.AddrPort
		rrtype uint16
	}
	keyOf := func(q apexQuestion) key { return key{netip.AddrPortFrom(q.server.IP, q.server.Port), q.rrtype} }
	held := make(map[key][]dns.RR)
	failed := make(map[key]reading)
	for i, hop := range followed {
		hop.step.Aside = true
		hop.step.Records = nil
		hop.step.Notes = append(hop.step.Notes, "request check: "+dnsutil.TypeToString(follow[i].rrtype)+" for the CSYNC of "+zone)
		r.attach(answer, hop.step)
		got, state, reason := signedAnswer(chain, hop, zone, follow[i].rrtype)
		if state != trace.ServerRequestRead {
			failed[keyOf(follow[i])] = reading{ServerRequest: trace.ServerRequest{State: state, Reason: reason}}
			continue
		}
		held[keyOf(follow[i])] = got
	}

	for i, hop := range hops {
		each := &readings[i]
		record := records[i]
	judged:
		switch {
		case each.State != trace.ServerRequestRead:
		case record == nil:
			each.Asks, each.same = "nothing", ""
		default:
			// What the budget did not pay for was never read, which is no
			// difference either.
			for _, q := range named(each.Server, record) {
				if bad, ok := failed[keyOf(q)]; ok {
					each.State, each.Reason = bad.State, bad.Reason
					break judged
				}
				if _, ok := held[keyOf(q)]; !ok {
					each.State, each.Reason = trace.ServerRequestUnanswered, "the budget ran out before what it names could be fetched"
					break judged
				}
			}
			each.Asks, each.same = csyncAsks(record, held[keyOf(apexQuestion{each.Server, dns.TypeSOA})], held[keyOf(apexQuestion{each.Server, dns.TypeNS})], zone)
		}
		hop.step.Notes = append(hop.step.Notes, "request check: "+each.note())
	}
	agreement := agreed(readings, budget, func(reading) bool { return false })

	switch agreement.State {
	case trace.AgreementDiffer:
		r.warnf(trace.AreaDelegation, "the nameservers of %s do not serve the same CSYNC: %s; a parent acts on none of it (RFC 9975), so the delegation stays as it is; publish the same CSYNC, and the NS set it names, from every nameserver",
			zone, requestsSaid(readings, hops))
	case trace.AgreementPartial:
		r.warnPartial(trace.AreaDelegation, zone, "CSYNC", readings, hops, budget)
	}
	return agreement
}

// named is what a server's CSYNC has to be read beside: the SOA its serial
// waits for, and the NS set it asks to be copied.
func named(server trace.Server, record *dns.CSYNC) []apexQuestion {
	if record == nil {
		return nil
	}
	var follow []apexQuestion
	if record.Flags&csyncSOAMinimum != 0 {
		follow = append(follow, apexQuestion{server, dns.TypeSOA})
	}
	if slices.Contains(record.TypeBitMap, dns.TypeNS) {
		follow = append(follow, apexQuestion{server, dns.TypeNS})
	}
	return follow
}

// csyncAsks is what one server's CSYNC asks for, as a reader says it and in the
// form held against the others'. The serial and the flag that waits for it can
// differ between providers; what counts is whether this server's own SOA has
// reached it, so a parent would act now (RFC 9975 3.2).
func csyncAsks(record *dns.CSYNC, soas, ns []dns.RR, zone string) (string, string) {
	types := make([]string, 0, len(record.TypeBitMap))
	for _, rrtype := range record.TypeBitMap {
		types = append(types, dnsutil.TypeToString(rrtype))
	}
	slices.Sort(types)
	asks := "a copy of " + strings.Join(types, " ")
	same := strings.Join(types, " ")
	if slices.Contains(record.TypeBitMap, dns.TypeNS) {
		var names []string
		for _, rr := range ns {
			if found, ok := rr.(*dns.NS); ok && dns.EqualName(found.Hdr.Name, zone) {
				names = append(names, strings.ToLower(dnsutil.Fqdn(found.Ns)))
			}
		}
		slices.SortFunc(names, cmp.Compare)
		names = slices.Compact(names)
		asks += " (its NS set: " + strings.Join(names, " ") + ")"
		same += " NS " + strings.Join(names, " ")
	}
	if record.Flags&csyncImmediate == 0 {
		asks += ", once approved"
		same += " manual"
	}
	if record.Flags&csyncSOAMinimum != 0 {
		var serial *uint32
		for _, rr := range soas {
			if found, ok := rr.(*dns.SOA); ok && dns.EqualName(found.Hdr.Name, zone) {
				serial = &found.Serial
			}
		}
		if serial == nil || serialBefore(*serial, record.Serial) {
			asks += fmt.Sprintf(", once serial %d is served", record.Serial)
			same += " waiting"
		}
	}
	return asks, same
}

// securedSignal is the request checkDS read from one server of a zone the
// chain reached secure, nil where it read none that a parent would act on.
func securedSignal(last zoneCut) *trace.Signal {
	verdict := last.step.DNSSEC
	if verdict == nil || verdict.State != trace.Secure || verdict.Signal == nil || verdict.Signal.State == trace.SignalUnchecked {
		return nil
	}
	return verdict.Signal
}

// provenCSYNC is the CSYNC checkNS read from one server, nil where it could not
// be proved, which says enough on its own. Without --dnssec no answer can be
// told from a forged one, and a parent acts only on signed ones.
func (r *run) provenCSYNC(chain *dnssec.Chain, referred *trace.Step, zone string) *trace.CSYNC {
	if !r.cfg.CheckNS || !r.cfg.DNSSEC || referred == nil || referred.Delegation == nil || referred.Delegation.CSYNC == nil {
		return nil
	}
	if !dns.EqualName(referred.Delegation.Zone, zone) {
		return nil
	}
	if chain == nil || chain.State() != trace.Secure || !dns.EqualName(chain.Zone(), zone) {
		return nil
	}
	switch csync := referred.Delegation.CSYNC; csync.State {
	case trace.CSYNCNone, trace.CSYNCReady, trace.CSYNCManual, trace.CSYNCWaiting:
		return csync
	}
	return nil
}

// sweepsRequests is whether checkRequests will ask every nameserver of zone,
// which is what the names the walk did not look up are needed for.
func (r *run) sweepsRequests(chain *dnssec.Chain, last zoneCut, referred *trace.Step, zone string) bool {
	if signal := securedSignal(last); r.cfg.CheckDS && signal != nil && signal.State != trace.SignalInconsistent && dns.EqualName(last.zone, zone) {
		return true
	}
	return r.provenCSYNC(chain, referred, zone) != nil
}

// checkRequests holds the CDS, CDNSKEY and CSYNC the walk read from one server
// against every other server of the zone, then says what a parent will do.
func (r *run) checkRequests(ctx context.Context, chain *dnssec.Chain, answer *trace.Step, last zoneCut, referred *trace.Step, zone string, servers []trace.Server) {
	if signal := securedSignal(last); r.cfg.CheckDS && signal != nil {
		// The servers are those of the zone the walk was referred to, which a
		// signer naming another zone is not asking about.
		if signal.State != trace.SignalInconsistent && dns.EqualName(last.zone, zone) {
			signal.Agreement = r.agreeDS(ctx, chain, answer, last.zone, servers)
		}
		// Where the servers disagree, that is why the parent does nothing,
		// and what the one server asked for is not a request a parent sees.
		if signal.Agreement == nil || signal.Agreement.State != trace.AgreementDiffer {
			r.warnSignal(last.zone, signal)
		}
	}
	if csync := r.provenCSYNC(chain, referred, zone); csync != nil {
		csync.Agreement = r.agreeCSYNC(ctx, chain, answer, zone, servers)
	}
}
