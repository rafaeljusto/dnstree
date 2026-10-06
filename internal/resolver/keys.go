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
			r.warnf(trace.AreaDNSSEC, "the request %s makes of its parent could not be checked: %s", zone, reason)
			return
		}
		fetched[i] = records
	}

	signal := dnssec.Signal(last.authority, zone, fetched[0], fetched[1])
	verdict.Signal = signal
	switch signal.State {
	case trace.SignalPending:
		r.warnf(trace.AreaDNSSEC, "%s asks its parent for a DS it does not publish (%s), so a key rollover is waiting on the parent; if it has waited longer than the parent polls, ask the registrar why",
			zone, signal.Reason)
	case trace.SignalDelete:
		r.warnf(trace.AreaDNSSEC, "%s asks its parent to remove its DS (RFC 8078), which leaves it unsigned once the parent acts; if that is not the plan, remove its CDS and CDNSKEY",
			zone)
	case trace.SignalInconsistent:
		r.warnf(trace.AreaDNSSEC, "the CDS and CDNSKEY of %s do not describe the same keys (%s), so a parent acts on neither; publish both from one key set",
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

	questions, budget := afford(r.counters, questions)
	hops := askAll(questions, func(q question) *hop { return r.query(ctx, zone, q.server, zone, q.rrtype) })

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
		r.warnf(trace.AreaDNSSEC, "the nameservers of %s do not publish the same keys: %s %s key %d, which %s %s with, so a resolver that took the keys from %s rejects what %s answers; publish every signer's keys from every nameserver (RFC 8901)",
			zone, strings.Join(lacking, " and "), verb(lacking, "lacks", "lack"), tag,
			strings.Join(signers, " and "), verb(signers, "signs", "sign"),
			orList(lacking), orList(signers))
	}
	if budget != nil {
		r.warnf(trace.AreaDNSSEC, "the budget ran out before every nameserver of %s could be asked for its keys", zone)
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
