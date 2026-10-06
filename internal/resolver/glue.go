package resolver

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

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
		r.warnf(trace.AreaDelegation, "%s did not return its own NS records", delegated.Zone)
	} else {
		if missing := missing(delegated.NS, child); len(missing) > 0 {
			r.warnf(trace.AreaDelegation, "%s delegates to %s, which the zone itself does not list",
				delegated.Zone, strings.Join(missing, ", "))
		}
		if extra := missing(child, delegated.NS); len(extra) > 0 {
			r.warnf(trace.AreaDelegation, "%s lists %s, which the delegation does not carry",
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

	questions, budget := afford(r.counters, questions)
	hops := askAll(questions, func(q question) *hop { return r.query(ctx, delegated.Zone, server, q.name, q.rrtype) })

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
		r.warnf(trace.AreaDelegation, "the budget ran out before the glue of %s could be checked", delegated.Zone)
	}
}

// warnAliasedNS says a nameserver's name is an alias. A resolver looking up
// the address of a nameserver is not required to follow one (RFC 2181 section
// 10.3), so the zone resolves through some resolvers and not others, and this
// walk, which does not follow it, may not reach the zone at all.
func (r *run) warnAliasedNS(zone, name, target string) {
	r.warnOnceIn(trace.AreaDelegation, zone, "%s delegates to %s, which is an alias for %s; name the nameserver by its own name, since resolvers need not follow an alias to find one (RFC 2181 section 10.3)",
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
	r.warnOnceIn(trace.AreaDelegation, zone, "%s is an alias at the top of its zone, which hides the zone's SOA and NS from every resolver that asks (RFC 1034 section 3.6.2); serve the records there rather than an alias",
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
		r.warnf(trace.AreaDelegation, "%s hands out no %s address for %s, which %s gives as %s; have the registrar add it to the glue",
			parent, familyName(rrtype), name, zone, joinAddrs(held))
	case len(held) == 0:
		r.warnf(trace.AreaDelegation, "%s hands out %s for %s, which %s itself does not give; have the registrar remove it from the glue",
			parent, joinAddrs(glue), name, zone)
	default:
		r.warnf(trace.AreaDelegation, "%s hands out %s for %s, which %s itself gives as %s; have the registrar update the glue",
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
