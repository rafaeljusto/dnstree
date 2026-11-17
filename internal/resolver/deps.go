package resolver

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// deps finds every zone the name depends on: the zones its walk was referred
// to, then those the lookup of each of their nameservers is referred to, and
// so on until no nameserver is left that has not been looked up. A walk stops
// at the first nameserver it can reach; any of the others can answer too, so
// every one of them is followed. Every lookup is a walk of its own, drawn as
// an aside under under.
func (r *run) deps(ctx context.Context, under *trace.Step) {
	name := r.trace.Question.Name

	r.aside, r.asideStopped = true, false
	defer func() { r.aside = false }()

	d := &trace.Dependencies{Name: name}
	r.trace.Dependencies = d

	known := make(map[string]bool)
	keep := func(via, of string) func(*trace.Step) {
		return func(step *trace.Step) {
			zone := step.Delegation.Zone
			if known[dnsutil.Canonical(zone)] {
				return
			}
			known[dnsutil.Canonical(zone)] = true
			d.Zones = append(d.Zones, trace.DependencyZone{
				Zone: zone, NS: step.Delegation.NS, Glue: len(step.Delegation.Glue) > 0,
				Via: via, For: of, DNSSEC: step.DNSSEC,
			})
		}
	}
	referrals(r.trace.Root, keep("", ""))

	rrtype := uint16(dns.TypeA)
	if r.cfg.Family == 6 {
		rrtype = dns.TypeAAAA
	}

	// Each name is looked up once and each zone kept once, so zones that
	// serve each other end the loop rather than feed it.
	asked := make(map[string]bool)
	for i := 0; i < len(d.Zones) && d.Stopped == ""; i++ {
		zone := d.Zones[i]
		for _, ns := range zone.NS {
			// A nameserver inside its own zone adds no zone the list does not
			// have.
			if dnsutil.IsBelow(zone.Zone, ns) || asked[dnsutil.Canonical(ns)] {
				continue
			}
			asked[dnsutil.Canonical(ns)] = true

			from := len(under.Children)
			result, lookup, stopped := r.look(ctx, under, ns, rrtype, "deps")
			for _, root := range under.Children[from:] {
				referrals(root, keep(ns, zone.Zone))
			}
			if stopped {
				d.Stopped = "the budget ran out before every nameserver was looked up"
				break
			}
			r.claim(ctx, result, r.orphan(result), trace.DanglingNameserver, zone.Zone, zone.Zone)

			switch {
			case lookup.Err != "":
				d.Unresolved = append(d.Unresolved, trace.UnresolvedNS{Name: ns, For: zone.Zone, Err: lookup.Err})
			case result.Kind == trace.KindNXDomain:
				d.Unresolved = append(d.Unresolved, trace.UnresolvedNS{Name: ns, For: zone.Zone, Err: "does not exist"})
			}
		}
	}

	d.Work = work(d)

	if d.Stopped != "" {
		budget := "the budget that ran out"
		if r.counters.spent() {
			budget = "--max-queries"
		}
		r.warnf("", "the dependencies of %s ran out of budget before every nameserver was looked up; raise %s", name, budget)
	}
}

// referrals hands found every referral below step that is part of its walk,
// leaving out the asides, which answer questions of their own.
func referrals(step *trace.Step, found func(*trace.Step)) {
	for _, child := range step.Children {
		if child.Aside {
			continue
		}
		if child.Kind == trace.KindReferral && child.Delegation != nil {
			found(child)
		}
		referrals(child, found)
	}
}

// work counts, for each zone on the walk's own way, the queries a resolver with
// nothing cached makes before it can ask the zone anything (trace.ZoneWork).
// It reads only the zones the lookups met, so a nameserver no lookup reached
// is one no count goes through, and a zone with none left is not counted.
//
// Zones that serve each other's nameservers make the counts lean on each
// other, so they are lowered pass by pass until none moves. Every pass that
// goes on lowers one, and a count never goes below the referrals to the zone,
// so the passes end.
func work(d *trace.Dependencies) []trace.ZoneWork {
	type cost struct {
		queries, glueless, depth int
		via                      string
	}
	zones := make(map[string]*trace.DependencyZone, len(d.Zones))
	for i := range d.Zones {
		zones[dnsutil.Canonical(d.Zones[i].Zone)] = &d.Zones[i]
	}
	unresolved := make(map[string]bool, len(d.Unresolved))
	for _, ns := range d.Unresolved {
		unresolved[dnsutil.Canonical(ns.Name)] = true
	}

	// enclosing is the deepest zone met that name is in, the root where none,
	// leaving name itself out where strictly.
	enclosing := func(name string, strictly bool) string {
		name = dnsutil.Canonical(name)
		for off, end := 0, false; !end; off, end = dnsutil.Next(name, off) {
			if suffix := name[off:]; (off > 0 || !strictly) && zones[suffix] != nil {
				return suffix
			}
		}
		return "."
	}

	costs := map[string]cost{".": {}}
	for changed := true; changed; {
		changed = false
		for _, zone := range d.Zones {
			key := dnsutil.Canonical(zone.Zone)
			above, ok := costs[enclosing(key, true)]
			if !ok {
				continue
			}
			next := cost{queries: above.queries + 1, glueless: above.glueless, depth: above.depth}
			if !zone.Glue {
				var best *cost
				for _, ns := range zone.NS {
					if unresolved[dnsutil.Canonical(ns)] || dnsutil.IsBelow(zone.Zone, ns) {
						continue
					}
					holder, ok := costs[enclosing(ns, false)]
					if !ok {
						continue
					}
					found := cost{queries: holder.queries + 1, depth: holder.depth, via: ns}
					if best == nil || found.queries < best.queries || found.queries == best.queries && found.depth < best.depth {
						best = &found
					}
				}
				if best == nil {
					continue
				}
				next.queries += best.queries
				next.glueless += best.queries
				next.depth = max(next.depth, best.depth) + 1
				next.via = best.via
			}
			if old, ok := costs[key]; !ok || next.queries < old.queries || next.queries == old.queries && next.depth < old.depth {
				costs[key] = next
				changed = true
			}
		}
	}

	var counted []trace.ZoneWork
	for _, zone := range d.Zones {
		if zone.Via != "" {
			continue
		}
		if c, ok := costs[dnsutil.Canonical(zone.Zone)]; ok {
			counted = append(counted, trace.ZoneWork{Zone: zone.Zone, Queries: c.queries,
				Glueless: c.glueless, Depth: c.depth, Via: c.via})
		}
	}
	return counted
}
