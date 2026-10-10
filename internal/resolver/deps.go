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
				Zone: zone, NS: step.Delegation.NS, Via: via, For: of, DNSSEC: step.DNSSEC,
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
