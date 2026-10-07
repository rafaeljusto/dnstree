package resolver

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// svcb follows the name's HTTPS records, or its SVCB records where those were
// asked for, to the servers a client would connect to (RFC 9460 3): down the
// alias chain, then to the addresses of every target the last set names,
// which are held against the hints the records carry. end is where the walk
// for the question ended, whose answer is the first set where the question
// was for one. Every other lookup is a walk of its own, drawn as an aside
// under under.
func (r *run) svcb(ctx context.Context, under, end *trace.Step) {
	name, qtype := r.trace.Question.Name, dns.TypeHTTPS
	if r.trace.Question.Type == "SVCB" {
		qtype = dns.TypeSVCB
	}

	r.aside, r.asideStopped = true, false
	defer func() { r.aside = false }()

	p := &trace.ServicePath{Name: name, Type: dnsutil.TypeToString(qtype)}
	r.trace.ServicePath = p

	var result *trace.Step
	var lookup trace.Lookup
	stopped, own := false, r.trace.Question.Type == p.Type
	if own {
		result, lookup = end, ended(name, r.trace.Root, end)
	} else {
		result, lookup, stopped = r.look(ctx, under, name, qtype, "svcb")
	}

	// RFC 9460 2.4.2 wants a limit on the aliases followed, and --max-cname
	// is the one a walk already keeps on the aliases it follows.
	seen := map[string]bool{dnsutil.Canonical(name): true}
	targets := []trace.ServiceTarget(nil)

	// weakest is the first verdict on the chain so far that is not secure: an
	// unsigned alias can send a client anywhere, signed or not.
	var weakest *trace.DNSSECStatus
	for {
		set := trace.ServiceSet{Lookup: lookup}
		if result != nil && lookup.Err == "" {
			set.Records = serviceRecords(result.Records, result.Asked.Name, p.Type)
		}
		p.Chain = append(p.Chain, set)
		at := cmp.Or(lookup.Alias, lookup.Name)
		if weakest == nil || weakest.State == trace.Secure {
			weakest = lookup.DNSSEC
		}

		if !own || len(p.Chain) > 1 {
			r.echOn(set, weakest)
		}
		switch {
		case stopped:
			p.Stopped = "the budget ran out before the " + p.Type + " set at " + lookup.Name + " was answered"
		case lookup.Err != "":
			p.Stopped = "the " + p.Type + " lookup of " + lookup.Name + " failed: " + lookup.Err
			r.warnf(trace.AreaAnswer, "the %s lookup of %s failed (%s), so a client connects without what its records offer; fix the servers of its zone",
				p.Type, lookup.Name, lookup.Err)
		case r.cfg.DNSSEC && lookup.DNSSEC != nil && lookup.DNSSEC.State == trace.Bogus:
			p.Stopped = "the " + p.Type + " set at " + at + " does not validate: " + lookup.DNSSEC.Reason
			r.warnf(trace.AreaDNSSEC, "the %s set at %s does not validate (%s), so a client that validates gets none of it; fix the signatures of its zone",
				p.Type, at, lookup.DNSSEC.Reason)
		}
		if p.Stopped != "" {
			break
		}

		aliases, services := split(set.Records)
		if len(aliases) == 0 {
			targets = serviceTargets(services)
			if len(services) == 0 {
				p.Fallback = true
				if len(p.Chain) > 1 {
					targets = []trace.ServiceTarget{{Name: at}}
				}
			}
			break
		}

		if len(services) > 0 {
			r.warnf(trace.AreaAnswer, "%s has %s records in alias and in service mode, and a client ignores the service mode ones (RFC 9460 2.4.2); remove the alias or the service mode records",
				at, p.Type)
		}
		if len(aliases) > 1 {
			r.warnf(trace.AreaAnswer, "%s has %d %s records in alias mode, where RFC 9460 2.4.2 asks for one, and a client picks one at random; keep one",
				at, len(aliases), p.Type)
		}
		next := aliases[0].Service.Target
		switch {
		case next == ".":
			p.None = true
		case seen[dnsutil.Canonical(next)]:
			p.Stopped = "the aliases loop back to " + next
			r.warnf(trace.AreaAnswer, "the %s aliases of %s loop back to %s, so a client gives up on them; end the chain on a record in service mode",
				p.Type, name, next)
		case len(p.Chain) > r.counters.max.MaxCNAME:
			p.Stopped = "the aliases go on past --max-cname " + strconv.Itoa(r.counters.max.MaxCNAME)
			r.warnf("", "the %s aliases of %s go on past --max-cname %d, so the rest were not followed; raise --max-cname to follow them",
				p.Type, name, r.counters.max.MaxCNAME)
		}
		if p.None || p.Stopped != "" {
			break
		}
		seen[dnsutil.Canonical(next)] = true
		result, lookup, stopped = r.look(ctx, under, next, qtype, "svcb")
	}

	for i := range targets {
		if r.counters.spent() {
			p.Cut = true
			break
		}
		r.addresses(ctx, under, &targets[i])
		p.Cut = p.Cut || r.asideStopped
	}
	p.Targets = targets

	if r.counters.spent() || r.asideStopped {
		p.Cut = true
		r.warnf("", "the %s check of %s ran out of budget before every lookup was made; raise the budget that ran out", p.Type, name)
	}
	r.warnService(p)
}

// serviceRecords are the records of type qtype owner owns, each decoded, by
// priority, so that they read in the order their targets are followed.
func serviceRecords(records []trace.RR, owner, qtype string) []trace.RR {
	var found []trace.RR
	for _, record := range records {
		if record.Type == qtype && record.Service != nil && dns.EqualName(record.Name, owner) {
			found = append(found, record)
		}
	}
	slices.SortStableFunc(found, func(a, b trace.RR) int { return cmp.Compare(a.Service.Priority, b.Service.Priority) })
	return found
}

// split sorts a set into its records in alias mode, by target so that two
// walks follow the same one, and those in service mode, by priority.
func split(records []trace.RR) (aliases, services []trace.RR) {
	for _, record := range records {
		if record.Service.Priority == 0 {
			aliases = append(aliases, record)
		} else {
			services = append(services, record)
		}
	}
	slices.SortFunc(aliases, func(a, b trace.RR) int { return dns.CompareName(a.Service.Target, b.Service.Target) })
	slices.SortStableFunc(services, func(a, b trace.RR) int { return cmp.Compare(a.Service.Priority, b.Service.Priority) })
	return aliases, services
}

// serviceTargets are the servers records in service mode name, each once,
// with every hint the records naming it carry. A target of "." is the owner
// of the record (RFC 9460 2.5).
func serviceTargets(services []trace.RR) []trace.ServiceTarget {
	var targets []trace.ServiceTarget
	for _, record := range services {
		name := record.Service.Target
		if name == "." {
			name = dnsutil.Fqdn(record.Name)
		}
		i := slices.IndexFunc(targets, func(t trace.ServiceTarget) bool { return dns.EqualName(t.Name, name) })
		if i < 0 {
			targets = append(targets, trace.ServiceTarget{Name: name, Priority: record.Service.Priority})
			i = len(targets) - 1
		}
		for _, hint := range record.Service.Hints {
			if !slices.Contains(targets[i].Hints, hint) {
				targets[i].Hints = append(targets[i].Hints, hint)
			}
		}
	}
	return targets
}

// addresses looks up the A and AAAA sets of a target, as far as the run's
// family allows, and finds the hints that are none of them.
func (r *run) addresses(ctx context.Context, under *trace.Step, target *trace.ServiceTarget) {
	judged := map[int]bool{}
	for _, f := range []struct {
		family int
		qtype  uint16
		into   **trace.Lookup
	}{{4, dns.TypeA, &target.IPv4}, {6, dns.TypeAAAA, &target.IPv6}} {
		if r.cfg.Family != 0 && r.cfg.Family != f.family {
			continue
		}
		result, lookup, stopped := r.look(ctx, under, target.Name, f.qtype, "svcb")
		*f.into = &lookup
		if stopped {
			return
		}
		if lookup.Err != "" {
			continue
		}
		judged[f.family] = true
		for _, record := range result.Records {
			if record.Type != dnsutil.TypeToString(f.qtype) || !dns.EqualName(record.Name, result.Asked.Name) {
				continue
			}
			if addr, err := netip.ParseAddr(record.Data); err == nil && !slices.Contains(target.Addrs, addr) {
				target.Addrs = append(target.Addrs, addr)
			}
		}
	}
	for _, hint := range target.Hints {
		if judged[family(hint)] && !slices.Contains(target.Addrs, hint) {
			target.Stray = append(target.Stray, hint)
		}
	}
}

// echOn warns about an ECH configuration in a set of the chain the way
// checkECH does about one in the walk's own answer, judged by the weakest
// verdict on the chain down to it.
func (r *run) echOn(set trace.ServiceSet, weakest *trace.DNSSECStatus) {
	for _, record := range set.Records {
		if record.Service.ECH {
			r.warnECH(record.Name, weakest)
			return
		}
	}
}

// warnService says what in the path sends a client somewhere other than where
// its owner may think.
func (r *run) warnService(p *trace.ServicePath) {
	for _, target := range p.Targets {
		switch {
		case target.Failed() != "":
			r.warnf(trace.AreaAnswer, "the addresses of %s, which the %s records of %s lead to, could not be looked up (%s), so a client may have nothing to connect to; fix the servers of its zone",
				target.Name, p.Type, p.Name, target.Failed())
		case target.Nowhere():
			r.warnf(trace.AreaAnswer, "%s, which the %s records of %s lead to, has no address, so a client has nothing to connect to; fix the record or give the target an address",
				target.Name, p.Type, p.Name)
		case len(target.Stray) > 0:
			var stray []string
			for _, hint := range target.Stray {
				stray = append(stray, hint.String())
			}
			r.warnf(trace.AreaAnswer, "the %s records naming %s hint at %s, which %s not among its addresses, so a client that connects on the hint may reach another server; update the %s or remove %s",
				p.Type, target.Name, strings.Join(stray, ", "), verb(stray, "is", "are"), verb(stray, "hint", "hints"), verb(stray, "it", "them"))
		}
	}
}
