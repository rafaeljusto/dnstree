package resolver

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// look looks name up with a walk of its own, drawn as an aside under under,
// starting from the deepest zone the run has entered that name sits in. It
// returns the step the walk ended on, nil where it got nowhere, the lookup as
// the check keeps it, whose Err is set unless the step answered, and whether a
// budget of the run's stopped it, which says nothing of the zone. purpose names
// the check in the note the aside carries.
func (r *run) look(ctx context.Context, under *trace.Step, name string, qtype uint16, purpose string) (*trace.Step, trace.Lookup, bool) {
	lookup := trace.Lookup{Name: name}
	if r.counters.spent() {
		lookup.Err = "the budget ran out before it was made"
		r.asideStopped = true
		return nil, lookup, true
	}
	cnames := r.counters.cnames

	from, zone := r.cutOf(name), "."
	if from != nil {
		zone = from.zone
	}

	// The walk's own aliases are not this lookup's, and must not read as a loop.
	saved := r.chased
	r.chased = map[string]bool{dnsutil.Canonical(name): true}
	defer func() { r.chased = saved }()

	root := &trace.Step{Zone: zone, Kind: trace.KindZone, Aside: true,
		Notes: []string{dnsutil.TypeToString(qtype) + " of " + name + " for " + purpose}}
	r.attach(under, root)
	result := r.walkFrom(ctx, from, name, qtype, root, 0)

	lookup.DNSSEC = verdictOn(root, result)
	answered := result != nil &&
		(result.Kind == trace.KindAnswer || result.Kind == trace.KindNoData || result.Kind == trace.KindNXDomain)
	// A budget that ran out on the way may also have left the chain of trust
	// short of the keys it needed, so even an answer is not one to judge by.
	if r.counters.spentSince(cnames) {
		r.asideStopped = true
		lookup.Err = "the budget ran out before it was answered"
		return result, lookup, true
	}
	switch {
	case result == nil:
		lookup.Err = "no server answered"
		return nil, lookup, false
	case !answered:
		lookup.Err = why(result)
		return result, lookup, false
	}
	if !dns.EqualName(result.Asked.Name, name) {
		lookup.Alias = result.Asked.Name
	}
	return result, lookup, false
}

// verdictOn is the first verdict that is not secure among the answers on the
// way from root to result, the aliases included, or else the last of them.
func verdictOn(root, result *trace.Step) *trace.DNSSECStatus {
	var last *trace.DNSSECStatus
	for _, step := range pathTo(root, result) {
		switch step.Kind {
		case trace.KindAnswer, trace.KindCNAME, trace.KindNoData, trace.KindNXDomain:
		default:
			continue
		}
		if step.Minimised || step.DNSSEC == nil {
			continue
		}
		if step.DNSSEC.State != trace.Secure {
			return step.DNSSEC
		}
		last = step.DNSSEC
	}
	return last
}

// pathTo is the steps from step down to target, both included, nil where
// target is not below step.
func pathTo(step, target *trace.Step) []*trace.Step {
	if step == nil || target == nil {
		return nil
	}
	if step == target {
		return []*trace.Step{step}
	}
	for _, child := range step.Children {
		if path := pathTo(child, target); path != nil {
			return append([]*trace.Step{step}, path...)
		}
	}
	return nil
}
