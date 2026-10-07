package trace

import (
	"cmp"
	"net/netip"
	"slices"
)

// ServicePath is where a client that reads HTTPS or SVCB records (RFC 9460)
// connects for a name: the alias chain the records lead down, and the servers
// the last set of them names, with their addresses.
type ServicePath struct {
	Name string
	Type string // HTTPS or SVCB

	// Chain is each set looked up, the name's own first, then the target of
	// each alias mode record that was followed.
	Chain []ServiceSet

	// Targets are the servers the service mode records of the last set name,
	// each once, best priority first. Where aliases were followed to a name
	// with no records, it is the one target, and Fallback is set.
	Targets []ServiceTarget

	// Fallback is a chain that ended on no records, which leaves a client
	// connecting to the last name by its addresses alone (RFC 9460 3).
	Fallback bool

	// None is an alias to ".", which says the service does not exist.
	None bool

	// Stopped is why the chain was left before its end: a lookup that failed
	// or did not validate, a loop, too many aliases, or a budget of the run.
	Stopped string

	// Cut is a path whose address lookups a budget cut short, which leaves the
	// hints unjudged.
	Cut bool
}

// ServiceSet is the HTTPS or SVCB set at one name of the chain.
type ServiceSet struct {
	Lookup  Lookup
	Records []RR
}

// ServiceTarget is one server the records name, and what its addresses are.
type ServiceTarget struct {
	Name string

	// Priority is the best of the records that name it.
	Priority uint16

	// IPv4 and IPv6 are the lookups of its A and AAAA sets, nil where they
	// were not asked.
	IPv4 *Lookup
	IPv6 *Lookup

	Addrs []netip.Addr

	// Hints are the addresses the records naming it hint at, and Stray those
	// of them that are none of its addresses, judged only for a family whose
	// lookup was answered.
	Hints []netip.Addr
	Stray []netip.Addr
}

// Nowhere is a target whose every address lookup was answered, with none.
func (t ServiceTarget) Nowhere() bool {
	asked := 0
	for _, lookup := range []*Lookup{t.IPv4, t.IPv6} {
		if lookup == nil {
			continue
		}
		if lookup.Err != "" {
			return false
		}
		asked++
	}
	return asked > 0 && len(t.Addrs) == 0
}

// Failed is why the address lookups of a target failed, where every one asked
// did, and empty otherwise.
func (t ServiceTarget) Failed() string {
	why := ""
	for _, lookup := range []*Lookup{t.IPv4, t.IPv6} {
		if lookup == nil {
			continue
		}
		if lookup.Err == "" {
			return ""
		}
		why = cmp.Or(why, lookup.Err)
	}
	return why
}

// Shown is the path with every name and text the zones wrote escaped.
func (p *ServicePath) Shown() *ServicePath {
	if p == nil {
		return nil
	}
	shown := *p
	shown.Name, shown.Type, shown.Stopped = Shown(p.Name), Shown(p.Type), Shown(p.Stopped)
	shown.Chain = slices.Clone(p.Chain)
	for i := range shown.Chain {
		set := &shown.Chain[i]
		set.Lookup = set.Lookup.shown()
		set.Records = shownRecords(set.Records)
	}
	shown.Targets = slices.Clone(p.Targets)
	for i := range shown.Targets {
		target := &shown.Targets[i]
		target.Name = Shown(target.Name)
		target.IPv4, target.IPv6 = target.IPv4.shownRef(), target.IPv6.shownRef()
	}
	return &shown
}
