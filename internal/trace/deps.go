package trace

import "slices"

// Dependencies are the zones a name depends on: those its walk went through,
// and those the walks to the nameservers of each of them go through in turn.
// Whoever controls any one of them can make the name resolve somewhere else,
// and most of them nobody chose.
type Dependencies struct {
	Name string

	// Zones are the zones met, each once: the walk's own first, then in the
	// order the lookups came to them. The root is left out, since every name
	// depends on it and the walk reaches it through the hints.
	Zones []DependencyZone

	// Unresolved are the nameservers whose lookup came to no address, which
	// leaves the zones on their way unknown.
	Unresolved []UnresolvedNS

	// Stopped is why the lookups were left before every nameserver was looked
	// up, which leaves the list short of zones it would have had.
	Stopped string
}

// DependencyZone is one zone a name depends on.
type DependencyZone struct {
	Zone string

	// NS are the nameservers its parent delegated it to.
	NS []string

	// Via is the nameserver whose lookup came to the zone, and For the zone
	// that nameserver serves. Both are empty for a zone on the walk's own way.
	Via, For string

	// DNSSEC is the verdict on the delegation into the zone, nil where no
	// signatures were checked.
	DNSSEC *DNSSECStatus
}

// UnresolvedNS is a nameserver of For whose lookup failed, and why.
type UnresolvedNS struct {
	Name, For, Err string
}

// Unsigned counts the zones whose delegation was proved insecure.
func (d *Dependencies) Unsigned() int { return d.count(Insecure) }

// Bogus counts the zones whose delegation does not validate.
func (d *Dependencies) Bogus() int { return d.count(Bogus) }

func (d *Dependencies) count(state DNSSECState) int {
	n := 0
	for _, zone := range d.Zones {
		if zone.DNSSEC != nil && zone.DNSSEC.State == state {
			n++
		}
	}
	return n
}

// Shown is the dependencies with every name and reason escaped.
func (d *Dependencies) Shown() *Dependencies {
	if d == nil {
		return nil
	}
	shown := *d
	shown.Name, shown.Stopped = Shown(d.Name), Shown(d.Stopped)
	shown.Zones = slices.Clone(d.Zones)
	for i := range shown.Zones {
		zone := &shown.Zones[i]
		zone.Zone, zone.Via, zone.For = Shown(zone.Zone), Shown(zone.Via), Shown(zone.For)
		zone.NS = shownAll(zone.NS)
		zone.DNSSEC = zone.DNSSEC.shown()
	}
	shown.Unresolved = slices.Clone(d.Unresolved)
	for i := range shown.Unresolved {
		ns := &shown.Unresolved[i]
		ns.Name, ns.For, ns.Err = Shown(ns.Name), Shown(ns.For), Shown(ns.Err)
	}
	return &shown
}
