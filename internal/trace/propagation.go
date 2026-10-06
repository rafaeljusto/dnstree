package trace

import "strings"

// Propagation is how long each kind of change to the zone the walk ended in
// takes to reach every cache, read off the TTLs the walk recorded. Nothing is
// pushed out when a zone changes: the old copies run out, and a change waits
// on every copy it depends on. Each wait is the worst case, a cache filled
// just before the change.
type Propagation struct {
	Zone  string
	Waits []Wait
}

// Wait is how long one kind of change takes to reach every cache, and the TTLs
// it was worked out from.
type Wait struct {
	Change  Change
	Seconds uint32

	// Type is the record whose TTL decides the wait, and Held each TTL of it
	// the walk read, where it was served.
	Type string
	Held []Held
}

// Held is one TTL a wait was worked out from.
type Held struct {
	Zone string
	TTL  uint32

	// Field is the part of the record the number came from where it is not
	// the TTL: the minimum of an SOA, which caps how long a denial is kept.
	Field string
}

// Change is a kind of change to a zone.
type Change string

// The kinds of change a wait is worked out for.
const (
	ChangeAnswer      Change = "answer"      // the records that answered
	ChangeDenial      Change = "denial"      // a name or type that did not exist, created
	ChangeNameservers Change = "nameservers" // the zone moved to other nameservers
	ChangeDS          Change = "ds"          // the DS the parent publishes
	ChangeKeys        Change = "keys"        // the zone's DNSKEY set
)

// Propagated is how long changes to the zone the walk ended in take to reach
// every cache. A wait the walk read no TTL for is left out rather than
// guessed, so a walk that reached no zone has none.
func (t *Trace) Propagated() *Propagation {
	zone := t.Ended()
	p := &Propagation{Zone: zone}
	if zone == "" {
		return p
	}

	if result := t.Result(); result != nil && result.Kind != KindNXDomain && result.Kind != KindNoData {
		if ttl := t.Allowed(); ttl > 0 {
			p.Waits = append(p.Waits, Wait{Change: ChangeAnswer, Seconds: ttl, Type: t.Question.Type,
				Held: []Held{{Zone: result.Zone, TTL: ttl}}})
		}
	}
	if wait, ok := t.denial(zone); ok {
		p.Waits = append(p.Waits, wait)
	}
	if wait, ok := t.nameservers(zone); ok {
		p.Waits = append(p.Waits, wait)
	}
	p.Waits = append(p.Waits, t.keys(zone)...)
	return p
}

// Ended is the zone the walk came to rest in: the one that answered, or the
// last one it got to.
func (t *Trace) Ended() string {
	if result := t.Result(); result != nil {
		return result.Zone
	}
	var zone string
	for step := range t.Mainline() {
		if step.Kind != KindZone {
			zone = step.Zone
		}
	}
	return zone
}

// denial is how long a cache keeps a name or type the zone said does not
// exist: the shorter of the SOA's TTL and its minimum (RFC 2308). The SOA
// comes with a denial, or with --serial; the longest any server gave is the
// one every cache has let go of by.
func (t *Trace) denial(zone string) (Wait, bool) {
	var found *SOA
	for step := range t.Steps() {
		soa := step.SOA
		if soa == nil || !strings.EqualFold(step.Zone, zone) {
			continue
		}
		if found == nil || min(soa.TTL, soa.Minimum) > min(found.TTL, found.Minimum) {
			found = soa
		}
	}
	if found == nil || min(found.TTL, found.Minimum) == 0 {
		return Wait{}, false
	}
	return Wait{Change: ChangeDenial, Seconds: min(found.TTL, found.Minimum), Type: "SOA", Held: []Held{
		{Zone: zone, TTL: found.TTL},
		{Zone: zone, TTL: found.Minimum, Field: "minimum"},
	}}, true
}

// nameservers is how long the old nameservers go on being asked after a move.
// Resolvers differ over whose NS set they keep, the parent's or the zone's own
// once they have seen it, so the move takes the longer of the two.
func (t *Trace) nameservers(zone string) (Wait, bool) {
	var (
		parent     string
		above, own uint32
	)
	for step := range t.Mainline() {
		d := step.Delegation
		if d == nil || !strings.EqualFold(d.Zone, zone) {
			continue
		}
		if d.TTL >= above {
			parent, above = step.Zone, d.TTL
		}
		own = max(own, d.ZoneTTL)
	}
	if above == 0 {
		return Wait{}, false
	}
	wait := Wait{Change: ChangeNameservers, Seconds: max(above, own), Type: "NS",
		Held: []Held{{Zone: parent, TTL: above}}}
	if own > 0 {
		wait.Held = append(wait.Held, Held{Zone: zone, TTL: own})
	}
	return wait, true
}

// keys is how long a new DS and a new DNSKEY set take to reach every cache,
// where the chain of trust entered the zone and held. A rollover is steps that
// each wait on one of these.
func (t *Trace) keys(zone string) []Wait {
	var (
		parent      string
		ds, dnskeys uint32
	)
	for step := range t.Mainline() {
		status := step.DNSSEC
		if status == nil || status.State != Secure || !strings.EqualFold(status.Zone, zone) {
			continue
		}
		// The parent is where the DS came from, and a step of the zone itself
		// is not a referral to it.
		if status.DSTTL > ds && !strings.EqualFold(step.Zone, zone) {
			parent, ds = step.Zone, status.DSTTL
		}
		dnskeys = max(dnskeys, status.KeysTTL)
	}

	var waits []Wait
	if ds > 0 {
		waits = append(waits, Wait{Change: ChangeDS, Seconds: ds, Type: "DS", Held: []Held{{Zone: parent, TTL: ds}}})
	}
	if dnskeys > 0 {
		waits = append(waits, Wait{Change: ChangeKeys, Seconds: dnskeys, Type: "DNSKEY",
			Held: []Held{{Zone: zone, TTL: dnskeys}}})
	}
	return waits
}

// Shown is the propagation with every string in it escaped.
func (p *Propagation) Shown() *Propagation {
	if p == nil {
		return nil
	}
	shown := Propagation{Zone: Shown(p.Zone)}
	for _, wait := range p.Waits {
		held := make([]Held, len(wait.Held))
		for i, h := range wait.Held {
			held[i] = Held{Zone: Shown(h.Zone), TTL: h.TTL, Field: Shown(h.Field)}
		}
		wait.Type, wait.Held = Shown(wait.Type), held
		wait.Change = Change(Shown(string(wait.Change)))
		shown.Waits = append(shown.Waits, wait)
	}
	return &shown
}
