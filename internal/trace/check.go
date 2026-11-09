package trace

import (
	"slices"
	"strings"
)

// Area is what part of a zone's health a check, or a warning, is about.
type Area string

// The areas --check grades, in the order it says them.
const (
	AreaAnswer       Area = "answer"       // what the walk came to
	AreaDelegation   Area = "delegation"   // the parent and the zone agree on the nameservers and their glue
	AreaConsistency  Area = "consistency"  // every nameserver serves the same copy and the same answer
	AreaDNSSEC       Area = "dnssec"       // the chain of trust, and what the zone asks its parent
	AreaServers      Area = "servers"      // every nameserver answers, with authority and room to spare
	AreaEDNS         Area = "edns"         // EDNS, TCP and DNS cookies are handled as they should be
	AreaStrangers    Area = "strangers"    // no zone transfer or recursion for strangers
	AreaCAA          Area = "caa"          // who may issue certificates for the name
	AreaMail         Area = "mail"         // mail to and as the name
	AreaRegistration Area = "registration" // the registry holds the domain, with time left
)

// Areas are the areas --check grades, in order.
var Areas = []Area{AreaAnswer, AreaDelegation, AreaConsistency, AreaDNSSEC, AreaServers,
	AreaEDNS, AreaStrangers, AreaCAA, AreaMail, AreaRegistration}

// Concern is what a warning is about: an area, and the zone it was raised
// over where it is about one zone of the many a walk passes through. Only the
// zone --check grades counts against it.
type Concern struct {
	Area Area
	Zone string
}

// Grade is how an area came out.
type Grade string

// How an area can come out.
const (
	GradePassed  Grade = "passed"
	GradeLook    Grade = "look"    // worth a look, but nothing is broken
	GradeBroken  Grade = "broken"  // no answer, or none to trust
	GradeSkipped Grade = "skipped" // not checked, or nothing there to check
)

// Check is what --check made of the walk: one grade for each area, worked out
// once the walk is over from what the walk recorded. It is kept in the trace,
// and read back from a file, because the area each warning belongs to is known
// only to the walk that raised it.
type Check struct {
	// Zone is the zone the walk ended in, whose health this is.
	Zone  string
	Areas []Graded
}

// Graded is one area and how it came out.
type Graded struct {
	Area  Area
	Grade Grade

	// Text is what passed, what to look at or what broke; for an area with
	// more than one thing to say, the worst of them.
	Text string

	// More is how many other things the area had to say, which are among the
	// warnings or what --explain says.
	More int
}

// Count is how many areas came out with this grade.
func (c *Check) Count(grade Grade) int {
	if c == nil {
		return 0
	}
	n := 0
	for _, area := range c.Areas {
		if area.Grade == grade {
			n++
		}
	}
	return n
}

// DelegationOf is the referral that pointed the walk at zone, nil for a zone
// nothing referred it to: the root, or wherever a walk was told to start.
func (t *Trace) DelegationOf(zone string) *Delegation {
	for step := range t.Mainline() {
		if step.Delegation != nil && strings.EqualFold(step.Delegation.Zone, zone) {
			return step.Delegation
		}
	}
	return nil
}

// NSAgree is whether the parent and the zone list the same nameservers, and
// false for known where --check-ns did not get the zone's own list.
func (d *Delegation) NSAgree() (agree, known bool) {
	if d == nil || len(d.ZoneNS) == 0 {
		return false, false
	}
	return sameNames(d.NS, d.ZoneNS) && sameNames(d.ZoneNS, d.NS), true
}

// sameNames is whether every name of a is in b. Names are raw octets, which
// DNS compares with ASCII case folded and nothing else.
func sameNames(a, b []string) bool {
	for _, name := range a {
		if !slices.ContainsFunc(b, func(other string) bool { return equalName(name, other) }) {
			return false
		}
	}
	return true
}

func equalName(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// Serials are the steps --serial asked the nameservers of zone for the copy
// they serve with, and got an SOA from.
func (t *Trace) Serials(zone string) []*Step {
	var steps []*Step
	for step := range t.Steps() {
		if step.Aside && step.Asked.Type == "SOA" && strings.EqualFold(step.Asked.Name, zone) && step.SOA != nil {
			steps = append(steps, step)
		}
	}
	return steps
}

// Copies is how many different copies of zone, by SOA serial, the nameservers
// --serial asked serve; 0 where none was asked.
func (t *Trace) Copies(zone string) int {
	serials := map[uint32]bool{}
	for _, step := range t.Serials(zone) {
		serials[step.SOA.Serial] = true
	}
	return len(serials)
}
