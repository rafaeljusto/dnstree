package trace

// Area is what part of a zone's health a check, or a warning, is about.
type Area string

// The areas --check grades, in the order it says them.
const (
	AreaAnswer       Area = "answer"       // what the walk came to
	AreaDelegation   Area = "delegation"   // the parent and the zone agree on the nameservers and their glue
	AreaConsistency  Area = "consistency"  // every nameserver serves the same copy and the same answer
	AreaDNSSEC       Area = "dnssec"       // the chain of trust, and what the zone asks its parent
	AreaServers      Area = "servers"      // every nameserver answers, with authority and room to spare
	AreaEDNS         Area = "edns"         // EDNS and DNS cookies are handled as they should be
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
