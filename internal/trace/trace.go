// Package trace is the data model shared by the resolver and every renderer: a
// tree of steps, one per query, with no dependency on the DNS codec.
package trace

import (
	"iter"
	"net/netip"
	"time"
)

// Trace is one resolution, from the root down.
type Trace struct {
	Question Question

	// Root is the zone the resolution started from. It carries no query of its
	// own: its children are the servers that were asked.
	Root *Step

	Elapsed time.Duration

	// Warnings are what the resolver could not do, in the order it found out.
	Warnings []string
}

// Question is what the resolution set out to answer.
type Question struct {
	Name  string
	Type  string
	Class string
}

// StepKind is what happened at a hop.
type StepKind string

const (
	KindZone     StepKind = "zone"     // the synthetic node a trace starts from
	KindReferral StepKind = "referral" // sent us one zone further down
	KindAnswer   StepKind = "answer"
	KindCNAME    StepKind = "cname"
	KindNoData   StepKind = "nodata" // the name exists, the type does not
	KindNXDomain StepKind = "nxdomain"
	KindLame     StepKind = "lame" // not serving the zone it was asked about
	KindTimeout  StepKind = "timeout"
	KindError    StepKind = "error"
	KindSkipped  StepKind = "skipped" // known, never queried
)

// Step is one query and the queries it led to.
type Step struct {
	// Zone the queried server is believed to serve.
	Zone   string
	Server Server
	Proto  string // udp, tcp, dot or doh
	RTT    time.Duration
	Rcode  string
	Flags  Flags
	Kind   StepKind

	// Records is what the server returned, when that is the point of the step.
	Records []RR

	// Delegation is set on a referral.
	Delegation *Delegation

	// DNSSEC is the state of the chain at this zone cut.
	DNSSEC *DNSSECStatus

	Children []*Step
	Err      string
}

// Server is the nameserver a step queried.
type Server struct {
	Name string // empty when only the address is known
	IP   netip.Addr
	Port uint16
	ASN  *ASNInfo
}

// ASNInfo is the origin AS of a server address.
type ASNInfo struct {
	Number      uint32
	Prefix      string
	CountryCode string
	Registry    string
}

// Flags are the header bits worth showing on a hop.
type Flags struct {
	AA   bool // authoritative answer
	TC   bool // truncated, the answer did not fit
	AD   bool // authenticated data
	DO   bool // DNSSEC records were asked for
	EDNS bool // the server answered with EDNS0
}

// RR is one record, flattened to text so that renderers need no codec.
type RR struct {
	Name string
	TTL  uint32
	Type string
	Data string
}

// Delegation is the zone cut a referral pointed at.
type Delegation struct {
	Zone string

	// NS are the nameserver names, in the order they were received.
	NS []string

	// Glue holds the addresses from the additional section that this zone was
	// allowed to hand out, meaning the in-bailiwick ones.
	Glue map[string][]netip.Addr

	// GlueLess are the nameservers no address was found for. In-bailiwick names
	// make the delegation broken; the others need a side resolution.
	GlueLess []string

	// DSPresent reports whether the parent signed the delegation.
	DSPresent bool
}

// DNSSECState is how far the chain of trust got.
type DNSSECState string

const (
	Secure        DNSSECState = "secure"
	Insecure      DNSSECState = "insecure"
	Bogus         DNSSECState = "bogus"
	Indeterminate DNSSECState = "indeterminate"
)

// DNSSECStatus is the chain of trust at one zone cut.
type DNSSECStatus struct {
	State   DNSSECState
	Reason  string
	KeyTags []uint16
}

// Steps walks the tree depth first, parents before children.
func (t *Trace) Steps() iter.Seq[*Step] {
	return func(yield func(*Step) bool) {
		if t.Root != nil {
			walk(t.Root, yield)
		}
	}
}

func walk(step *Step, yield func(*Step) bool) bool {
	if !yield(step) {
		return false
	}
	for _, child := range step.Children {
		if !walk(child, yield) {
			return false
		}
	}
	return true
}

// Result is the step that ended the resolution, or nil when nothing answered.
func (t *Trace) Result() *Step {
	for step := range t.Steps() {
		switch step.Kind {
		case KindAnswer, KindCNAME, KindNoData, KindNXDomain:
			return step
		}
	}
	return nil
}
