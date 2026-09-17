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

	// Resolver is the same question put to a recursive server, when the run
	// asked for the comparison. A walk from the root is deliberately the slow
	// way round — it keeps no cache and takes every step itself — so the time
	// it took only means something next to the time the ordinary path takes.
	Resolver *Resolver

	// Warnings are what the resolver could not do, in the order it found out.
	Warnings []string
}

// Resolver is what one recursive server made of the question. It is metadata,
// like the origin AS lookups: nothing about the walk depends on it, and a
// server that will not answer leaves Err rather than failing the resolution.
type Resolver struct {
	Server  Server
	Elapsed time.Duration
	Rcode   string
	Err     string
}

// Question is what the resolution set out to answer.
type Question struct {
	Name  string
	Type  string
	Class string
}

// StepKind is what happened at a hop.
type StepKind string

// What a hop turned out to be.
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

	// Notes are what it took to get the answer: a retry over TCP, a query sent
	// again without EDNS0. They belong to this hop, not to a new one.
	Notes []string

	// Aside marks work that answers a different question: the address of a
	// nameserver, or the NS set of a zone. The resolution's own answer is never
	// inside one. Following an alias is not an aside: the target is what the
	// question meant all along.
	Aside bool

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

	// Port is where the server is asked. Zero leaves the choice to the
	// transport, which is the ordinary case: glue carries addresses and never
	// ports. A step of a finished trace always names the port it used.
	Port uint16
	ASN  *ASNInfo
}

// ASNInfo is the origin AS of a server address. A prefix announced by more
// than one AS keeps the first of them.
type ASNInfo struct {
	Number      uint32
	Prefix      string
	CountryCode string
	Registry    string
	Allocated   string // the date the prefix was handed out
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

	// GlueLess are nameservers inside the delegated zone that came with no
	// glue. Nothing can resolve them, so the delegation is broken.
	GlueLess []string

	// OutOfBailiwick are nameservers named outside the delegated zone that came
	// with no address the parent was entitled to give. They are found with a
	// walk of their own instead.
	OutOfBailiwick []string

	// DSPresent reports whether the parent signed the delegation.
	DSPresent bool
}

// DNSSECState is how far the chain of trust got.
type DNSSECState string

// How far the chain of trust got.
const (
	Secure        DNSSECState = "secure"
	Insecure      DNSSECState = "insecure"
	Bogus         DNSSECState = "bogus"
	Indeterminate DNSSECState = "indeterminate"
)

// DNSSECStatus is the chain of trust at one zone cut. The algorithm and the
// digest are always carried, so that an algorithm nothing here supports reads
// differently from a signature that genuinely does not verify.
type DNSSECStatus struct {
	State     DNSSECState
	Reason    string
	KeyTags   []uint16
	Algorithm string // the signing algorithm, e.g. ECDSAP256SHA256
	Digest    string // the DS digest type, e.g. SHA256
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
// It is the deepest one that is not an aside: an alias is an answer, but the
// walk it starts carries the answer that was actually asked for.
func (t *Trace) Result() *Step {
	if t.Root == nil {
		return nil
	}
	return result(t.Root)
}

func result(step *Step) *Step {
	if step.Aside {
		return nil
	}

	var found *Step
	switch step.Kind {
	case KindAnswer, KindCNAME, KindNoData, KindNXDomain:
		found = step
	}
	for _, child := range step.Children {
		if deeper := result(child); deeper != nil {
			found = deeper
		}
	}
	return found
}
