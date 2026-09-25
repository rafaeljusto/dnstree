// Package trace is the data model shared by the resolver and every renderer: a
// tree of steps, one per query, with no dependency on the DNS codec.
package trace

import (
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Trace is one resolution, from the root down.
type Trace struct {
	Question Question

	// Root is the zone the resolution started from. It carries no query of its
	// own: its children are the servers that were asked.
	Root *Step

	Elapsed time.Duration

	// Started is when the walk began. It is what the lifetime of a signature is
	// read against, so that a trace read back later says what it said when it
	// was made rather than what the clock says now.
	Started time.Time

	// Resolvers is the same question put to recursive servers, in the order the
	// run named them, when it asked for the comparison. A walk from the root is
	// deliberately the slow way round — it keeps no cache and takes every step
	// itself — so the time it took only means something next to the time the
	// ordinary path takes.
	//
	// More than one of them is how a question is asked from more than one
	// place at once: two resolvers that answer differently are two views of
	// the same name, and which of them a client gets depends only on which it
	// happens to use.
	Resolvers []*Resolver

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

	// Records is what it answered with, kept so that its answer can be set
	// against the one the walk found, rather than only the time it took.
	Records []RR

	// Extended is what the server said about its own answer, which is where a
	// resolver that filtered rather than resolved says so.
	Extended []ExtendedError

	// Subnet is the client subnet it echoed, when the question carried one.
	Subnet *Subnet

	// Match is how its answer stands against the walk's, empty when there was
	// nothing to compare.
	Match Match
}

// Match is how a recursive server's answer stands against the one the walk
// found for itself. The two are allowed to differ honestly: a CDN tailors its
// answer to where the question seems to come from, and the walk and the
// resolver are rarely in the same place. A difference is something to look at,
// not a verdict.
type Match string

// What the comparison came to.
const (
	MatchSame    Match = "same"
	MatchDiffers Match = "differs"
)

// ExtendedError is what a server said about its own answer, in the codes of
// RFC 8914. An rcode says what happened; this says why, and it is the only
// thing in a reply that tells an answer withheld apart from an answer that is
// not there.
type ExtendedError struct {
	Code uint16

	// Reason is the registered name of the code, empty for one this build does
	// not know. An unregistered code is still worth showing: the number and
	// whatever the server wrote beside it are what a reader has.
	Reason string

	// Text is EXTRA-TEXT, whatever the server chose to add in words, as it
	// arrived. String is what makes it fit to draw.
	Text string
}

// MaxExtraText is how much of an EXTRA-TEXT is drawn.
const MaxExtraText = 64

// Withheld reports whether the code says somebody decided this answer rather
// than served it. These are what a filtering resolver, a captive network or a
// blocklist answers with, and they are why a REFUSED is not always a server
// with no business serving the zone.
func (e ExtendedError) Withheld() bool {
	switch e.Code {
	case 4, 15, 16, 17, 18: // forged, blocked, censored, filtered, prohibited
		return true
	}
	return false
}

// String is the code as a reader wants it: the name when there is one, the
// number always, and whatever the server added.
func (e ExtendedError) String() string {
	label := strconv.FormatUint(uint64(e.Code), 10)
	if e.Reason != "" {
		label = e.Reason + " (" + label + ")"
	}
	if e.Text != "" {
		label += ": " + Printable(e.Text, MaxExtraText)
	}
	return label
}

// MaxErr is how much of an error is kept on a step.
const MaxErr = 512

// Printable escapes every byte outside printable ASCII the way record data is
// escaped, \DDD, and clips what is left. The text is the server's alone, and
// drawn raw it could move the cursor over lines already written, break a line
// of a tree in two, or put a byte above 127 in --format ascii.
func Printable(text string, limit int) string {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if b.Len() >= limit {
			b.WriteString("...")
			break
		}
		switch c := text[i]; {
		case c < ' ' || c > '~':
			fmt.Fprintf(&b, "\\%03d", c)
		case c == '\\':
			b.WriteString(`\\`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Subnet is the client subnet of RFC 7871 as a server handed it back. A server
// that answers with one has taken it into account; Scope is how much of it it
// actually used, and a zero scope means this answer is the same for everybody.
type Subnet struct {
	Prefix netip.Prefix
	Scope  uint8
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

	// KindFiltered is an answer somebody decided rather than served, as the
	// server's own extended error says. It is neither lameness nor a name that
	// is not there: the zone was never consulted.
	KindFiltered StepKind = "filtered"

	KindTimeout StepKind = "timeout"
	KindError   StepKind = "error"
	KindSkipped StepKind = "skipped" // known, never queried
)

// Step is one query and the queries it led to.
type Step struct {
	// Zone the queried server is believed to serve.
	Zone   string
	Server Server
	Proto  string // udp, tcp, dot or doh

	// Asked is the question this hop put, which is not always the question the
	// resolution set out to answer: a walk asks for the keys of a zone, the DS
	// of a cut, the NS set a zone holds of itself, the serial each of its
	// servers is on, and the address of a nameserver named somewhere else. The
	// zero value is a step that asked nothing — a server listed and never
	// queried, or a note about why the walk stopped.
	//
	// The class is the resolution's own and is not repeated here.
	Asked Question
	RTT   time.Duration

	// Size is the answer as it arrived, in bytes on the wire: what dig reports
	// as MSG SIZE. Zero where nothing answered.
	Size int

	// Limit is the most that answer could have been without being truncated:
	// the EDNS0 buffer the query advertised, or the 512 bytes a query carrying
	// no EDNS0 is answered within. It is zero over TCP, DoT and DoH, where a
	// single answer is not bounded this way, and it is what makes Size worth
	// reading: bytes alone say nothing about how close the server came to
	// running out of room.
	Limit int

	Rcode string
	Flags Flags
	Kind  StepKind

	// Records is what the server returned, when that is the point of the step.
	Records []RR

	// Notes are what it took to get the answer: a retry over TCP, a query sent
	// again without EDNS0. They belong to this hop, not to a new one.
	Notes []string

	// Extended is what the server said about its own answer, in the codes of
	// RFC 8914. One reply may carry several.
	Extended []ExtendedError

	// Subnet is the client subnet the server echoed, set only when the query
	// carried one and the server answered with it.
	Subnet *Subnet

	// SOA is what the zone said about itself when it said the answer was not
	// there. A denial carries the zone's start of authority in place of records,
	// and how long the denial may be cached is in it; an answer carries its TTL
	// on the records themselves, so this is set on a NODATA or an NXDOMAIN and
	// nowhere else.
	SOA *SOA

	// NSID is what the server called itself (RFC 5001), empty when the query
	// asked for no identifier or the server gave none. It belongs to the answer
	// rather than to the server: one anycast address is many machines, and
	// which of them answered is the whole of what this says.
	NSID string

	// Minimised marks a hop that asked for less of the name than the walk was
	// after, to find where the next zone cut is (RFC 9156). What it came back
	// with is about that shorter name, so it is never the resolution's answer.
	Minimised bool

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

// tightMargin is how little room left counts as none: about what one more
// address record takes once the name is compressed. A referral with this much
// of its buffer left cannot take another nameserver without being cut.
const tightMargin = 64

// Tight reports whether the answer very nearly did not fit. One more record —
// an address added to the zone, a signature that grew with a key roll — and the
// answer is truncated, which costs every resolver asking for it a second round
// trip over TCP, and costs the ones that cannot reach the server over TCP the
// answer altogether.
//
// It is the reason to record a size at all, and it is read off the hop rather
// than worked out by whoever draws it, so the tree, the sentences and the JSON
// cannot come to disagree about which hops are close to the edge.
func (s *Step) Tight() bool {
	return s.Limit > 0 && s.Size > 0 && s.Size >= s.Limit-tightMargin
}

// SOA is as much of a zone's start of authority as it is read for: how long a
// denial from it lives, and which copy of the zone the server answering holds.
type SOA struct {
	// Serial is the version of the zone the server is serving. Two nameservers
	// of one zone that answer with different serials are answering from
	// different copies of it, which is what a secondary that has fallen behind
	// looks like from outside.
	Serial uint32

	// TTL is the TTL on the SOA record itself, and Minimum the last field of
	// its rdata. A denial lives for the shorter of the two (RFC 2308). Both are
	// kept: which of them wins is a reading, and the trace records what the
	// zone said rather than what somebody made of it.
	TTL     uint32
	Minimum uint32
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

	// Service is what an HTTPS or SVCB record offers, decoded. Nil for every
	// other type.
	Service *Service
}

// Service is the parameters of an HTTPS or SVCB record. Data carries them as
// text already; this is the part worth acting on, which is ECH: a client that
// finds a configuration here encrypts the name it is about to ask for, and
// that is worth something only if the record reached it unforged.
type Service struct {
	Priority uint16
	Target   string
	ALPN     []string

	// ECH reports whether the record publishes an encrypted client hello
	// configuration.
	ECH bool
}

// Delegation is the zone cut a referral pointed at.
type Delegation struct {
	Zone string

	// TTL is how long the parent lets its referral be cached, in seconds. It is
	// what a resolver goes on using these nameservers for after they have been
	// changed, which is not the same as the TTL on the answer below them and is
	// usually a great deal longer.
	TTL uint32

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
	State  DNSSECState
	Reason string

	// Zone is the zone the verdict is about, which is not always the zone of
	// the step it is drawn on: a cut is judged from above, so a referral holds
	// the verdict of the zone it points at.
	Zone string

	KeyTags   []uint16
	Algorithm string // the signing algorithm, e.g. ECDSAP256SHA256
	Digest    string // the DS digest type, e.g. SHA256

	// Signatures are the lifetimes of the signatures this verdict rests on,
	// set only on a secure one: the keys of the zone, the DS its parent signed,
	// the records that answered. A zone that stops being re-signed goes on
	// validating until the first of them runs out, and then fails all at once.
	Signatures []Lifetime
}

// Lifetime is how long one signature was made to last.
type Lifetime struct {
	Inception  time.Time
	Expiration time.Time
}

// staleShare is the part of a signature's life that, left, marks it stale. A
// signer re-signs with between a quarter and a half of a signature's life still
// ahead of it, so one with less than a fifth left has a signer that stopped.
// An absolute margin would not do: an online signer hands out signatures that
// last a day, fresh every time.
const staleShare = 5

// Left is how long the first of the signatures under a verdict had to run when
// the walk was made, and false where that is not known: no signature held, or
// the trace does not say when it was made.
func (t *Trace) Left(status *DNSSECStatus) (time.Duration, bool) {
	if t == nil || status == nil || len(status.Signatures) == 0 || t.Started.IsZero() {
		return 0, false
	}
	left := status.Signatures[0].Expiration.Sub(t.Started)
	for _, signature := range status.Signatures[1:] {
		left = min(left, signature.Expiration.Sub(t.Started))
	}
	return left, true
}

// Expiring is how long is left of the stalest signature under a verdict, and
// whether it is stale at all: in the last fifth of the life it was made for,
// when the walk was made.
func (t *Trace) Expiring(status *DNSSECStatus) (time.Duration, bool) {
	if t == nil || status == nil || t.Started.IsZero() {
		return 0, false
	}
	var (
		left  time.Duration
		stale bool
	)
	for _, signature := range status.Signatures {
		remaining := signature.Expiration.Sub(t.Started)
		if remaining*staleShare >= signature.Expiration.Sub(signature.Inception) {
			continue
		}
		if !stale || remaining < left {
			left, stale = remaining, true
		}
	}
	return left, stale
}

// Soonest is the step whose signatures run out first, nil where none were
// checked. A chain is as good as its weakest link, and every link of it is
// re-signed on its own schedule. The asides are read too, since a cut crossed
// without a referral is checked on one.
func (t *Trace) Soonest() *Step {
	var (
		soonest *Step
		first   time.Duration
	)
	for step := range t.Steps() {
		left, ok := t.Left(step.DNSSEC)
		if ok && (soonest == nil || left < first) {
			soonest, first = step, left
		}
	}
	return soonest
}

// Stale is the step carrying the stalest signature of the walk, nil where none
// is in the last fifth of its life.
func (t *Trace) Stale() *Step {
	var (
		stalest *Step
		first   time.Duration
	)
	for step := range t.Steps() {
		left, ok := t.Expiring(step.DNSSEC)
		if ok && (stalest == nil || left < first) {
			stalest, first = step, left
		}
	}
	return stalest
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

// Mainline walks the steps the resolution itself is made of, parents before
// children, leaving the asides out: the address of a nameserver looked up on
// the way is work the walk did, not where it got to.
func (t *Trace) Mainline() iter.Seq[*Step] {
	return func(yield func(*Step) bool) {
		if t.Root != nil {
			mainline(t.Root, yield)
		}
	}
}

func mainline(step *Step, yield func(*Step) bool) bool {
	if step.Aside {
		return true
	}
	if !yield(step) {
		return false
	}
	for _, child := range step.Children {
		if !mainline(child, yield) {
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
		if !step.Minimised {
			found = step
		}
	}
	for _, child := range step.Children {
		if deeper := result(child); deeper != nil {
			found = deeper
		}
	}
	return found
}

// Answers is the rdata of the records that answer a question of this type,
// sorted and deduplicated. Two answers to the same question can be held
// against each other this way without the order counting: a nameserver is free
// to rotate an RRset between one question and the next, and an alias chain
// reaches the same records under a different name.
func Answers(records []RR, qtype string) []string {
	var data []string
	for _, record := range records {
		if strings.EqualFold(record.Type, qtype) {
			data = append(data, record.Data)
		}
	}
	slices.Sort(data)
	return slices.Compact(data)
}

// TTL is how long a cache may keep the records that answer a question of this
// type: the shortest of them where they disagree, which is the one every copy
// of the set has run out by.
func TTL(records []RR, qtype string) uint32 {
	var shortest uint32
	for _, record := range records {
		if !strings.EqualFold(record.Type, qtype) {
			continue
		}
		if shortest == 0 || record.TTL < shortest {
			shortest = record.TTL
		}
	}
	return shortest
}

// Trust is the step carrying the verdict the answer rests on: the one recorded
// where the walk ended, or the last verdict it reached where it ended without
// an answer. It is nil for a walk that followed no chain of trust.
//
// The step is returned rather than the verdict alone because a verdict names
// the zone it is about, which is not the zone of the step it sits on: a cut is
// judged from above, so a referral carries the verdict of the zone it points
// at, and only the step has both.
func (t *Trace) Trust() *Step {
	if result := t.Result(); result != nil && result.DNSSEC != nil {
		return result
	}

	var last *Step
	for step := range t.Mainline() {
		if step.DNSSEC != nil {
			last = step
		}
	}
	return last
}

// Filtered is a hop where somebody decided the answer rather than serving it,
// or nil where nothing did. It is not a [Trace.Result]: a walk that ends here
// has not been answered, it has been turned away, and the two are worth saying
// differently.
func (t *Trace) Filtered() *Step {
	for step := range t.Steps() {
		if step.Kind == KindFiltered {
			return step
		}
	}
	return nil
}
