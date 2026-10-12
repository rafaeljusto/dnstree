package trace

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Rollover is where a change of keys in the zone the walk ended in stands
// (RFC 6781, RFC 7583): what the zone publishes, what its parent holds, and
// what the next step waits on. Every method is a fixed order of steps, and
// each step waits until the copies cached before the last one have run out.
//
// One walk sees where the keys are, not which way they are going: a DS no key
// matches is the first step of a double DS or what one leaves behind. An
// earlier walk that saw one of them first, or a CDS that asks for one, tells
// them apart; without either, both readings are kept.
type Rollover struct {
	Zone   string
	State  RolloverState
	Reason string // why it is not known, or what fits no reading, where either

	// Parent is the zone the DS came from.
	Parent string

	// Keys are the zone's keys and its parent's DS, one per key tag and
	// algorithm, sorted by tag. A revoked key has nothing left to do and is
	// not among them.
	Keys []RolloverKey

	// Readings are what the keys can mean: none for a zone that is not
	// rolling, one where a single step fits, two where the walk cannot tell
	// the new key from the old.
	Readings []Reading

	KeysTTL uint32
	DSTTL   uint32
}

// RolloverState is what a zone's keys came to.
type RolloverState string

// What a zone's keys can come to.
const (
	RolloverNone          RolloverState = "none"          // one key in use, nothing in flight
	RolloverRolling       RolloverState = "rolling"       // a rollover is under way
	RolloverUnrecognised  RolloverState = "unrecognised"  // more in flight than any one rollover has
	RolloverIndeterminate RolloverState = "indeterminate" // a DS this build cannot hold against the keys
	RolloverUnchecked     RolloverState = "unchecked"     // no chain of trust held into the zone
)

// RolloverKey is one key of the zone, or one DS of its parent, or both.
type RolloverKey struct {
	Tag       uint16
	Algorithm string

	SEP       bool // flagged as a key signing key
	Published bool // in the zone's DNSKEY set
	DS        bool // the parent holds a DS that digests to it, or names it with no key to digest
	SignsKeys bool // a signature over the DNSKEY set names it
	SignsData bool // it signed the records that answered

	// KeySeen and DSSeen are when a walk remembered by --diff first saw the
	// key and its DS, zero where none did. A first sighting is when dnstree
	// looked at one server, not when the zone changed: the other servers may
	// have picked the record up later, which a wait counted from it does not
	// see.
	KeySeen time.Time
	DSSeen  time.Time
}

// Reading is one step of one rollover the keys fit, and what comes next.
type Reading struct {
	Kind RolloverKind

	// Method is empty where the keys fit no one method: two zone signing
	// keys, neither of which signed the answer.
	Method RolloverMethod

	// New and Old are the tags of the key coming in and the key going out,
	// set where the method pairs them.
	New uint16
	Old uint16

	// Next is the step that comes next, empty where it is not worked out, and
	// Waits what it waits on. A next step with no waits is one whose wait
	// rests on more than the walk read.
	Next  Next
	Waits []Waiting
}

// RolloverKind is which key is being replaced.
type RolloverKind string

// Which key is being replaced.
const (
	KindKSK       RolloverKind = "ksk"       // the key the DS points at
	KindZSK       RolloverKind = "zsk"       // a key that signs the zone's records
	KindAlgorithm RolloverKind = "algorithm" // every key, for one of another algorithm
)

// RolloverMethod is how a key is being replaced.
type RolloverMethod string

// The methods of RFC 6781 and RFC 7583.
const (
	MethodDoubleDS        RolloverMethod = "double-ds"        // the DS first, then the key
	MethodDoubleKSK       RolloverMethod = "double-ksk"       // the key first, then the DS
	MethodDoubleRRset     RolloverMethod = "double-rrset"     // the key and its DS together
	MethodPrePublish      RolloverMethod = "pre-publish"      // a zone signing key published before it signs
	MethodDoubleSignature RolloverMethod = "double-signature" // the records signed by both
	MethodAlgorithm       RolloverMethod = "algorithm"        // every key of the old algorithm replaced
)

// Next is the step of a rollover that comes next.
type Next string

// The steps that can come next.
const (
	NextSwapKey   Next = "swap-key"   // sign the keys with New in place of Old
	NextRemoveDS  Next = "remove-ds"  // the parent removes the DS of Old
	NextSwapDS    Next = "swap-ds"    // the parent replaces the DS of Old with one of New
	NextRemoveKey Next = "remove-key" // the zone stops publishing Old
	NextRemoveOld Next = "remove-old" // the zone and the parent drop Old and its DS
	NextSignWith  Next = "sign-with"  // the zone signs its records with New
)

// Waiting is one cache the next step waits on to run out: the copies of Type
// cached before the record Tag was published.
type Waiting struct {
	Type string // DS or DNSKEY
	Tag  uint16
	TTL  uint32

	// Since is when the record was first seen, zero where no remembered walk
	// saw it, which leaves the wait counted from whenever it was published.
	Since time.Time
}

// Ready is when the wait is over, and false where it cannot be said.
func (w Waiting) Ready() (time.Time, bool) {
	if w.Since.IsZero() {
		return time.Time{}, false
	}
	return w.Since.Add(time.Duration(w.TTL) * time.Second), true
}

// Seen is when a remembered walk first saw a record of a zone, zero where none
// did. rrtype is DS or DNSKEY.
type Seen func(zone, rrtype string, tag uint16, algorithm string) time.Time

// Rolled is where a change of keys in the zone the walk ended in stands. seen
// says when each key and DS was first seen, and may be nil.
func (t *Trace) Rolled(seen Seen) *Rollover {
	zone := t.Ended()
	r := &Rollover{Zone: zone, State: RolloverUnchecked}
	if zone == "" {
		r.Reason = "the walk reached no zone"
		return r
	}
	if zone == "." {
		r.Reason = "the root's keys are rolled against the trust anchors, which are not read here"
		return r
	}

	status, parent := t.entered(zone)
	switch {
	case status == nil:
		r.Reason = "the walk followed no chain of trust into " + zone
		return r
	case status.State == Insecure:
		r.Reason = "the parent holds no DS for " + zone + ", so there is no key to roll"
		return r
	case status.State != Secure:
		r.Reason = "the chain of trust did not hold into " + zone
		return r
	case len(status.Keys) == 0:
		r.Reason = "the walk did not record the keys of " + zone
		return r
	}
	r.Parent, r.KeysTTL, r.DSTTL = parent, status.KeysTTL, status.DSTTL

	keys, state, reason := t.keysOf(zone, status, seen)
	r.Keys = keys
	if state != "" {
		r.State, r.Reason = state, reason
		return r
	}

	var algorithms []string
	for _, key := range keys {
		if !slices.Contains(algorithms, key.Algorithm) {
			algorithms = append(algorithms, key.Algorithm)
		}
	}
	if len(algorithms) > 1 {
		r.State = RolloverRolling
		r.Readings = []Reading{{Kind: KindAlgorithm, Method: MethodAlgorithm}}
		return r
	}

	var signing, data []RolloverKey
	for _, key := range keys {
		if key.SEP || key.DS {
			signing = append(signing, key)
		} else {
			data = append(data, key)
		}
	}
	switch len(signing) {
	case 0, 1:
	case 2:
		r.Readings = r.keySigning(signing[0], signing[1], status.Signal)
	default:
		r.State = RolloverUnrecognised
		r.Reason = fmt.Sprintf("%d key signing keys and DS records are in play, more than any one rollover has", len(signing))
		return r
	}
	switch {
	case len(data) == 2:
		r.Readings = append(r.Readings, r.zoneSigning(data[0], data[1])...)
	case len(data) > 2:
		// Providers keep zone signing keys standing by, and a zone signed by
		// several publishes every operator's: neither is a rollover the walk
		// can name, and neither is nothing in flight. Readings of the key
		// signing key stand, with this beside them.
		var signing int
		for _, k := range data {
			if k.SignsData {
				signing++
			}
		}
		r.Reason = fmt.Sprintf("%d zone signing keys are published and %d signed the answer: the others stand by for a rollover, or are another operator's (RFC 8901)",
			len(data), signing)
		if len(r.Readings) == 0 {
			r.State = RolloverUnrecognised
			return r
		}
	}

	r.State = RolloverNone
	if len(r.Readings) > 0 {
		r.State = RolloverRolling
	}
	return r
}

// entered is the verdict reached on entering the zone, and the zone whose DS
// it was reached with. With --all several servers refer to the zone, and the
// first verdict that recorded the keys is the one kept.
func (t *Trace) entered(zone string) (*DNSSECStatus, string) {
	var found *DNSSECStatus
	var parent string
	for step := range t.Mainline() {
		status := step.DNSSEC
		if status == nil || !strings.EqualFold(status.Zone, zone) {
			continue
		}
		if found == nil || (len(found.Keys) == 0 && len(status.Keys) > 0) {
			found = status
			if !strings.EqualFold(step.Zone, zone) {
				parent = step.Zone
			}
		}
	}
	return found, parent
}

// keysOf merges the zone's keys with its parent's DS, one per tag and
// algorithm, and says why they cannot be held against each other where they
// cannot, with the state that leaves.
func (t *Trace) keysOf(zone string, status *DNSSECStatus, seen Seen) ([]RolloverKey, RolloverState, string) {
	var keys []RolloverKey
	find := func(tag uint16, algorithm string) *RolloverKey {
		for i := range keys {
			if keys[i].Tag == tag && keys[i].Algorithm == algorithm {
				return &keys[i]
			}
		}
		keys = append(keys, RolloverKey{Tag: tag, Algorithm: algorithm})
		return &keys[len(keys)-1]
	}

	signer := t.dataSigner(zone)
	for _, key := range status.Keys {
		if key.Revoked {
			continue
		}
		k := find(key.Tag, key.Algorithm)
		k.SEP, k.Published, k.SignsKeys = key.SEP, true, key.Signs
		k.DS = k.DS || key.Pointed
		k.SignsData = signer != nil && signer.Algorithm == key.Algorithm && slices.Contains(signer.KeyTags, key.Tag)
	}

	// A DS of a digest this build cannot compute is fine beside one that
	// matched the same key; alone, which key it vouches for is not known.
	unchecked := make(map[uint16]bool)
	for _, ds := range status.DS {
		switch ds.Match {
		case DSMatched:
			find(ds.Tag, ds.Algorithm).DS = true
		case DSUnchecked:
			unchecked[ds.Tag] = true
		case DSUnmatched:
			k := find(ds.Tag, ds.Algorithm)
			if k.Published && !k.DS {
				return keys, RolloverUnrecognised, fmt.Sprintf("the DS for tag %d does not digest the key of that tag", ds.Tag)
			}
			k.DS = true
		}
	}
	for tag := range unchecked {
		if !slices.ContainsFunc(keys, func(k RolloverKey) bool { return k.Tag == tag && k.DS }) {
			return keys, RolloverIndeterminate, fmt.Sprintf("the DS for tag %d uses a digest this build cannot compute", tag)
		}
	}

	if seen != nil {
		for i := range keys {
			k := &keys[i]
			if k.Published {
				k.KeySeen = seen(zone, "DNSKEY", k.Tag, k.Algorithm)
			}
			if k.DS {
				k.DSSeen = seen(zone, "DS", k.Tag, k.Algorithm)
			}
		}
	}
	slices.SortStableFunc(keys, func(a, b RolloverKey) int {
		return cmp.Or(cmp.Compare(a.Tag, b.Tag), cmp.Compare(a.Algorithm, b.Algorithm))
	})
	return keys, "", ""
}

// dataSigner is the verdict on the records that answered, where they were
// the zone's and their signature held.
func (t *Trace) dataSigner(zone string) *DNSSECStatus {
	result := t.Result()
	if result == nil || result.DNSSEC == nil || result.DNSSEC.State != Secure ||
		!strings.EqualFold(result.DNSSEC.Zone, zone) {
		return nil
	}
	return result.DNSSEC
}

// keySigning is what two key signing keys, or a key and a DS, can mean. One of
// them is the key in use, since the chain held through it.
func (r *Rollover) keySigning(a, b RolloverKey, signal *Signal) []Reading {
	inUse, other := a, b
	if use(b) > use(a) {
		inUse, other = b, a
	}

	read := func(incoming, outgoing RolloverKey) Reading {
		reading := Reading{Kind: KindKSK, New: incoming.Tag, Old: outgoing.Tag}
		ds := Waiting{Type: "DS", Tag: incoming.Tag, TTL: r.DSTTL, Since: incoming.DSSeen}
		key := Waiting{Type: "DNSKEY", Tag: incoming.Tag, TTL: r.KeysTTL, Since: incoming.KeySeen}
		switch {
		case !other.Published && incoming.Tag == other.Tag:
			reading.Method, reading.Next, reading.Waits = MethodDoubleDS, NextSwapKey, []Waiting{ds}
		case !other.Published:
			reading.Method, reading.Next, reading.Waits = MethodDoubleDS, NextRemoveDS, []Waiting{key}
		case !other.DS && incoming.Tag == other.Tag:
			reading.Method, reading.Next, reading.Waits = MethodDoubleKSK, NextSwapDS, []Waiting{key}
		case !other.DS:
			reading.Method, reading.Next, reading.Waits = MethodDoubleKSK, NextRemoveKey, []Waiting{ds}
		case !incoming.SignsKeys:
			// Both linked, and the new one not signing yet: it has to take
			// over the key set before the old one can go.
			reading.Method, reading.Next, reading.Waits = MethodDoubleRRset, NextSwapKey, []Waiting{ds, key}
		default:
			reading.Method, reading.Next, reading.Waits = MethodDoubleRRset, NextRemoveOld, []Waiting{ds, key}
		}
		return reading
	}

	switch newer(inUse, other, signal) {
	case 1:
		return []Reading{read(inUse, other)}
	case -1:
		return []Reading{read(other, inUse)}
	}
	return []Reading{read(other, inUse), read(inUse, other)}
}

// use is how much of the chain a key carries: a DS that vouches for it, its
// key published, and the key set signed with it.
func use(k RolloverKey) int {
	switch {
	case k.Published && k.DS && k.SignsKeys:
		return 2
	case k.Published && k.DS:
		return 1
	}
	return 0
}

// zoneSigning is what two zone signing keys can mean. One that never signed
// the answer may also be the key of another operator of a zone signed by
// several (RFC 8901), which the walk cannot tell from a rollover.
func (r *Rollover) zoneSigning(a, b RolloverKey) []Reading {
	switch {
	case a.SignsData && b.SignsData:
		return []Reading{{Kind: KindZSK, Method: MethodDoubleSignature}}
	case a.SignsData == b.SignsData:
		return []Reading{{Kind: KindZSK}}
	}

	inUse, other := a, b
	if b.SignsData {
		inUse, other = b, a
	}
	incoming := Reading{Kind: KindZSK, Method: MethodPrePublish, New: other.Tag, Old: inUse.Tag, Next: NextSignWith,
		Waits: []Waiting{{Type: "DNSKEY", Tag: other.Tag, TTL: r.KeysTTL, Since: other.KeySeen}}}
	// The old key goes once the records it signed have run out of every
	// cache, which waits on the longest TTL in the zone: more than a walk
	// reads, so it is not timed.
	outgoing := Reading{Kind: KindZSK, Method: MethodPrePublish, New: inUse.Tag, Old: other.Tag, Next: NextRemoveKey}

	switch newer(inUse, other, nil) {
	case 1:
		return []Reading{outgoing}
	case -1:
		return []Reading{incoming}
	}
	return []Reading{incoming, outgoing}
}

// newer is 1 where a came after b, -1 where b came after a, and 0 where
// neither a remembered walk nor the zone's CDS says. A record seen later was
// published later; a CDS asks for the key coming in and drops the one going
// out.
func newer(a, b RolloverKey, signal *Signal) int {
	if c := later(a.KeySeen, b.KeySeen); c != 0 {
		return c
	}
	if c := later(a.DSSeen, b.DSSeen); c != 0 {
		return c
	}
	if signal == nil || signal.State == SignalUnchecked || signal.State == SignalInconsistent ||
		signal.State == SignalNone || signal.State == SignalDelete {
		return 0
	}
	wants := func(k RolloverKey) int {
		asked, held := slices.Contains(signal.Requested, k.Tag), slices.Contains(signal.Held, k.Tag)
		switch {
		case asked && !held:
			return 1
		case held && !asked:
			return -1
		}
		return 0
	}
	return cmp.Compare(wants(a), wants(b))
}

func later(a, b time.Time) int {
	if a.IsZero() || b.IsZero() {
		return 0
	}
	return a.Compare(b)
}

// Shown is the rollover with every string in it escaped.
func (r *Rollover) Shown() *Rollover {
	if r == nil {
		return nil
	}
	shown := *r
	shown.Zone, shown.Parent, shown.Reason = Shown(r.Zone), Shown(r.Parent), Shown(r.Reason)
	shown.State = RolloverState(Shown(string(r.State)))
	shown.Keys = slices.Clone(r.Keys)
	for i := range shown.Keys {
		shown.Keys[i].Algorithm = Shown(shown.Keys[i].Algorithm)
	}
	shown.Readings = slices.Clone(r.Readings)
	for i := range shown.Readings {
		reading := &shown.Readings[i]
		reading.Kind = RolloverKind(Shown(string(reading.Kind)))
		reading.Method = RolloverMethod(Shown(string(reading.Method)))
		reading.Next = Next(Shown(string(reading.Next)))
		reading.Waits = slices.Clone(reading.Waits)
		for j := range reading.Waits {
			reading.Waits[j].Type = Shown(reading.Waits[j].Type)
		}
	}
	return &shown
}
