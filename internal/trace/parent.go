package trace

import "slices"

// CSYNC is what a zone's CSYNC record asks its parent to copy from it (RFC
// 7477): its NS set, the addresses of the nameservers named inside it, or both.
// A parent that polls for it copies only what the zone's keys signed, so an
// unsigned one is a claim and nothing more.
type CSYNC struct {
	State CSYNCState

	// Reason says why it is not ready, where it is not.
	Reason string

	Serial uint32

	// Immediate is whether a parent may act on it without asking anyone, and
	// SOAMinimum whether it waits for the zone's serial to reach Serial.
	Immediate  bool
	SOAMinimum bool

	// Types are the types it asks to be copied, as the record names them.
	Types []string

	// ZoneSerial is the serial of the SOA the zone served beside it, set only
	// where SOAMinimum made it matter.
	ZoneSerial uint32

	// Changes are what a parent acting on it would change in the delegation,
	// worked out against the referral the walk was handed.
	Changes []DelegationChange
}

// CSYNCState is what a zone's CSYNC came to.
type CSYNCState string

// What a zone's CSYNC can come to.
const (
	CSYNCNone      CSYNCState = "none"      // the zone has no CSYNC
	CSYNCReady     CSYNCState = "ready"     // signed, and a parent that polls acts on it
	CSYNCManual    CSYNCState = "manual"    // signed, but waits for someone to approve it
	CSYNCWaiting   CSYNCState = "waiting"   // signed, but the zone's serial has not reached its own
	CSYNCUnproven  CSYNCState = "unproven"  // not signed, or its signature did not hold
	CSYNCUnchecked CSYNCState = "unchecked" // could not be fetched, or its signature was not checked
)

// DelegationChange is one record of the delegation a parent would add or
// remove.
type DelegationChange struct {
	Add  bool
	Type string // NS, A or AAAA
	Name string // the nameserver

	// Data is the address, empty for an NS.
	Data string
}

// Bootstrap is how a zone that is signed but not yet secure asks for its first
// DS (RFC 9615): the operator of each of its nameservers publishes the same CDS
// and CDNSKEY under a name of its own signed zone. A parent that bootstraps
// adds the DS only where every one of them validates and says what the zone
// does, so one missing or different signal stops it.
type Bootstrap struct {
	State BootstrapState

	// Reason says why a parent would not add the DS, where it would not.
	Reason string

	// Signals are one per nameserver the parent delegates to, in its order.
	Signals []BootstrapSignal
}

// BootstrapState is what a zone's bootstrap came to.
type BootstrapState string

// What a zone's bootstrap can come to.
const (
	BootstrapReady     BootstrapState = "ready"     // every signal validates and says what the zone does
	BootstrapRefused   BootstrapState = "refused"   // a parent that bootstraps would add no DS
	BootstrapUnchecked BootstrapState = "unchecked" // the signals could not all be looked up
)

// BootstrapSignal is the signal under one nameserver.
type BootstrapSignal struct {
	NS string

	// Name is where the signal is looked for, empty where no name can be made.
	Name string

	State  SignalingState
	Reason string

	// Requested are the key tags the signal asks for, sorted.
	Requested []uint16

	// Lookup is the lookup of the signal, nil where it was not asked.
	Lookup *Lookup
}

// SignalingState is what the signal under one nameserver came to.
type SignalingState string

// What the signal under one nameserver can come to.
const (
	SignalingMatched  SignalingState = "matched"  // validates, and says what the zone does
	SignalingDiffers  SignalingState = "differs"  // validates, and asks for something else
	SignalingMissing  SignalingState = "missing"  // the operator's zone proves there is none
	SignalingUnproven SignalingState = "unproven" // did not validate
	SignalingFailed   SignalingState = "failed"   // the lookup failed, or was cut short
	SignalingUnasked  SignalingState = "unasked"  // inside the zone, or a name too long to ask
)

func (c *CSYNC) shown() *CSYNC {
	if c == nil {
		return nil
	}
	shown := *c
	shown.Reason = Shown(c.Reason)
	shown.Types = shownAll(c.Types)
	shown.Changes = slices.Clone(c.Changes)
	for i := range shown.Changes {
		change := &shown.Changes[i]
		change.Type, change.Name, change.Data = Shown(change.Type), Shown(change.Name), Shown(change.Data)
	}
	return &shown
}

func (b *Bootstrap) shown() *Bootstrap {
	if b == nil {
		return nil
	}
	shown := *b
	shown.Reason = Shown(b.Reason)
	shown.Signals = slices.Clone(b.Signals)
	for i := range shown.Signals {
		signal := &shown.Signals[i]
		signal.NS, signal.Name, signal.Reason = Shown(signal.NS), Shown(signal.Name), Shown(signal.Reason)
		signal.Lookup = signal.Lookup.shownRef()
	}
	return &shown
}

// Request is what one zone on the walk asks its parent to change: the CSYNC
// --check-ns found, and the CDS --check-ds found where it asks for a first DS.
type Request struct {
	Zone   string
	CSYNC  *CSYNC
	Signal *Signal
}

// Requests are the requests of the zones the walk entered that ask for
// something a parent would copy or a bootstrap would decide, in the order the
// walk entered them.
func (t *Trace) Requests() []Request {
	var requests []Request
	for step := range t.Mainline() {
		var request Request
		if step.Delegation != nil && step.Delegation.CSYNC != nil && step.Delegation.CSYNC.State != CSYNCNone {
			request.Zone, request.CSYNC = step.Delegation.Zone, step.Delegation.CSYNC
		}
		if step.DNSSEC != nil && step.DNSSEC.Signal != nil && step.DNSSEC.Signal.Bootstrap != nil {
			request.Signal = step.DNSSEC.Signal
			if request.Zone == "" {
				request.Zone = step.DNSSEC.Zone
			}
			if request.Zone == "" && step.Delegation != nil {
				request.Zone = step.Delegation.Zone
			}
		}
		if request.CSYNC != nil || request.Signal != nil {
			requests = append(requests, request)
		}
	}
	return requests
}
