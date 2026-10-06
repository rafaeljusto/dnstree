package trace

import (
	"slices"
	"strings"
	"time"
)

// Registration is what the registry of a domain says about it over RDAP
// (RFC 9083), held against what the zone above the domain hands out. A domain
// whose registration lapses drops out of its TLD everywhere at once, and the
// registry knew for weeks.
type Registration struct {
	// Domain is the name the registry was asked about: the zone the walk was
	// delegated to below the TLD, or the TLD and one label of the name where
	// nothing delegated it.
	Domain string

	// Server is the RDAP service that answered for the TLD, as IANA's
	// bootstrap file names it.
	Server string

	State RegistrationState

	// Why is what kept the registry from saying more, empty where it answered.
	Why string

	// Registered and Expires are the events the registry publishes, zero where
	// it publishes none.
	Registered time.Time
	Expires    time.Time

	// Status is the registry's statuses (RFC 8056), lowercase and in the
	// order it gave them.
	Status []string

	// NS are the nameservers the registry holds, and DS the key tags of the
	// DS records it holds. Signed is whether it says the delegation is signed.
	NS     []string
	DS     []uint16
	Signed bool

	// Parent is the zone whose referral the registry was held against, empty
	// where the walk was handed none.
	Parent string

	// NSOnlyRegistry are nameservers the registry holds and the parent did
	// not hand out, and NSOnlyParent the other way round.
	NSOnlyRegistry []string
	NSOnlyParent   []string

	// DSChecked is whether the parent's DS were there to hold the registry's
	// against, which takes --dnssec. DSOnlyRegistry and DSOnlyParent are the
	// key tags either side alone has; a signed delegation whose DS the chain
	// did not reach is compared by whether there are any.
	DSChecked      bool
	DSOnlyRegistry []uint16
	DSOnlyParent   []uint16
	DSDiffer       bool
}

// RegistrationState is what the registry said about the domain.
type RegistrationState string

// What the registry can say.
const (
	Registered   RegistrationState = "registered"
	Unregistered RegistrationState = "unregistered" // the registry holds no such domain
	Unpublished  RegistrationState = "unpublished"  // the TLD runs no RDAP service
	Unreached    RegistrationState = "unreached"    // the service could not be asked, or did not answer in time
)

// RegistrationSoon is how close to its expiry a registration is drawn as a
// warning.
const RegistrationSoon = 30 * 24 * time.Hour

// Lapses is how long the registration has to run from when the walk started,
// and false where the registry publishes no expiry. It is read against the
// walk rather than the clock, so a walk drawn again says what it said.
func (t *Trace) Lapses(reg *Registration) (time.Duration, bool) {
	if reg == nil || reg.Expires.IsZero() {
		return 0, false
	}
	return reg.Expires.Sub(t.Started), true
}

// Held is the first status that takes the domain out of its TLD's zone, or on
// its way out: a hold, or a lapsed registration waiting to be deleted.
func (r *Registration) Held() string {
	if r == nil {
		return ""
	}
	for _, status := range r.Status {
		switch status {
		case "client hold", "server hold", "pending delete", "redemption period", "pending restore", "inactive":
			return status
		}
	}
	return ""
}

// Agrees is whether the registry and the parent hand out the same delegation,
// as far as it was compared.
func (r *Registration) Agrees() bool {
	return len(r.NSOnlyRegistry)+len(r.NSOnlyParent)+len(r.DSOnlyRegistry)+len(r.DSOnlyParent) == 0 && !r.DSDiffer
}

// Shown is the registration with everything the registry wrote escaped.
func (r *Registration) Shown() *Registration {
	if r == nil {
		return nil
	}
	shown := *r
	shown.Domain, shown.Server, shown.Why = Shown(r.Domain), Shown(r.Server), Shown(r.Why)
	shown.Parent = Shown(r.Parent)
	shown.Status = shownAll(r.Status)
	shown.NS = shownAll(r.NS)
	shown.NSOnlyRegistry, shown.NSOnlyParent = shownAll(r.NSOnlyRegistry), shownAll(r.NSOnlyParent)
	shown.DS = slices.Clone(r.DS)
	return &shown
}

// Delegated is the zones the walk was referred to on its way to the name,
// below the TLD, shortest first, each with the step that referred it. A
// registration is one of them, nearly always the first: the zone the TLD's own
// servers delegate.
func (t *Trace) Delegated() []*Step {
	name := strings.ToLower(t.Question.Name)
	var cuts []*Step
	for step := range t.Mainline() {
		if step.Kind != KindReferral || step.Delegation == nil {
			continue
		}
		zone := strings.ToLower(step.Delegation.Zone)
		if strings.Count(zone, ".") < 2 || zone != name && !strings.HasSuffix(name, "."+zone) {
			continue
		}
		if slices.ContainsFunc(cuts, func(s *Step) bool { return strings.EqualFold(s.Delegation.Zone, zone) }) {
			continue
		}
		cuts = append(cuts, step)
	}
	slices.SortStableFunc(cuts, func(a, b *Step) int {
		return strings.Count(a.Delegation.Zone, ".") - strings.Count(b.Delegation.Zone, ".")
	})
	return cuts
}
