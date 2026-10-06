package jsonout

import (
	"fmt"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// registration is what the registry of the domain said over RDAP, held
// against what the zone above it hands out.
type registration struct {
	Domain         string   `json:"domain"`
	Server         string   `json:"server,omitempty"`
	State          string   `json:"state"`
	Why            string   `json:"why,omitempty"`
	Registered     string   `json:"registered,omitempty"`
	Expires        string   `json:"expires,omitempty"`
	Status         []string `json:"status,omitempty"`
	NS             []string `json:"ns,omitempty"`
	DS             []uint16 `json:"ds,omitempty"`
	Signed         bool     `json:"signed,omitempty"`
	Parent         string   `json:"parent,omitempty"`
	NSOnlyRegistry []string `json:"ns_only_registry,omitempty"`
	NSOnlyParent   []string `json:"ns_only_parent,omitempty"`
	DSChecked      bool     `json:"ds_checked,omitempty"`
	DSOnlyRegistry []uint16 `json:"ds_only_registry,omitempty"`
	DSOnlyParent   []uint16 `json:"ds_only_parent,omitempty"`
	DSDiffer       bool     `json:"ds_differ,omitempty"`
}

func convertRegistration(from *trace.Registration) *registration {
	if from == nil {
		return nil
	}
	return &registration{
		Domain: from.Domain, Server: from.Server, State: string(from.State), Why: from.Why,
		Registered: timestamp(from.Registered), Expires: timestamp(from.Expires),
		Status: from.Status, NS: from.NS, DS: from.DS, Signed: from.Signed, Parent: from.Parent,
		NSOnlyRegistry: from.NSOnlyRegistry, NSOnlyParent: from.NSOnlyParent,
		DSChecked: from.DSChecked, DSOnlyRegistry: from.DSOnlyRegistry, DSOnlyParent: from.DSOnlyParent, DSDiffer: from.DSDiffer,
	}
}

// readRegistration reads the registration back. --expect registered is a
// verdict read from its state and its expiry, so the state has to be one this
// build knows and the expiry a time.
func readRegistration(from *registration) (*trace.Registration, error) {
	if from == nil {
		return nil, nil
	}
	state := trace.RegistrationState(from.State)
	switch state {
	case trace.Registered, trace.Unregistered, trace.Unpublished, trace.Unreached:
	default:
		return nil, fmt.Errorf("jsonout: %q is not what a registry can say", from.State)
	}
	registered, err := moment(from.Registered)
	if err != nil {
		return nil, fmt.Errorf("jsonout: registration: %w", err)
	}
	expires, err := moment(from.Expires)
	if err != nil {
		return nil, fmt.Errorf("jsonout: registration: %w", err)
	}
	return &trace.Registration{
		Domain: from.Domain, Server: from.Server, State: state, Why: from.Why,
		Registered: registered, Expires: expires,
		Status: from.Status, NS: from.NS, DS: from.DS, Signed: from.Signed, Parent: from.Parent,
		NSOnlyRegistry: from.NSOnlyRegistry, NSOnlyParent: from.NSOnlyParent,
		DSChecked: from.DSChecked, DSOnlyRegistry: from.DSOnlyRegistry, DSOnlyParent: from.DSOnlyParent, DSDiffer: from.DSDiffer,
	}, nil
}
