package jsonout

import (
	"fmt"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

type csync struct {
	State      string             `json:"state"`
	Reason     string             `json:"reason,omitempty"`
	Serial     uint32             `json:"serial"`
	Immediate  bool               `json:"immediate,omitempty"`
	SOAMinimum bool               `json:"soaminimum,omitempty"`
	Types      []string           `json:"types,omitempty"`
	ZoneSerial uint32             `json:"zone_serial,omitempty"`
	Changes    []delegationChange `json:"changes,omitempty"`
}

type delegationChange struct {
	Add  bool   `json:"add"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data,omitempty"`
}

type bootstrap struct {
	State   string            `json:"state"`
	Reason  string            `json:"reason,omitempty"`
	Signals []bootstrapSignal `json:"signals,omitempty"`
}

type bootstrapSignal struct {
	NS        string   `json:"ns"`
	Name      string   `json:"name,omitempty"`
	State     string   `json:"state"`
	Reason    string   `json:"reason,omitempty"`
	Requested []uint16 `json:"requested,omitempty"`
	Lookup    *lookup  `json:"lookup,omitempty"`
}

func convertCSYNC(from *trace.CSYNC) *csync {
	if from == nil {
		return nil
	}
	to := &csync{State: string(from.State), Reason: from.Reason, Serial: from.Serial, Immediate: from.Immediate,
		SOAMinimum: from.SOAMinimum, Types: from.Types, ZoneSerial: from.ZoneSerial}
	for _, change := range from.Changes {
		to.Changes = append(to.Changes, delegationChange{Add: change.Add, Type: change.Type, Name: change.Name, Data: change.Data})
	}
	return to
}

func convertBootstrap(from *trace.Bootstrap) *bootstrap {
	if from == nil {
		return nil
	}
	to := &bootstrap{State: string(from.State), Reason: from.Reason}
	for _, signal := range from.Signals {
		s := bootstrapSignal{NS: signal.NS, Name: signal.Name, State: string(signal.State), Reason: signal.Reason,
			Requested: signal.Requested}
		if signal.Lookup != nil {
			s.Lookup = new(convertLookup(*signal.Lookup))
		}
		to.Signals = append(to.Signals, s)
	}
	return to
}

func readCSYNC(from *csync) (*trace.CSYNC, error) {
	if from == nil {
		return nil, nil
	}
	state := trace.CSYNCState(from.State)
	switch state {
	case trace.CSYNCNone, trace.CSYNCReady, trace.CSYNCManual, trace.CSYNCWaiting, trace.CSYNCUnproven, trace.CSYNCUnchecked:
	default:
		return nil, fmt.Errorf("jsonout: %q is not what a CSYNC can come to", from.State)
	}
	to := &trace.CSYNC{State: state, Reason: from.Reason, Serial: from.Serial, Immediate: from.Immediate,
		SOAMinimum: from.SOAMinimum, Types: from.Types, ZoneSerial: from.ZoneSerial}
	for _, change := range from.Changes {
		to.Changes = append(to.Changes, trace.DelegationChange{Add: change.Add, Type: change.Type, Name: change.Name, Data: change.Data})
	}
	return to, nil
}

func readBootstrap(from *bootstrap) (*trace.Bootstrap, error) {
	if from == nil {
		return nil, nil
	}
	state := trace.BootstrapState(from.State)
	switch state {
	case trace.BootstrapReady, trace.BootstrapRefused, trace.BootstrapUnchecked:
	default:
		return nil, fmt.Errorf("jsonout: %q is not what a bootstrap can come to", from.State)
	}
	to := &trace.Bootstrap{State: state, Reason: from.Reason}
	for _, signal := range from.Signals {
		each := trace.SignalingState(signal.State)
		switch each {
		case trace.SignalingMatched, trace.SignalingDiffers, trace.SignalingMissing, trace.SignalingUnproven,
			trace.SignalingFailed, trace.SignalingUnasked:
		default:
			return nil, fmt.Errorf("jsonout: %q is not what a bootstrap signal can come to", signal.State)
		}
		lookup, err := readLookupRef(signal.Lookup)
		if err != nil {
			return nil, err
		}
		to.Signals = append(to.Signals, trace.BootstrapSignal{NS: signal.NS, Name: signal.Name, State: each,
			Reason: signal.Reason, Requested: signal.Requested, Lookup: lookup})
	}
	return to, nil
}
