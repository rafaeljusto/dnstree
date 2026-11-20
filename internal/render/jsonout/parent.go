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
	Agreement  *agreement         `json:"agreement,omitempty"`
}

// agreement is whether every nameserver serves the same request (RFC 9975).
type agreement struct {
	State   string          `json:"state"`
	Reason  string          `json:"reason,omitempty"`
	Servers []serverRequest `json:"servers"`
}

type serverRequest struct {
	Server *server `json:"server,omitempty"`
	State  string  `json:"state"`
	Asks   string  `json:"asks,omitempty"`
	Reason string  `json:"reason,omitempty"`
}

type delegationChange struct {
	Add  bool   `json:"add"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data,omitempty"`
}

type dsync struct {
	State     string          `json:"state"`
	Reason    string          `json:"reason,omitempty"`
	Parent    string          `json:"parent"`
	Name      string          `json:"name,omitempty"`
	Lookups   []lookup        `json:"lookups,omitempty"`
	Endpoints []dsyncEndpoint `json:"endpoints,omitempty"`
}

type dsyncEndpoint struct {
	Type    string   `json:"type"`
	Scheme  string   `json:"scheme"`
	Port    uint16   `json:"port"`
	Target  string   `json:"target"`
	Ignored string   `json:"ignored,omitempty"`
	IPv4    *lookup  `json:"ipv4,omitempty"`
	IPv6    *lookup  `json:"ipv6,omitempty"`
	Addrs   []string `json:"addrs,omitempty"`
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
	to.Agreement = convertAgreement(from.Agreement)
	return to
}

func convertAgreement(from *trace.Agreement) *agreement {
	if from == nil {
		return nil
	}
	to := &agreement{State: string(from.State), Reason: from.Reason, Servers: []serverRequest{}}
	for _, each := range from.Servers {
		to.Servers = append(to.Servers, serverRequest{Server: convertServer(each.Server), State: string(each.State),
			Asks: each.Asks, Reason: each.Reason})
	}
	return to
}

func readAgreement(from *agreement) (*trace.Agreement, error) {
	if from == nil {
		return nil, nil
	}
	state := trace.AgreementState(from.State)
	switch state {
	case trace.AgreementSame, trace.AgreementDiffer, trace.AgreementPartial:
	default:
		return nil, fmt.Errorf("%q is not what the nameservers' requests can come to", from.State)
	}
	to := &trace.Agreement{State: state, Reason: from.Reason}
	for _, each := range from.Servers {
		read := trace.ServerRequestState(each.State)
		switch read {
		case trace.ServerRequestRead, trace.ServerRequestUnanswered, trace.ServerRequestBogus:
		default:
			return nil, fmt.Errorf("%q is not what one server's request can come to", each.State)
		}
		server, err := readServer(each.Server)
		if err != nil {
			return nil, err
		}
		to.Servers = append(to.Servers, trace.ServerRequest{Server: server, State: read, Asks: each.Asks, Reason: each.Reason})
	}
	return to, nil
}

func convertDSYNC(from *trace.DSYNC) *dsync {
	if from == nil {
		return nil
	}
	to := &dsync{State: string(from.State), Reason: from.Reason, Parent: from.Parent, Name: from.Name}
	for _, l := range from.Lookups {
		to.Lookups = append(to.Lookups, convertLookup(l))
	}
	for _, e := range from.Endpoints {
		each := dsyncEndpoint{Type: e.Type, Scheme: e.Scheme, Port: e.Port, Target: e.Target, Ignored: e.Ignored, Addrs: texts(e.Addrs)}
		if e.IPv4 != nil {
			each.IPv4 = new(convertLookup(*e.IPv4))
		}
		if e.IPv6 != nil {
			each.IPv6 = new(convertLookup(*e.IPv6))
		}
		to.Endpoints = append(to.Endpoints, each)
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
		return nil, fmt.Errorf("%q is not what a CSYNC can come to", from.State)
	}
	to := &trace.CSYNC{State: state, Reason: from.Reason, Serial: from.Serial, Immediate: from.Immediate,
		SOAMinimum: from.SOAMinimum, Types: from.Types, ZoneSerial: from.ZoneSerial}
	for _, change := range from.Changes {
		to.Changes = append(to.Changes, trace.DelegationChange{Add: change.Add, Type: change.Type, Name: change.Name, Data: change.Data})
	}
	agreement, err := readAgreement(from.Agreement)
	if err != nil {
		return nil, err
	}
	to.Agreement = agreement
	return to, nil
}

func readDSYNC(from *dsync) (*trace.DSYNC, error) {
	if from == nil {
		return nil, nil
	}
	state := trace.DSYNCState(from.State)
	switch state {
	case trace.DSYNCFound, trace.DSYNCNone, trace.DSYNCBogus, trace.DSYNCUnchecked:
	default:
		return nil, fmt.Errorf("%q is not what a DSYNC search can come to", from.State)
	}
	to := &trace.DSYNC{State: state, Reason: from.Reason, Parent: from.Parent, Name: from.Name}
	for _, l := range from.Lookups {
		read, err := readLookup(l)
		if err != nil {
			return nil, err
		}
		to.Lookups = append(to.Lookups, read)
	}
	for _, e := range from.Endpoints {
		each := trace.DSYNCEndpoint{Type: e.Type, Scheme: e.Scheme, Port: e.Port, Target: e.Target, Ignored: e.Ignored}
		var err error
		if each.IPv4, err = readLookupRef(e.IPv4); err != nil {
			return nil, err
		}
		if each.IPv6, err = readLookupRef(e.IPv6); err != nil {
			return nil, err
		}
		if each.Addrs, err = parseAddrs("dsync addrs", e.Addrs); err != nil {
			return nil, err
		}
		to.Endpoints = append(to.Endpoints, each)
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
		return nil, fmt.Errorf("%q is not what a bootstrap can come to", from.State)
	}
	to := &trace.Bootstrap{State: state, Reason: from.Reason}
	for _, signal := range from.Signals {
		each := trace.SignalingState(signal.State)
		switch each {
		case trace.SignalingMatched, trace.SignalingDiffers, trace.SignalingMissing, trace.SignalingUnproven,
			trace.SignalingFailed, trace.SignalingUnasked:
		default:
			return nil, fmt.Errorf("%q is not what a bootstrap signal can come to", signal.State)
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
