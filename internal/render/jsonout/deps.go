package jsonout

import (
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// dependencies are the zones the name depends on.
type dependencies struct {
	Name       string             `json:"name"`
	Zones      []dependencyZone   `json:"zones"`
	Unresolved []unresolvedServer `json:"unresolved,omitempty"`
	Stopped    string             `json:"stopped,omitempty"`
}

type dependencyZone struct {
	Zone   string   `json:"zone"`
	NS     []string `json:"ns,omitempty"`
	Via    string   `json:"via,omitempty"`
	For    string   `json:"for,omitempty"`
	DNSSEC *dnssec  `json:"dnssec,omitempty"`
}

type unresolvedServer struct {
	Name  string `json:"name"`
	For   string `json:"for"`
	Error string `json:"error"`
}

func convertDependencies(from *trace.Dependencies) *dependencies {
	if from == nil {
		return nil
	}
	to := &dependencies{Name: from.Name, Zones: []dependencyZone{}, Stopped: from.Stopped}
	for _, zone := range from.Zones {
		to.Zones = append(to.Zones, dependencyZone{Zone: zone.Zone, NS: zone.NS, Via: zone.Via, For: zone.For,
			DNSSEC: convertDNSSEC(zone.DNSSEC)})
	}
	for _, ns := range from.Unresolved {
		to.Unresolved = append(to.Unresolved, unresolvedServer{Name: ns.Name, For: ns.For, Error: ns.Err})
	}
	return to
}

func readDependencies(from *dependencies) (*trace.Dependencies, error) {
	if from == nil {
		return nil, nil
	}
	to := &trace.Dependencies{Name: from.Name, Stopped: from.Stopped}
	for _, zone := range from.Zones {
		status, err := readDNSSEC(zone.DNSSEC)
		if err != nil {
			return nil, err
		}
		to.Zones = append(to.Zones, trace.DependencyZone{Zone: zone.Zone, NS: zone.NS, Via: zone.Via, For: zone.For,
			DNSSEC: status})
	}
	for _, ns := range from.Unresolved {
		to.Unresolved = append(to.Unresolved, trace.UnresolvedNS{Name: ns.Name, For: ns.For, Err: ns.Error})
	}
	return to, nil
}
