package jsonout

import (
	"fmt"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// srv is where the name's SRV records send a client (RFC 2782).
type srv struct {
	Name    string      `json:"name"`
	Lookup  lookup      `json:"lookup"`
	Targets []srvTarget `json:"targets,omitempty"`
	None    bool        `json:"none,omitempty"`
	Stopped string      `json:"stopped,omitempty"`
	Cut     bool        `json:"cut,omitempty"`
	Left    int         `json:"left,omitempty"`
}

type srvTarget struct {
	Name        string   `json:"name"`
	Priority    uint16   `json:"priority"`
	Weight      uint16   `json:"weight"`
	Port        uint16   `json:"port"`
	IPv4        *lookup  `json:"ipv4,omitempty"`
	IPv6        *lookup  `json:"ipv6,omitempty"`
	Addrs       []string `json:"addrs,omitempty"`
	Unreachable []string `json:"unreachable,omitempty"`
}

func convertSRV(from *trace.SRV) *srv {
	if from == nil {
		return nil
	}
	to := &srv{Name: from.Name, Lookup: convertLookup(from.Lookup),
		None: from.None, Stopped: from.Stopped, Cut: from.Cut, Left: from.Left}
	for _, target := range from.Targets {
		t := srvTarget{Name: target.Name, Priority: target.Priority, Weight: target.Weight, Port: target.Port,
			Addrs: texts(target.Addrs), Unreachable: texts(target.Unreachable)}
		if target.IPv4 != nil {
			t.IPv4 = new(convertLookup(*target.IPv4))
		}
		if target.IPv6 != nil {
			t.IPv6 = new(convertLookup(*target.IPv6))
		}
		to.Targets = append(to.Targets, t)
	}
	return to
}

func readSRV(from *srv) (*trace.SRV, error) {
	if from == nil {
		return nil, nil
	}
	if from.Left < 0 {
		return nil, fmt.Errorf("jsonout: the SRV check of %q left %d targets", from.Name, from.Left)
	}
	read, err := readLookup(from.Lookup)
	if err != nil {
		return nil, err
	}
	to := &trace.SRV{Name: from.Name, Lookup: read, None: from.None, Stopped: from.Stopped, Cut: from.Cut, Left: from.Left}
	for _, target := range from.Targets {
		t := trace.SRVTarget{Name: target.Name, Priority: target.Priority, Weight: target.Weight, Port: target.Port}
		if t.Addrs, err = parseAddrs(fmt.Sprintf("the addresses of %q", target.Name), target.Addrs); err != nil {
			return nil, err
		}
		if t.Unreachable, err = parseAddrs(fmt.Sprintf("the unreachable addresses of %q", target.Name), target.Unreachable); err != nil {
			return nil, err
		}
		if t.IPv4, err = readLookupRef(target.IPv4); err != nil {
			return nil, err
		}
		if t.IPv6, err = readLookupRef(target.IPv6); err != nil {
			return nil, err
		}
		to.Targets = append(to.Targets, t)
	}
	return to, nil
}
