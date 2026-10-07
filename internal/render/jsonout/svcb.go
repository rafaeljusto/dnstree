package jsonout

import (
	"fmt"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// servicePath is where a client that reads the name's HTTPS or SVCB records
// connects (RFC 9460).
type servicePath struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Chain    []serviceSet    `json:"chain"`
	Targets  []serviceTarget `json:"targets,omitempty"`
	Fallback bool            `json:"fallback,omitempty"`
	None     bool            `json:"none,omitempty"`
	Stopped  string          `json:"stopped,omitempty"`
	Cut      bool            `json:"cut,omitempty"`
}

type serviceSet struct {
	Lookup  lookup   `json:"lookup"`
	Records []record `json:"records,omitempty"`
}

type serviceTarget struct {
	Name     string   `json:"name"`
	Priority uint16   `json:"priority"`
	IPv4     *lookup  `json:"ipv4,omitempty"`
	IPv6     *lookup  `json:"ipv6,omitempty"`
	Addrs    []string `json:"addrs,omitempty"`
	Hints    []string `json:"hints,omitempty"`
	Stray    []string `json:"stray,omitempty"`
}

func convertServicePath(from *trace.ServicePath) *servicePath {
	if from == nil {
		return nil
	}
	to := &servicePath{Name: from.Name, Type: from.Type, Chain: []serviceSet{},
		Fallback: from.Fallback, None: from.None, Stopped: from.Stopped, Cut: from.Cut}
	for _, set := range from.Chain {
		to.Chain = append(to.Chain, serviceSet{Lookup: convertLookup(set.Lookup), Records: convertRecords(set.Records)})
	}
	for _, target := range from.Targets {
		t := serviceTarget{Name: target.Name, Priority: target.Priority,
			Addrs: texts(target.Addrs), Hints: texts(target.Hints), Stray: texts(target.Stray)}
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

// readServicePath reads the path back. The tree draws the decoded parameters
// of every record in the chain, so a record without them is refused.
func readServicePath(from *servicePath) (*trace.ServicePath, error) {
	if from == nil {
		return nil, nil
	}
	switch {
	case from.Type != "HTTPS" && from.Type != "SVCB":
		return nil, fmt.Errorf("jsonout: a service path follows HTTPS or SVCB records, not %q", from.Type)
	case len(from.Chain) == 0:
		return nil, fmt.Errorf("jsonout: a service path starts with the set of its name, and has none")
	}
	to := &trace.ServicePath{Name: from.Name, Type: from.Type,
		Fallback: from.Fallback, None: from.None, Stopped: from.Stopped, Cut: from.Cut}
	for _, set := range from.Chain {
		read, err := readLookup(set.Lookup)
		if err != nil {
			return nil, err
		}
		for _, rr := range set.Records {
			if rr.Service == nil {
				return nil, fmt.Errorf("jsonout: the %q record of a service path at %q is not decoded", rr.Type, rr.Name)
			}
		}
		records, err := readRecords(set.Records)
		if err != nil {
			return nil, err
		}
		to.Chain = append(to.Chain, trace.ServiceSet{Lookup: read, Records: records})
	}
	for _, target := range from.Targets {
		t := trace.ServiceTarget{Name: target.Name, Priority: target.Priority}
		var err error
		if t.Addrs, err = parseAddrs(fmt.Sprintf("the addresses of %q", target.Name), target.Addrs); err != nil {
			return nil, err
		}
		if t.Hints, err = parseAddrs(fmt.Sprintf("the hints for %q", target.Name), target.Hints); err != nil {
			return nil, err
		}
		if t.Stray, err = parseAddrs(fmt.Sprintf("the stray hints for %q", target.Name), target.Stray); err != nil {
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
