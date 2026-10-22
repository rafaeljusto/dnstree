package jsonout

import (
	"fmt"
	"net/netip"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// reverse is whether the names an address's PTR set gives point back to it.
type reverse struct {
	Addr      string        `json:"addr"`
	PTR       lookup        `json:"ptr"`
	Names     []reverseName `json:"names,omitempty"`
	Confirmed bool          `json:"confirmed"`
	Cut       bool          `json:"cut,omitempty"`
}

type reverseName struct {
	Name   string   `json:"name"`
	Lookup lookup   `json:"lookup"`
	Addrs  []string `json:"addrs,omitempty"`
	Back   bool     `json:"back"`
}

func convertReverse(from *trace.Reverse) *reverse {
	if from == nil {
		return nil
	}
	to := &reverse{Addr: from.Addr.String(), PTR: convertLookup(from.PTR), Confirmed: from.Confirmed(), Cut: from.Cut}
	for _, name := range from.Names {
		to.Names = append(to.Names, reverseName{Name: name.Name, Lookup: convertLookup(name.Lookup),
			Addrs: texts(name.Addrs), Back: name.Back(from.Addr)})
	}
	return to
}

// readReverse reads the check back. Back and Confirmed are worked out again
// from the addresses, so a file cannot claim what they do not hold.
func readReverse(from *reverse) (*trace.Reverse, error) {
	if from == nil {
		return nil, nil
	}
	addr, err := netip.ParseAddr(from.Addr)
	if err != nil {
		return nil, fmt.Errorf("jsonout: the address of the reverse check: %w", err)
	}
	to := &trace.Reverse{Addr: addr, Cut: from.Cut}
	if to.PTR, err = readLookup(from.PTR); err != nil {
		return nil, err
	}
	for _, name := range from.Names {
		read := trace.ReverseName{Name: name.Name}
		if read.Lookup, err = readLookup(name.Lookup); err != nil {
			return nil, err
		}
		if read.Addrs, err = parseAddrs(fmt.Sprintf("the addresses of %q", name.Name), name.Addrs); err != nil {
			return nil, err
		}
		to.Names = append(to.Names, read)
	}
	return to, nil
}
