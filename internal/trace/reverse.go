package trace

import (
	"net/netip"
	"slices"
)

// Reverse is whether the names an address's PTR set gives point back to it:
// forward-confirmed reverse DNS, which mail receivers judge a sender by. Both
// owners agreeing says nothing more about the server than that.
type Reverse struct {
	Addr netip.Addr

	// PTR is the lookup the walk made, whose Alias is where a delegation
	// below a /24 (RFC 2317) sent it.
	PTR Lookup

	// Names are the names the PTR set gives, each once, in the order of the
	// set, with the lookup of its addresses in the family of Addr. None where
	// PTR was not answered.
	Names []ReverseName

	// Cut is a check a budget of the run stopped before every name was
	// looked up.
	Cut bool
}

// ReverseName is one name the PTR set gives, and the addresses it has.
type ReverseName struct {
	Name   string
	Lookup Lookup
	Addrs  []netip.Addr
}

// Back reports whether the name holds addr, by a lookup that was answered.
func (n ReverseName) Back(addr netip.Addr) bool {
	return n.Lookup.Answered() && slices.Contains(n.Addrs, addr)
}

// Confirmed reports whether a name the PTR set gives points back.
func (r *Reverse) Confirmed() bool {
	return slices.ContainsFunc(r.Names, func(n ReverseName) bool { return n.Back(r.Addr) })
}

// Shown is the check with every name the zones wrote escaped.
func (r *Reverse) Shown() *Reverse {
	if r == nil {
		return nil
	}
	shown := *r
	shown.PTR = r.PTR.shown()
	shown.Names = slices.Clone(r.Names)
	for i := range shown.Names {
		name := &shown.Names[i]
		name.Name, name.Lookup = Shown(name.Name), name.Lookup.shown()
	}
	return &shown
}
