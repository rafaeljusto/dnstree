package trace

import (
	"net/netip"
	"slices"
)

// SRV is where a client that asks for the name's SRV records (RFC 2782) is
// sent: the servers the set names, with their addresses. Nothing is connected
// to, so a target that resolves is not one that serves.
type SRV struct {
	Name   string
	Lookup Lookup

	// Targets are the records of the set, by priority, then by target.
	Targets []SRVTarget

	// None is a set whose one record has a target of ".", which says the
	// service is not offered at the name (RFC 2782).
	None bool

	// Stopped is why the targets were not followed: a lookup that failed or
	// did not validate, or a budget of the run.
	Stopped string

	// Cut is a check a budget cut short, and Left the targets it left without
	// a lookup.
	Cut  bool
	Left int
}

// SRVTarget is one record of the set, and what its target resolves to.
type SRVTarget struct {
	Name     string
	Priority uint16
	Weight   uint16
	Port     uint16

	// IPv4 and IPv6 are the lookups of its A and AAAA sets, nil where they
	// were not asked.
	IPv4 *Lookup
	IPv6 *Lookup

	Addrs []netip.Addr

	// Unreachable are those of its addresses nobody on the internet can reach
	// it at.
	Unreachable []netip.Addr
}

// Alias is the name the target is an alias for, which RFC 2782 says it must
// not be, and empty where it is none.
func (t SRVTarget) Alias() string {
	for _, lookup := range []*Lookup{t.IPv4, t.IPv6} {
		if lookup != nil && lookup.Alias != "" {
			return lookup.Alias
		}
	}
	return ""
}

// Nowhere is a target whose every address lookup was answered, with none.
func (t SRVTarget) Nowhere() bool {
	return nowhere(t.Addrs, t.IPv4, t.IPv6)
}

// Failed is why the address lookups of a target failed, where every one asked
// did, and empty otherwise.
func (t SRVTarget) Failed() string {
	return failed(t.IPv4, t.IPv6)
}

// Shown is the check with every name and text the zones wrote escaped.
func (s *SRV) Shown() *SRV {
	if s == nil {
		return nil
	}
	shown := *s
	shown.Name, shown.Stopped = Shown(s.Name), Shown(s.Stopped)
	shown.Lookup = s.Lookup.shown()
	shown.Targets = slices.Clone(s.Targets)
	for i := range shown.Targets {
		target := &shown.Targets[i]
		target.Name = Shown(target.Name)
		target.IPv4, target.IPv6 = target.IPv4.shownRef(), target.IPv6.shownRef()
	}
	return &shown
}
