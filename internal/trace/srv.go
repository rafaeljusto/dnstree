package trace

import (
	"net/netip"
	"slices"
	"strings"
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

	// TLSA is the lookup of its TLSA set at _PORT._tcp.NAME (RFC 7673 3.3),
	// nil where --tlsa did not ask, and DANE and Why what a client that checks
	// DANE makes of it. DANE is empty where --tlsa did not ask.
	TLSA    *Lookup
	Records []TLSARecord
	DANE    DANEState
	Why     string

	// Presented is what each proven address showed --tlsa, nil where it
	// connected to none.
	Presented []Presented
}

// Proven are the addresses of the target whose lookup DNSSEC proved secure,
// the only ones a client that checks DANE connects to (RFC 7673 3.2).
func (t SRVTarget) Proven() []netip.Addr {
	var proven []netip.Addr
	for _, addr := range t.Addrs {
		// An IPv4-mapped address came from the AAAA set, and only its
		// lookup proves it.
		lookup := t.IPv6
		if addr.Is4() {
			lookup = t.IPv4
		}
		if lookup != nil && lookup.DNSSEC != nil && lookup.DNSSEC.State == Secure {
			proven = append(proven, addr)
		}
	}
	return proven
}

// Service is the service label of the name (RFC 2782), lowercased, and empty
// where the name has not the shape of _service._proto.domain.
func (s *SRV) Service() string { service, _, _ := s.split(); return service }

// Proto is the protocol label of the name, lowercased, such as _tcp.
func (s *SRV) Proto() string { _, proto, _ := s.split(); return proto }

// Domain is the service domain: the name with its service and protocol
// labels taken off (RFC 7673 4.1).
func (s *SRV) Domain() string { _, _, domain := s.split(); return domain }

// split cuts the name in its three parts. The two labels hold no dot.
func (s *SRV) split() (service, proto, domain string) {
	parts := strings.SplitN(s.Name, ".", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") || parts[2] == "" {
		return "", "", ""
	}
	return strings.ToLower(parts[0]), strings.ToLower(parts[1]), parts[2]
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
		target.TLSA, target.Why = target.TLSA.shownRef(), Shown(target.Why)
		target.DANE = DANEState(Shown(string(target.DANE)))
		target.Records, target.Presented = shownTLSA(target.Records), shownPresented(target.Presented)
	}
	return &shown
}
