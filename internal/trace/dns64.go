package trace

import "net/netip"

// DNS64Lengths are the prefix lengths an IPv4 address can be put under in an
// IPv6 one (RFC 6052 section 2.2), longest first.
var DNS64Lengths = []int{96, 64, 56, 48, 40, 32}

// Embedded is the IPv4 address an IPv6 one carries under a prefix of the given
// length. Below 96 bits the address skips the octet at bits 64 to 71, which
// has to be zero (RFC 6052 section 2.2).
func Embedded(addr netip.Addr, bits int) (netip.Addr, bool) {
	if !addr.Is6() || addr.Is4In6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	if bits < 96 && b[8] != 0 {
		return netip.Addr{}, false
	}
	var at []int
	switch bits {
	case 32:
		at = []int{4, 5, 6, 7}
	case 40:
		at = []int{5, 6, 7, 9}
	case 48:
		at = []int{6, 7, 9, 10}
	case 56:
		at = []int{7, 9, 10, 11}
	case 64:
		at = []int{9, 10, 11, 12}
	case 96:
		at = []int{12, 13, 14, 15}
	default:
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{b[at[0]], b[at[1]], b[at[2]], b[at[3]]}), true
}

// Synthesised is the IPv4 address a made-up AAAA was made from, where it sits
// under one of prefixes.
func Synthesised(addr netip.Addr, prefixes []netip.Prefix) (netip.Addr, bool) {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return Embedded(addr, prefix.Bits())
		}
	}
	return netip.Addr{}, false
}
