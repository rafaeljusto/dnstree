package fakens

import (
	"encoding/base32"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Denial is how a signed zone proves that a child of it has no DS, which is
// what makes an insecure delegation something the parent said rather than
// something that merely is not there.
type Denial string

// The shapes a parent proves it in. The zero value is what the large TLDs do.
const (
	// DenialNSEC3OptOut covers the delegation with an NSEC3 carrying the
	// opt-out flag, which is how com. and net. sign their unsigned children.
	DenialNSEC3OptOut Denial = ""

	// DenialNSEC3 names the delegation with an NSEC3 of its own, saying it is
	// a delegation with no DS.
	DenialNSEC3 Denial = "nsec3"

	// DenialNSEC does the same without hashing, the way a small signed zone does.
	DenialNSEC Denial = "nsec"
)

// The NSEC3 parameters the fake zones sign with, the ones RFC 5155 uses in its
// own examples.
const (
	nsec3Salt       = "aabbccdd"
	nsec3Iterations = 12
	nsec3HashLength = 20 // SHA-1
)

var base32hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// denial is the parent's signed word that child has no DS. It is added to a
// referral, and to a DS query the zone answers with nothing, exactly where a
// real signed parent puts it.
func (s *Server) denial(child string) []dns.RR {
	if s.signer == nil || s.behaviour.NoDenial {
		return nil
	}

	header := func(name string) dns.Header {
		return dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}
	}
	// A delegation is an NS and nothing else of the parent's: no DS, which is
	// the point, and no SOA, which would make it the child's own apex.
	bitmap := []uint16{dns.TypeNS, dns.TypeRRSIG}

	if s.denialKind == DenialNSEC {
		nsec := &dns.NSEC{Hdr: header(child)}
		nsec.NextDomain = s.origin
		nsec.TypeBitMap = bitmap
		return []dns.RR{nsec}
	}

	hashed := dnsutil.NSEC3Name(dnsutil.Canonical(child), nsec3Salt, nsec3Iterations)
	raw, err := base32hex.DecodeString(hashed)
	if err != nil {
		return nil
	}

	nsec3 := &dns.NSEC3{}
	nsec3.Hash, nsec3.Iterations = 1, nsec3Iterations
	nsec3.Salt, nsec3.SaltLength = nsec3Salt, uint8(len(nsec3Salt)/2)
	nsec3.HashLength = nsec3HashLength
	nsec3.TypeBitMap = bitmap

	switch s.denialKind {
	case DenialNSEC3:
		// Named outright: the hash of the delegation is the owner.
		nsec3.Hdr = header(s.under(base32hex.EncodeToString(raw)))
		nsec3.NextDomain = base32hex.EncodeToString(step(raw, +1))
	default:
		// Opt-out: the parent never said whether this one is signed, only that
		// the range the delegation falls in holds nothing it vouches for.
		nsec3.Flags = 1
		nsec3.Hdr = header(s.under(base32hex.EncodeToString(step(raw, -1))))
		nsec3.NextDomain = base32hex.EncodeToString(step(raw, +1))
	}
	return []dns.RR{nsec3}
}

// under is one label inside the zone. The root is the reason this is not a
// concatenation: its origin is already the separator.
func (s *Server) under(label string) string {
	return label + "." + strings.TrimPrefix(s.origin, ".")
}

// step is the hash next to this one, which is what it takes to build a range
// that holds exactly the name in the middle of it.
func step(hash []byte, by int) []byte {
	out := append([]byte(nil), hash...)
	for i := len(out) - 1; i >= 0; i-- {
		if by > 0 {
			out[i]++
			if out[i] != 0 {
				break
			}
			continue
		}
		if out[i] != 0 {
			out[i]--
			break
		}
		out[i] = 0xff
	}
	return out
}
