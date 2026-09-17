package dnssec

import (
	"encoding/base32"
	"fmt"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// A delegation with no DS is a claim, not an absence: the parent is saying that
// the child is unsigned, and a chain that takes its word for it can be walked
// off the secure path by anyone able to drop records from a referral. RFC 4035
// section 5.2 and RFC 5155 section 8.9 are what turn the claim back into
// something the parent has to have signed.
//
// Only the no-DS proof is read here. Proving that a name or a type does not
// exist is the other half of denial of existence and is not needed to keep the
// chain of trust honest.

// base32hex is how NSEC3 spells a hash, both in an owner name and in the field
// naming the next one.
var base32hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// optOut is the flag that lets an NSEC3 cover a delegation it does not name.
const optOut = 1

// maxNSEC3Iterations is where hashing stops being worth it. Every iteration
// costs the validator a hash of its own, and a referral may carry several
// records, so a zone asking for tens of thousands is asking us to grind rather
// than to check. RFC 9276 settles on nought and calls anything beyond a hundred
// unreasonable.
const maxNSEC3Iterations = 100

// provesNoDS reports whether authority carries the parent's signed word that
// zone has no DS record. A nil error means the insecure delegation is proven.
func (c *Chain) provesNoDS(authority []dns.RR, zone string) error {
	if len(c.keys) == 0 {
		return fmt.Errorf("there are no keys to check the denial against")
	}
	zone = dnsutil.Canonical(zone)

	// RFC 4035 5.2: an NSEC owned by the delegation itself, saying the name is
	// a delegation (NS) that carries no DS. SOA would make it the apex of the
	// zone below the cut, which is the child's word and not the parent's.
	for _, rr := range authority {
		nsec, ok := rr.(*dns.NSEC)
		if !ok || !dns.EqualName(nsec.Hdr.Name, zone) {
			continue
		}
		if err := c.signedBy(authority, nsec.Hdr.Name, dns.TypeNSEC); err != nil {
			return err
		}
		return provesNoDSBitmap(nsec.TypeBitMap, "NSEC")
	}

	// RFC 5155 8.9: an NSEC3 matching the delegation, or one covering it with
	// the opt-out flag set.
	unproven := fmt.Errorf("the parent published no proof that it has no DS")
	for _, rr := range authority {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		if nsec3.Hash != 1 {
			return unsupportedError{fmt.Sprintf("NSEC3 hash algorithm %d is not supported here", nsec3.Hash)}
		}
		if nsec3.Iterations > maxNSEC3Iterations {
			return unsupportedError{fmt.Sprintf("the NSEC3 asks for %d iterations, more than the %d worth hashing",
				nsec3.Iterations, maxNSEC3Iterations)}
		}
		// The owner is the hash of some name inside the parent, so the parent
		// is what the record has to be signed by; the codec ties a signature
		// to the key's own zone, and signedBy ties it to these keys.
		hashed := dnsutil.NSEC3Name(zone, nsec3.Salt, nsec3.Iterations)
		if hashed == "" {
			return fmt.Errorf("the name of the delegation could not be hashed")
		}

		switch owner := ownerHash(nsec3.Hdr.Name); {
		case owner == "":
			continue
		case owner == hashed:
			if err := c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3); err != nil {
				return err
			}
			return provesNoDSBitmap(nsec3.TypeBitMap, "NSEC3")
		case nsec3.Flags&optOut == 0:
			continue // covers nothing it does not name
		case covers(owner, nsec3.NextDomain, hashed):
			if err := c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3); err != nil {
				return err
			}
			return nil // opt-out: the parent never said whether this one is signed
		}
	}
	return unproven
}

// provesNoDSBitmap reads the one thing the proof is for. A bitmap carrying DS
// says the opposite of what the referral did, which is a parent contradicting
// itself rather than a delegation to read either way.
func provesNoDSBitmap(bitmap []uint16, kind string) error {
	switch {
	case hasType(bitmap, dns.TypeDS):
		return fmt.Errorf("the %s of the delegation says it has a DS the referral did not carry", kind)
	case hasType(bitmap, dns.TypeSOA):
		return fmt.Errorf("the %s of the delegation comes from the child, not the parent", kind)
	case !hasType(bitmap, dns.TypeNS):
		return fmt.Errorf("the %s of the delegation does not say it is a delegation", kind)
	}
	return nil
}

// signedBy checks the parent's signature over one RRset of the denial. Without
// it an NSEC3 is just bytes anybody can write.
func (c *Chain) signedBy(authority []dns.RR, owner string, rrtype uint16) error {
	var (
		rrset      []dns.RR
		signatures []*dns.RRSIG
	)
	for _, rr := range authority {
		if !dns.EqualName(rr.Header().Name, owner) {
			continue
		}
		if signature, ok := rr.(*dns.RRSIG); ok {
			if signature.TypeCovered == rrtype {
				signatures = append(signatures, signature)
			}
			continue
		}
		if dns.RRToType(rr) == rrtype {
			rrset = append(rrset, rr)
		}
	}
	if len(signatures) == 0 {
		return fmt.Errorf("the denial of a DS carries no signature")
	}
	if _, err := c.verify(rrset, signatures, c.keys); err != nil {
		return fmt.Errorf("the denial of a DS is not signed by the keys of the parent")
	}
	return nil
}

// ownerHash is the hash an NSEC3 owner name carries, which is its first label.
func ownerHash(owner string) string {
	label, _, found := strings.Cut(owner, ".")
	if !found || label == "" {
		return ""
	}
	return strings.ToUpper(label)
}

// covers reports whether the range an NSEC3 spans holds hashed. The range runs
// from the owner to the next owner, exclusive at both ends, and the last one of
// a zone wraps around the end of the ordering.
func covers(owner, next, hashed string) bool {
	from, to, target := decode(owner), decode(next), decode(hashed)
	if from == "" || to == "" || target == "" {
		return false
	}
	if from < to {
		return from < target && target < to
	}
	// The record closing the circle: everything after the last hash, and
	// everything before the first.
	return target > from || target < to
}

// decode turns a base32hex hash into the bytes it stands for, so that two of
// them compare the way the ordering of a zone does.
func decode(hash string) string {
	raw, err := base32hex.DecodeString(strings.ToUpper(hash))
	if err != nil {
		return ""
	}
	return string(raw)
}

func hasType(bitmap []uint16, rrtype uint16) bool {
	return slices.Contains(bitmap, rrtype)
}
