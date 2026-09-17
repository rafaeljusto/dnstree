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
		return fmt.Errorf("the %s of %s carries no signature", dnsutil.TypeToString(rrtype), owner)
	}
	if _, err := c.verify(rrset, signatures, c.keys); err != nil {
		return fmt.Errorf("the %s of %s is not signed by the keys of the zone: %w",
			dnsutil.TypeToString(rrtype), owner, err)
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

// Below here is the machinery the existence proofs share: what an NSEC or an
// NSEC3 says about one name, and the name arithmetic RFC 5155 section 8 is
// written in.

// nsecsOf and nsec3sOf are the denial records of a section. A hash nothing here
// computes, or an iteration count not worth grinding through, stops the reading
// rather than failing it.
func nsecsOf(authority []dns.RR) []*dns.NSEC {
	var records []*dns.NSEC
	for _, rr := range authority {
		if nsec, ok := rr.(*dns.NSEC); ok {
			records = append(records, nsec)
		}
	}
	return records
}

func nsec3sOf(authority []dns.RR) ([]*dns.NSEC3, error) {
	var records []*dns.NSEC3
	for _, rr := range authority {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		if nsec3.Hash != 1 {
			return nil, unsupportedError{fmt.Sprintf("NSEC3 hash algorithm %d is not supported here", nsec3.Hash)}
		}
		if nsec3.Iterations > maxNSEC3Iterations {
			return nil, unsupportedError{fmt.Sprintf("the NSEC3 asks for %d iterations, more than the %d worth hashing",
				nsec3.Iterations, maxNSEC3Iterations)}
		}
		records = append(records, nsec3)
	}
	return records, nil
}

// nsecMatches and nsecCovers are the two things an NSEC can say: this name is
// the one I am about, or this name falls in the gap I span. The last NSEC of a
// zone wraps past the end of the ordering back to the apex.
func nsecMatches(nsec *dns.NSEC, name string) bool {
	return dns.EqualName(nsec.Hdr.Name, name)
}

func nsecCovers(nsec *dns.NSEC, name string) bool {
	owner, next := nsec.Hdr.Name, nsec.NextDomain
	if dns.CompareName(owner, next) >= 0 {
		return dns.CompareName(owner, name) < 0 || dns.CompareName(name, next) < 0
	}
	return dns.CompareName(owner, name) < 0 && dns.CompareName(name, next) < 0
}

// nsec3Matches and nsec3Covers are the same two things, about the hash of a
// name rather than the name itself.
func nsec3Matches(nsec3 *dns.NSEC3, name string) bool {
	hashed := dnsutil.NSEC3Name(dnsutil.Canonical(name), nsec3.Salt, nsec3.Iterations)
	return hashed != "" && ownerHash(nsec3.Hdr.Name) == hashed
}

func nsec3Covers(nsec3 *dns.NSEC3, name string) bool {
	hashed := dnsutil.NSEC3Name(dnsutil.Canonical(name), nsec3.Salt, nsec3.Iterations)
	return hashed != "" && covers(ownerHash(nsec3.Hdr.Name), nsec3.NextDomain, hashed)
}

// ancestorOf is the last n labels of name, which is how the closest encloser
// and the name one label below it are named.
func ancestorOf(name string, n int) string {
	if n <= 0 {
		return "."
	}
	labels := dnsutil.Split(dnsutil.Fqdn(name))
	if name == "." || n >= len(labels) {
		return dnsutil.Fqdn(name)
	}
	return dnsutil.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}

// wildcardAt is the name a wildcard would answer under an encloser.
func wildcardAt(encloser string) string {
	if encloser == "." {
		return "*."
	}
	return "*." + dnsutil.Fqdn(encloser)
}

// closestEncloser is the deepest ancestor of qname an NSEC3 says exists, and
// the name one label below it: the pair every NSEC3 proof of absence is built
// on. RFC 5155 section 8.3.
func closestEncloser(nsec3s []*dns.NSEC3, qname, zone string) (encloser, nextCloser string, found bool) {
	deepest, apex := dnsutil.Labels(qname), dnsutil.Labels(zone)
	for n := deepest; n >= apex; n-- {
		candidate := ancestorOf(qname, n)
		for _, nsec3 := range nsec3s {
			if !nsec3Matches(nsec3, candidate) {
				continue
			}
			if n < deepest {
				nextCloser = ancestorOf(qname, n+1)
			}
			return candidate, nextCloser, true
		}
	}
	return "", "", false
}
