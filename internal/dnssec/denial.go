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

// maxNSEC3Records is more than any proof needs: three make the longest of
// them. Every record is hashed against every label of the name, so a response
// stuffed with them is a way to make a validator grind, and the query timeout
// does not stop hashing that has already begun.
const maxNSEC3Records = 16

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

	// RFC 5155 8.9: an NSEC3 matching the delegation, or else a closest
	// encloser proof whose span over the next closer name opts out.
	nsec3s, err := c.nsec3sOf(authority)
	if err != nil {
		return err
	}
	for _, nsec3 := range nsec3s {
		// The owner is the hash of some name inside the parent, so the parent
		// is what the record has to be signed by; the codec ties a signature
		// to the key's own zone, and signedBy ties it to these keys.
		if !nsec3Matches(nsec3, zone) {
			continue
		}
		if err := c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3); err != nil {
			return err
		}
		return provesNoDSBitmap(nsec3.TypeBitMap, "NSEC3")
	}

	// A span covering the delegation alone is not enough: a referral can name
	// a cut several labels down, below a signed delegation the span knows
	// nothing about. The closest encloser is what rules that out, since a cut
	// is never one.
	_, nextCloser, found := c.closestEncloser(nsec3s, authority, zone, c.zoneName())
	if !found || nextCloser == "" {
		return fmt.Errorf("the parent published no proof that it has no DS")
	}
	span, err := c.nsec3Covering(nsec3s, authority, nextCloser)
	if err != nil {
		return fmt.Errorf("the parent published no proof that it has no DS")
	}
	if span.Flags&optOut == 0 {
		return fmt.Errorf("the NSEC3 over %s does not opt out, so it denies the delegation rather than its DS", nextCloser)
	}
	return nil // opt-out: the parent never said whether this one is signed
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
	signature, err := c.verify(rrset, signatures, c.keys)
	if err != nil {
		return fmt.Errorf("the %s of %s is not signed by the keys of the zone: %w",
			dnsutil.TypeToString(rrtype), owner, err)
	}
	// A signature covering fewer labels than the owner was made over a
	// wildcard, and the codec verifies it under any name below that wildcard.
	// A denial speaks only for the name it was signed for: RFC 4035 5.3.4.
	labels := dnsutil.Labels(owner)
	if strings.HasPrefix(dnsutil.Canonical(owner), "*.") {
		labels--
	}
	if int(signature.Labels) < labels {
		return fmt.Errorf("the %s of %s was signed for a wildcard, not for that name",
			dnsutil.TypeToString(rrtype), owner)
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

// fromTheParent is a denial record made on the parent side of a zone cut. It
// speaks for the DS at its owner and for nothing else there: RFC 6840 section
// 4.1.
func fromTheParent(bitmap []uint16) bool {
	return hasType(bitmap, dns.TypeNS) && !hasType(bitmap, dns.TypeSOA)
}

// silentBelow is a denial record that says nothing about the names under its
// owner, because they belong to another zone or are redirected by a DNAME.
func silentBelow(bitmap []uint16) bool {
	return fromTheParent(bitmap) || hasType(bitmap, dns.TypeDNAME)
}

// Below here is the machinery the existence proofs share: what an NSEC or an
// NSEC3 says about one name, and the name arithmetic RFC 5155 section 8 is
// written in.

// nsecsOf and nsec3sOf are the denial records of a section.
func nsecsOf(authority []dns.RR) []*dns.NSEC {
	var records []*dns.NSEC
	for _, rr := range authority {
		if nsec, ok := rr.(*dns.NSEC); ok {
			records = append(records, nsec)
		}
	}
	return records
}

// A hash nothing here computes, or an iteration count not worth grinding
// through, is ignored rather than trusted (RFC 5155 section 8.1): anyone can
// write one. Only when nothing else is left, and the zone signed what it could
// not be read, is the proof uncheckable rather than missing (RFC 9276 section
// 3.2).
func (c *Chain) nsec3sOf(authority []dns.RR) ([]*dns.NSEC3, error) {
	var (
		records []*dns.NSEC3
		skipped []unsupportedNSEC3
		seen    int
	)
	for _, rr := range authority {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		// Counted before anything is read: a record skipped below is still
		// checked for a signature, which costs as much as one that is used.
		if seen++; seen > maxNSEC3Records {
			return nil, fmt.Errorf("the section carries more than %d NSEC3 records, more than any proof needs", maxNSEC3Records)
		}
		switch {
		case nsec3.Hash != 1:
			skipped = append(skipped, unsupportedNSEC3{nsec3,
				fmt.Sprintf("NSEC3 hash algorithm %d is not supported here", nsec3.Hash)})
		case nsec3.Iterations > maxNSEC3Iterations:
			skipped = append(skipped, unsupportedNSEC3{nsec3,
				fmt.Sprintf("the NSEC3 asks for %d iterations, more than the %d worth hashing",
					nsec3.Iterations, maxNSEC3Iterations)})
		default:
			records = append(records, nsec3)
		}
	}
	if len(records) > 0 {
		return records, nil
	}
	for _, s := range skipped {
		if c.signedBy(authority, s.record.Hdr.Name, dns.TypeNSEC3) == nil {
			return nil, unsupportedError{s.reason}
		}
	}
	return nil, nil
}

type unsupportedNSEC3 struct {
	record *dns.NSEC3
	reason string
}

// nsecMatches and nsecCovers are the two things an NSEC can say: this name is
// the one I am about, or this name falls in the gap I span. The last NSEC of a
// zone wraps past the end of the ordering back to the apex.
func nsecMatches(nsec *dns.NSEC, name string) bool {
	return dns.EqualName(nsec.Hdr.Name, name)
}

func nsecCovers(nsec *dns.NSEC, name string) bool {
	owner, next := nsec.Hdr.Name, nsec.NextDomain
	// A delegation sorts right before the names below it, which the parent
	// neither holds nor denies.
	if silentBelow(nsec.TypeBitMap) && dnsutil.IsBelow(owner, name) {
		return false
	}
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

// closestEncloser is the deepest ancestor of qname a signed NSEC3 says exists,
// and the name one label below it: the pair every NSEC3 proof of absence is
// built on. RFC 5155 section 8.3.
func (c *Chain) closestEncloser(nsec3s []*dns.NSEC3, authority []dns.RR, qname, zone string) (encloser, nextCloser string, found bool) {
	deepest, apex := dnsutil.Labels(qname), dnsutil.Labels(zone)
	for n := deepest; n >= apex; n-- {
		candidate := ancestorOf(qname, n)
		for _, nsec3 := range nsec3s {
			if !nsec3Matches(nsec3, candidate) {
				continue
			}
			if n < deepest && silentBelow(nsec3.TypeBitMap) {
				continue // RFC 5155 8.3: a cut is never the closest encloser
			}
			if c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3) != nil {
				continue // an unsigned match would move the encloser anywhere
			}
			if n < deepest {
				nextCloser = ancestorOf(qname, n+1)
			}
			return candidate, nextCloser, true
		}
	}
	return "", "", false
}
