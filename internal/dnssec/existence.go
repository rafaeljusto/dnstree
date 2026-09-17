package dnssec

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Proving that something is not there is the other half of denial of existence.
// A signed zone cannot sign an answer it is not sending, so it signs the gaps
// in itself instead: NSEC names the next name in the zone, NSEC3 names the next
// hash, and either way a name falling in a gap is a name the zone does not
// hold. RFC 4035 section 5.4 and RFC 5155 section 8.
//
// Without this an empty answer is only ever a server's word. With it, NXDOMAIN
// and NODATA are as checkable as an answer, and a wildcard cannot be stretched
// over a name the zone would have answered for itself.

// provesNoName checks that the zone denies qname altogether, which is what an
// NXDOMAIN claims. Two things have to hold: the name falls in a gap, and so
// does the wildcard that would otherwise have answered for it.
func (c *Chain) provesNoName(authority []dns.RR, qname string) error {
	if len(c.keys) == 0 {
		return fmt.Errorf("there are no keys to check the denial against")
	}
	qname = dnsutil.Canonical(qname)

	if nsecs := nsecsOf(authority); len(nsecs) > 0 {
		return c.nsecDeniesName(nsecs, authority, qname)
	}
	nsec3s, err := nsec3sOf(authority)
	if err != nil {
		return err
	}
	if len(nsec3s) > 0 {
		return c.nsec3DeniesName(nsec3s, authority, qname)
	}
	return fmt.Errorf("the answer carries no denial of existence")
}

// provesNoType checks that the name is there and the type is not, which is what
// a NODATA claims.
func (c *Chain) provesNoType(authority []dns.RR, qname string, qtype uint16) error {
	if len(c.keys) == 0 {
		return fmt.Errorf("there are no keys to check the denial against")
	}
	qname = dnsutil.Canonical(qname)

	if nsecs := nsecsOf(authority); len(nsecs) > 0 {
		return c.nsecDeniesType(nsecs, authority, qname, qtype)
	}
	nsec3s, err := nsec3sOf(authority)
	if err != nil {
		return err
	}
	if len(nsec3s) > 0 {
		return c.nsec3DeniesType(nsec3s, authority, qname, qtype)
	}
	return fmt.Errorf("the answer carries no denial of existence")
}

// provesNoCloserMatch checks the proof a wildcard answer owes. A signature
// covering fewer labels than the name it answers for was made over a wildcard
// and stretched across the gap below it; the zone has to show the gap is real,
// or any wildcard could be spread over a name the zone answers for itself.
// RFC 4035 section 5.3.4 and RFC 5155 section 8.8.
func (c *Chain) provesNoCloserMatch(authority []dns.RR, qname string, labels uint8) error {
	if len(c.keys) == 0 {
		return fmt.Errorf("there are no keys to check the denial against")
	}
	qname = dnsutil.Canonical(qname)

	// The wildcard sits at the last `labels` labels of the name; the one below
	// it is the name that must not exist.
	nextCloser := ancestorOf(qname, int(labels)+1)

	if nsecs := nsecsOf(authority); len(nsecs) > 0 {
		for _, nsec := range nsecs {
			if !nsecCovers(nsec, nextCloser) {
				continue
			}
			return c.signedBy(authority, nsec.Hdr.Name, dns.TypeNSEC)
		}
		return fmt.Errorf("nothing denies %s, so the wildcard was stretched over it", nextCloser)
	}

	nsec3s, err := nsec3sOf(authority)
	if err != nil {
		return err
	}
	for _, nsec3 := range nsec3s {
		if !nsec3Covers(nsec3, nextCloser) {
			continue
		}
		if nsec3.Flags&optOut != 0 {
			return unsupportedError{"the wildcard rests on an opt-out range, which proves nothing about " + nextCloser}
		}
		return c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3)
	}
	return fmt.Errorf("nothing denies %s, so the wildcard was stretched over it", nextCloser)
}

// nsecDeniesName is the NSEC half of an NXDOMAIN: a gap holding the name, and a
// gap holding the wildcard of its closest encloser.
func (c *Chain) nsecDeniesName(nsecs []*dns.NSEC, authority []dns.RR, qname string) error {
	var covering *dns.NSEC
	for _, nsec := range nsecs {
		if nsecCovers(nsec, qname) {
			covering = nsec
			break
		}
	}
	if covering == nil {
		return fmt.Errorf("no NSEC denies %s", qname)
	}
	if err := c.signedBy(authority, covering.Hdr.Name, dns.TypeNSEC); err != nil {
		return err
	}

	// The closest encloser is the deepest ancestor the covering record shows to
	// exist, which is whichever of its two ends shares more of the name.
	shared := max(dnsutil.Common(qname, covering.Hdr.Name), dnsutil.Common(qname, covering.NextDomain))
	wildcard := wildcardAt(ancestorOf(qname, shared))

	for _, nsec := range nsecs {
		if nsecMatches(nsec, wildcard) {
			return fmt.Errorf("%s exists, so %s should have been answered for", wildcard, qname)
		}
	}
	for _, nsec := range nsecs {
		if !nsecCovers(nsec, wildcard) {
			continue
		}
		return c.signedBy(authority, nsec.Hdr.Name, dns.TypeNSEC)
	}
	return fmt.Errorf("no NSEC denies the wildcard %s", wildcard)
}

// nsecDeniesType is the NSEC half of a NODATA. The name is named outright, or
// shown to be a name that only has children, or answered for by a wildcard that
// has no such type either.
func (c *Chain) nsecDeniesType(nsecs []*dns.NSEC, authority []dns.RR, qname string, qtype uint16) error {
	for _, nsec := range nsecs {
		if !nsecMatches(nsec, qname) {
			continue
		}
		if err := c.signedBy(authority, nsec.Hdr.Name, dns.TypeNSEC); err != nil {
			return err
		}
		return deniesType(nsec.TypeBitMap, qname, qtype, "NSEC")
	}

	// An empty non-terminal owns nothing itself, so no NSEC names it; the one
	// spanning it points at a name below it, which is what says it is there.
	for _, nsec := range nsecs {
		if !nsecCovers(nsec, qname) || dns.EqualName(nsec.NextDomain, qname) {
			continue
		}
		if !dnsutil.IsBelow(qname, nsec.NextDomain) {
			continue
		}
		return c.signedBy(authority, nsec.Hdr.Name, dns.TypeNSEC)
	}

	// A wildcard answered, and it has no more of this type than the name does.
	var covering *dns.NSEC
	for _, nsec := range nsecs {
		if nsecCovers(nsec, qname) {
			covering = nsec
			break
		}
	}
	if covering != nil {
		shared := max(dnsutil.Common(qname, covering.Hdr.Name), dnsutil.Common(qname, covering.NextDomain))
		wildcard := wildcardAt(ancestorOf(qname, shared))
		for _, nsec := range nsecs {
			if !nsecMatches(nsec, wildcard) {
				continue
			}
			if err := c.signedBy(authority, covering.Hdr.Name, dns.TypeNSEC); err != nil {
				return err
			}
			if err := c.signedBy(authority, nsec.Hdr.Name, dns.TypeNSEC); err != nil {
				return err
			}
			return deniesType(nsec.TypeBitMap, wildcard, qtype, "NSEC")
		}
	}
	return fmt.Errorf("no NSEC says %s has no %s", qname, dnsutil.TypeToString(qtype))
}

// nsec3DeniesName is the NSEC3 half of an NXDOMAIN, which RFC 5155 section 8.4
// builds out of three records: the closest encloser, the name one label below
// it, and the wildcard that would have answered.
func (c *Chain) nsec3DeniesName(nsec3s []*dns.NSEC3, authority []dns.RR, qname string) error {
	encloser, nextCloser, found := closestEncloser(nsec3s, qname, c.zoneName())
	if !found {
		return fmt.Errorf("no NSEC3 names an ancestor of %s", qname)
	}
	if nextCloser == "" {
		return fmt.Errorf("%s is named by an NSEC3, so it is not absent", qname)
	}

	// RFC 5155 section 8.4 asks for the gap holding the name one label below the
	// encloser, and for the gap holding the wildcard. It does not ask after the
	// opt-out flag here, and deliberately: an opt-out zone leaves unsigned
	// delegations out of its chain, so a name error from one says only that the
	// name is not in the signed part of the zone. That is the bargain opt-out
	// makes, not a proof this walk can improve on.
	if _, err := c.nsec3Covering(nsec3s, authority, nextCloser); err != nil {
		return err
	}

	wildcard := wildcardAt(encloser)
	for _, nsec3 := range nsec3s {
		if nsec3Matches(nsec3, wildcard) {
			return fmt.Errorf("%s exists, so %s should have been answered for", wildcard, qname)
		}
	}
	if _, err := c.nsec3Covering(nsec3s, authority, wildcard); err != nil {
		return fmt.Errorf("no NSEC3 denies the wildcard %s", wildcard)
	}
	return nil
}

// nsec3DeniesType is the NSEC3 half of a NODATA.
func (c *Chain) nsec3DeniesType(nsec3s []*dns.NSEC3, authority []dns.RR, qname string, qtype uint16) error {
	for _, nsec3 := range nsec3s {
		if !nsec3Matches(nsec3, qname) {
			continue
		}
		if err := c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3); err != nil {
			return err
		}
		return deniesType(nsec3.TypeBitMap, qname, qtype, "NSEC3")
	}

	// A wildcard answered with nothing of this type: RFC 5155 section 8.7.
	encloser, nextCloser, found := closestEncloser(nsec3s, qname, c.zoneName())
	if found && nextCloser != "" {
		if _, err := c.nsec3Covering(nsec3s, authority, nextCloser); err == nil {
			wildcard := wildcardAt(encloser)
			for _, nsec3 := range nsec3s {
				if !nsec3Matches(nsec3, wildcard) {
					continue
				}
				if err := c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3); err != nil {
					return err
				}
				return deniesType(nsec3.TypeBitMap, wildcard, qtype, "NSEC3")
			}
		}
	}
	return fmt.Errorf("no NSEC3 says %s has no %s", qname, dnsutil.TypeToString(qtype))
}

// nsec3Covering is the signed record spanning name, which is the shape every
// NSEC3 proof of absence repeats.
func (c *Chain) nsec3Covering(nsec3s []*dns.NSEC3, authority []dns.RR, name string) (*dns.NSEC3, error) {
	for _, nsec3 := range nsec3s {
		if !nsec3Covers(nsec3, name) {
			continue
		}
		if err := c.signedBy(authority, nsec3.Hdr.Name, dns.TypeNSEC3); err != nil {
			return nil, err
		}
		return nsec3, nil
	}
	return nil, fmt.Errorf("no NSEC3 denies %s", name)
}

// deniesType reads a bitmap for a NODATA. An alias in it means the server owed
// us the alias instead, and the type itself in it means the record is there.
func deniesType(bitmap []uint16, owner string, qtype uint16, kind string) error {
	switch {
	case hasType(bitmap, qtype):
		return fmt.Errorf("the %s says %s has a %s after all", kind, owner, dnsutil.TypeToString(qtype))
	case qtype != dns.TypeCNAME && hasType(bitmap, dns.TypeCNAME):
		return fmt.Errorf("the %s says %s is an alias, which the answer did not carry", kind, owner)
	}
	return nil
}

// zoneName is the zone the chain is in, which its keys are the keys of.
func (c *Chain) zoneName() string {
	if len(c.keys) == 0 {
		return "."
	}
	return dnsutil.Canonical(c.keys[0].Hdr.Name)
}
