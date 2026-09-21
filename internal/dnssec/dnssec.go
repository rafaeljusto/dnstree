// Package dnssec validates the chain of trust one zone cut at a time: DS from
// the parent, DNSKEY from the child, then the signatures over the answer.
package dnssec

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/roothints"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// Chain is the trust from the root anchors down to the zone a walk has reached.
// A walk enters one zone at a time, so a chain is not safe for concurrent use.
type Chain struct {
	anchors roothints.Anchors
	state   trace.DNSSECState
	reason  string

	// keys are the validated keys of the zone the chain is in.
	keys []*dns.DNSKEY

	// zone is the zone those keys belong to, carried on every verdict. The step
	// a verdict is drawn on is not always that zone: a cut is judged from
	// above, so a referral holds the verdict of the zone it points at, and a
	// cut crossed without a referral is judged on the hop that crossed it.
	zone string

	// now is the clock signature validity is judged against.
	now func() time.Time
}

// New starts a chain at the root, trusting anchors and nothing else.
func New(anchors roothints.Anchors) *Chain {
	return &Chain{anchors: anchors, state: trace.Secure, zone: ".", now: time.Now}
}

// State is how far the chain got.
func (c *Chain) State() trace.DNSSECState { return c.state }

// Enter validates the keys of a zone against the DS records its parent handed
// out, and makes them the keys the chain verifies with from here on. authority
// is the authority section of the parent's referral, and dnskeys the child's
// answer to a DNSKEY query; either may be empty. The root takes its DS from the
// anchors instead of from a parent.
func (c *Chain) Enter(zone string, authority, dnskeys []dns.RR) *trace.DNSSECStatus {
	return c.about(c.enter(zone, authority, dnskeys))
}

func (c *Chain) enter(zone string, authority, dnskeys []dns.RR) *trace.DNSSECStatus {
	zone = dnsutil.Fqdn(zone)
	c.zone = zone

	// An unsigned or broken zone stays that way all the way down: there is no
	// way back to secure without a DS to hang it on.
	if c.state != trace.Secure {
		c.keys = nil
		return &trace.DNSSECStatus{State: c.state, Reason: c.reason}
	}

	delegated := dsRecords(authority, zone)
	if zone == "." {
		delegated = anchorDS(c.anchors)
	}
	if len(delegated) == 0 {
		// The root has no parent to prove anything: without an anchor there is
		// nothing to start from, which is a chain that cannot begin rather than
		// one that ended.
		if zone == "." {
			return c.settleAs(&trace.DNSSECStatus{}, trace.Indeterminate,
				"there is no trust anchor to start the chain from", nil)
		}
		// An insecure delegation is something the parent says, and saying it is
		// what a DS-denying NSEC or NSEC3 is for. Taking the absence of a DS on
		// trust is what lets anyone who can drop records from a referral walk
		// the chain off the secure path.
		if err := c.provesNoDS(authority, zone); err != nil {
			state := trace.Bogus
			if unsupported(err) {
				state = trace.Indeterminate
			}
			return c.settleAs(&trace.DNSSECStatus{}, state,
				"the parent published no DS: "+err.Error(), nil)
		}
		return c.settleAs(&trace.DNSSECStatus{}, trace.Insecure, "the parent published no DS", nil)
	}

	status := &trace.DNSSECStatus{
		Algorithm: algorithm(delegated[0].Algorithm),
		Digest:    digest(delegated[0].DigestType),
	}
	for _, ds := range delegated {
		status.KeyTags = append(status.KeyTags, ds.KeyTag)
	}

	// A DS is the parent's word for the child, and worth no more than the
	// parent's signature over it. The anchors are the one thing trusted on
	// sight.
	if zone != "." {
		signed := dsSignatures(authority, zone)
		if len(signed) == 0 {
			return c.settleAs(status, trace.Bogus, "the parent published a DS it did not sign", nil)
		}
		if _, err := c.verify(asRRs(delegated), signed, c.keys); err != nil {
			return c.settleAs(status, trace.Bogus, "the DS is not signed by the keys of the parent", nil)
		}
	}

	keys, signatures := split(dnskeys, zone)
	if len(keys) == 0 {
		return c.settleAs(status, trace.Indeterminate, "the DNSKEY set could not be fetched", nil)
	}

	key, err := matchDS(delegated, keys)
	if err != nil {
		state := trace.Bogus
		if unsupported(err) {
			state = trace.Indeterminate
		}
		return c.settleAs(status, state, err.Error(), nil)
	}

	// The key the DS points at has to be the one that signed the whole set.
	if _, err := c.verify(asRRs(keys), signatures, []*dns.DNSKEY{key}); err != nil {
		return c.settleAs(status, trace.Bogus, "the DNSKEY set is not signed by the key the DS points at", nil)
	}

	status.KeyTags = []uint16{key.KeyTag()}
	return c.settleAs(status, trace.Secure, "", keys)
}

// Unchecked stops the chain where a link could not be fetched at all, which is
// neither a break nor a pass: everything below it is reported as unchecked.
func (c *Chain) Unchecked(zone, reason string) *trace.DNSSECStatus {
	status := &trace.DNSSECStatus{State: c.state, Reason: c.reason}
	if c.state == trace.Secure {
		status = c.settleAs(&trace.DNSSECStatus{}, trace.Indeterminate, reason, nil)
	}
	// The chain never reached this zone, so it is the caller that knows which
	// one was being fetched.
	status.Zone = dnsutil.Fqdn(zone)
	return status
}

// Verify checks what a server said about qname and qtype against the keys of
// the zone the chain is in: the records that answer it, or, when there are
// none, the denial in authority that says there are none to give. rcode is what
// the server answered with, which is the difference between a name that is not
// there and a name that has nothing of this type.
func (c *Chain) Verify(answer, authority []dns.RR, rcode uint16, qname string, qtype uint16) *trace.DNSSECStatus {
	return c.about(c.verifyAnswer(answer, authority, rcode, qname, qtype))
}

func (c *Chain) verifyAnswer(answer, authority []dns.RR, rcode uint16, qname string, qtype uint16) *trace.DNSSECStatus {
	if c.state != trace.Secure {
		return &trace.DNSSECStatus{State: c.state, Reason: c.reason}
	}

	rrset, signatures := rrset(answer, qname, qtype)
	if len(rrset) == 0 {
		return c.verifyDenial(authority, rcode, qname, qtype)
	}
	if len(signatures) == 0 {
		return &trace.DNSSECStatus{State: trace.Bogus, Reason: "the answer carries no signature"}
	}

	status := &trace.DNSSECStatus{Algorithm: algorithm(signatures[0].Algorithm)}
	signature, err := c.verify(rrset, signatures, c.keys)
	if err != nil {
		status.State = trace.Bogus
		if unsupported(err) {
			status.State = trace.Indeterminate
		}
		status.Reason = err.Error()
		return status
	}

	// A signature covering fewer labels than the name it answers for was made
	// over a wildcard, and the zone owes a proof that there was nothing closer.
	if covered := int(signature.Labels); covered < dnsutil.Labels(qname) {
		if err := c.provesNoCloserMatch(authority, qname, signature.Labels); err != nil {
			status.State = trace.Bogus
			if unsupported(err) {
				status.State = trace.Indeterminate
			}
			status.Reason = "the answer came from a wildcard: " + err.Error()
			return status
		}
		status.Reason = "answered by a wildcard"
	}

	// Mid rollover an RRset carries several signatures; the one that held is
	// the one worth naming.
	status.State = trace.Secure
	status.Algorithm = algorithm(signature.Algorithm)
	status.KeyTags = []uint16{signature.KeyTag}
	return status
}

// verifyDenial checks an answer that carried no records. A signed zone signs
// the gaps in itself, so an empty answer from one is as checkable as a full
// one: either the name is not there, or it is and the type is not.
func (c *Chain) verifyDenial(authority []dns.RR, rcode uint16, qname string, qtype uint16) *trace.DNSSECStatus {
	proved, what := c.provesNoType(authority, qname, qtype), "has no "+dnsutil.TypeToString(qtype)
	if rcode == dns.RcodeNameError {
		proved, what = c.provesNoName(authority, qname), "does not exist"
	}
	if proved != nil {
		state := trace.Bogus
		if unsupported(proved) {
			state = trace.Indeterminate
		}
		return &trace.DNSSECStatus{State: state,
			Reason: "the zone did not prove that " + qname + " " + what + ": " + proved.Error()}
	}
	return &trace.DNSSECStatus{State: trace.Secure, Reason: "proved that " + qname + " " + what}
}

// verify checks an RRset against every signature that one of keys can carry,
// and reports the signature that carried it, so that what is reported is the
// key that actually signed rather than the first one offered.
//
// The codec verifies the maths and nothing else: it neither checks that rrset
// is one RRset nor that the signature covers its type, so both are checked
// here. A set of mixed owners or types would otherwise be packed whole into
// the signed data, where one stray record is enough to fail a sound zone.
func (c *Chain) verify(rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) (*dns.RRSIG, error) {
	if len(signatures) == 0 {
		return nil, fmt.Errorf("there is no signature to check")
	}
	if !dnsutil.IsRRset(rrset) {
		return nil, fmt.Errorf("the records to check are not one RRset")
	}
	covered := dns.RRToType(rrset[0])

	reason := fmt.Errorf("no signature matches a key of the zone")
	for _, signature := range signatures {
		if signature.TypeCovered != covered {
			continue
		}
		for _, key := range keys {
			if signature.KeyTag != key.KeyTag() || signature.Algorithm != key.Algorithm {
				continue
			}
			if !signature.ValidPeriod(c.now()) {
				reason = fmt.Errorf("the signature of key %d is outside its validity period", key.KeyTag())
				continue
			}
			if err := signature.Verify(key, rrset, &dns.SignOption{}); err != nil {
				reason = fmt.Errorf("the signature of key %d does not verify", key.KeyTag())
				continue
			}
			return signature, nil
		}
	}
	return nil, reason
}

// about stamps a verdict with the zone the chain was in when it was reached,
// which is what the verdict is about.
func (c *Chain) about(status *trace.DNSSECStatus) *trace.DNSSECStatus {
	if status != nil {
		status.Zone = c.zone
	}
	return status
}

// settleAs moves the chain to a state and reports it.
func (c *Chain) settleAs(status *trace.DNSSECStatus, state trace.DNSSECState, reason string, keys []*dns.DNSKEY) *trace.DNSSECStatus {
	c.state, c.reason, c.keys = state, reason, keys
	status.State, status.Reason = state, reason
	return status
}

// matchDS finds the key a DS points at, by digesting the key the same way.
func matchDS(delegated []*dns.DS, keys []*dns.DNSKEY) (*dns.DNSKEY, error) {
	var unknown []uint8
	for _, ds := range delegated {
		for _, key := range keys {
			if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			digested := key.ToDS(ds.DigestType)
			if digested == nil {
				unknown = append(unknown, ds.DigestType)
				continue
			}
			if strings.EqualFold(digested.Digest, ds.Digest) {
				return key, nil
			}
		}
	}
	if len(unknown) > 0 {
		return nil, unsupportedError{fmt.Sprintf("digest type %d is not supported here", unknown[0])}
	}
	return nil, fmt.Errorf("no DNSKEY of the zone matches the DS its parent published")
}

// unsupportedError is a link that could not be checked rather than one that
// failed, which is the difference between indeterminate and bogus.
type unsupportedError struct{ reason string }

func (e unsupportedError) Error() string { return e.reason }

func unsupported(err error) bool {
	var unsupported unsupportedError
	return errors.As(err, &unsupported)
}

// dsSignatures are the signatures over the DS RRset of zone, which the parent
// makes and the parent's keys check.
func dsSignatures(authority []dns.RR, zone string) []*dns.RRSIG {
	var signatures []*dns.RRSIG
	for _, rr := range authority {
		signature, ok := rr.(*dns.RRSIG)
		if !ok || signature.TypeCovered != dns.TypeDS {
			continue
		}
		if dns.EqualName(signature.Hdr.Name, zone) {
			signatures = append(signatures, signature)
		}
	}
	return signatures
}

// dsRecords are the DS records of zone in an authority section.
func dsRecords(authority []dns.RR, zone string) []*dns.DS {
	var delegated []*dns.DS
	for _, rr := range authority {
		if ds, ok := rr.(*dns.DS); ok && dns.EqualName(ds.Hdr.Name, zone) {
			delegated = append(delegated, ds)
		}
	}
	return delegated
}

// anchorDS turns the trust anchors into the DS records the root is checked
// against.
func anchorDS(anchors roothints.Anchors) []*dns.DS {
	var delegated []*dns.DS
	for _, anchor := range anchors.ValidAt(time.Now()) {
		ds := &dns.DS{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}
		ds.KeyTag, ds.Algorithm, ds.DigestType = anchor.KeyTag, anchor.Algorithm, anchor.DigestType
		ds.Digest = hexDigest(anchor.Digest)
		delegated = append(delegated, ds)
	}
	return delegated
}

// split separates a DNSKEY answer into the keys of zone and the signatures over
// them. Anything owned by another name is not part of this zone's key set, and
// a server that bundles one in must not be able to spoil the set it did sign.
func split(records []dns.RR, zone string) ([]*dns.DNSKEY, []*dns.RRSIG) {
	var (
		keys       []*dns.DNSKEY
		signatures []*dns.RRSIG
	)
	for _, rr := range records {
		if !dns.EqualName(rr.Header().Name, zone) {
			continue
		}
		switch record := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, record)
		case *dns.RRSIG:
			if record.TypeCovered == dns.TypeDNSKEY {
				signatures = append(signatures, record)
			}
		}
	}
	return keys, signatures
}

// rrset picks the records that answer the question, and the signatures over
// them. An alias answers for any type.
func rrset(answer []dns.RR, qname string, qtype uint16) ([]dns.RR, []*dns.RRSIG) {
	wanted := qtype
	for _, rr := range answer {
		if dns.EqualName(rr.Header().Name, qname) && dns.RRToType(rr) == qtype {
			wanted = qtype
			break
		}
		if cname, ok := rr.(*dns.CNAME); ok && dns.EqualName(cname.Hdr.Name, qname) {
			wanted = dns.TypeCNAME
		}
	}

	var (
		rrset      []dns.RR
		signatures []*dns.RRSIG
	)
	for _, rr := range answer {
		if !dns.EqualName(rr.Header().Name, qname) {
			continue
		}
		switch record := rr.(type) {
		case *dns.RRSIG:
			if record.TypeCovered == wanted {
				signatures = append(signatures, record)
			}
		default:
			if dns.RRToType(rr) == wanted {
				rrset = append(rrset, rr)
			}
		}
	}
	return rrset, signatures
}

// asRRs widens a typed set to the records a signature covers.
func asRRs[T dns.RR](records []T) []dns.RR {
	rrs := make([]dns.RR, 0, len(records))
	for _, record := range records {
		rrs = append(rrs, record)
	}
	return rrs
}

// algorithm and digest name what was used, so that an algorithm this build
// cannot check is never mistaken for a broken signature.
func algorithm(code uint8) string {
	if name, ok := dns.AlgorithmToString[code]; ok {
		return name
	}
	return fmt.Sprintf("algorithm %d", code)
}

func digest(code uint8) string {
	if name, ok := dns.HashToString[code]; ok {
		return name
	}
	return fmt.Sprintf("digest %d", code)
}

// hexDigest is how a DS carries its digest on the wire.
func hexDigest(raw []byte) string { return hex.EncodeToString(raw) }
