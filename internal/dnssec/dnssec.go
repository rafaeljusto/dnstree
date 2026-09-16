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

	// now is the clock signature validity is judged against.
	now func() time.Time
}

// New starts a chain at the root, trusting anchors and nothing else.
func New(anchors roothints.Anchors) *Chain {
	return &Chain{anchors: anchors, state: trace.Secure, now: time.Now}
}

// State is how far the chain got.
func (c *Chain) State() trace.DNSSECState { return c.state }

// Enter validates the keys of a zone against the DS records its parent handed
// out, and makes them the keys the chain verifies with from here on. authority
// is the authority section of the parent's referral, and dnskeys the child's
// answer to a DNSKEY query; either may be empty. The root takes its DS from the
// anchors instead of from a parent.
func (c *Chain) Enter(zone string, authority, dnskeys []dns.RR) *trace.DNSSECStatus {
	zone = dnsutil.Fqdn(zone)

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
		return c.settleAs(&trace.DNSSECStatus{}, trace.Insecure, "the parent published no DS", nil)
	}

	status := &trace.DNSSECStatus{
		Algorithm: algorithm(delegated[0].Algorithm),
		Digest:    digest(delegated[0].DigestType),
	}
	for _, ds := range delegated {
		status.KeyTags = append(status.KeyTags, ds.KeyTag)
	}

	keys, signatures := split(dnskeys)
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
	if err := c.verify(asRRs(keys), signatures, []*dns.DNSKEY{key}); err != nil {
		return c.settleAs(status, trace.Bogus, "the DNSKEY set is not signed by the key the DS points at", nil)
	}

	status.KeyTags = []uint16{key.KeyTag()}
	return c.settleAs(status, trace.Secure, "", keys)
}

// Verify checks the records that answer qname and qtype against the keys of the
// zone the chain is in.
func (c *Chain) Verify(answer []dns.RR, qname string, qtype uint16) *trace.DNSSECStatus {
	if c.state != trace.Secure {
		return &trace.DNSSECStatus{State: c.state, Reason: c.reason}
	}

	rrset, signatures := rrset(answer, qname, qtype)
	if len(rrset) == 0 {
		// Denial of existence needs NSEC or NSEC3, which is not read here, so an
		// empty answer is neither proved nor disproved.
		return &trace.DNSSECStatus{State: trace.Indeterminate,
			Reason: "an answer with no records is not checked without NSEC"}
	}
	if len(signatures) == 0 {
		return &trace.DNSSECStatus{State: trace.Bogus, Reason: "the answer carries no signature"}
	}

	status := &trace.DNSSECStatus{Algorithm: algorithm(signatures[0].Algorithm)}
	if err := c.verify(rrset, signatures, c.keys); err != nil {
		status.State = trace.Bogus
		if unsupported(err) {
			status.State = trace.Indeterminate
		}
		status.Reason = err.Error()
		return status
	}

	status.State = trace.Secure
	status.KeyTags = []uint16{signatures[0].KeyTag}
	return status
}

// verify checks an RRset against every signature that one of keys can carry.
func (c *Chain) verify(rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) error {
	if len(signatures) == 0 {
		return fmt.Errorf("there is no signature to check")
	}

	reason := fmt.Errorf("no signature matches a key of the zone")
	for _, signature := range signatures {
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
			return nil
		}
	}
	return reason
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

// split separates a DNSKEY answer into the keys and the signatures over them.
func split(records []dns.RR) ([]*dns.DNSKEY, []*dns.RRSIG) {
	var (
		keys       []*dns.DNSKEY
		signatures []*dns.RRSIG
	)
	for _, rr := range records {
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

func asRRs(keys []*dns.DNSKEY) []dns.RR {
	rrs := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrs = append(rrs, key)
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
