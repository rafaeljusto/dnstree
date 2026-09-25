package resolver

import (
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// classify decides what a response means for the zone that was queried and the
// name being chased. It looks at nothing but the message, so a referral it
// reports still has to survive the walk's own checks.
//
// extended is what the server said about its own answer, which the rcode alone
// cannot say: a reply with nothing in it reads differently once the server
// admits it withheld what it had.
func classify(resp *dns.Msg, zone, qname string, qtype uint16, extended []trace.ExtendedError) (trace.StepKind, *trace.Delegation) {
	kind, delegation := outcome(resp, zone, qname, qtype)

	// A server that says it withheld the answer is not a server with no
	// business serving the zone, and a name it would not answer for is not a
	// name that is not there. Only a reply with nothing in it is read again
	// this way: an answer that arrived is an answer, whatever the server
	// attached to it.
	switch kind {
	case trace.KindLame, trace.KindNXDomain, trace.KindNoData, trace.KindError:
		if withheld(extended) {
			return trace.KindFiltered, nil
		}
	}
	return kind, delegation
}

// withheld reports whether any of the codes says somebody decided the answer.
func withheld(extended []trace.ExtendedError) bool {
	for _, ede := range extended {
		if ede.Withheld() {
			return true
		}
	}
	return false
}

// outcome is what the message says on its own, before the server's own account
// of it is taken into any consideration.
func outcome(resp *dns.Msg, zone, qname string, qtype uint16) (trace.StepKind, *trace.Delegation) {
	switch resp.Rcode {

	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return trace.KindNXDomain, nil
	case dns.RcodeRefused:
		return trace.KindLame, nil
	default:
		return trace.KindError, nil
	}

	for _, rr := range resp.Answer {
		if !dns.EqualName(rr.Header().Name, qname) {
			continue
		}
		switch rrtype := dns.RRToType(rr); {
		case rrtype == qtype:
			return trace.KindAnswer, nil
		case rrtype == dns.TypeCNAME && qtype != dns.TypeCNAME:
			return trace.KindCNAME, nil
		}
	}

	if delegation := referral(resp, zone, qname); delegation != nil {
		return trace.KindReferral, delegation
	}
	if resp.Authoritative {
		return trace.KindNoData, nil
	}
	// Neither an answer nor a way further down: the server is not serving this
	// zone, whatever it thinks.
	return trace.KindLame, nil
}

// referral reads a downward delegation out of the authority section. A referral
// is NOERROR with the AA bit clear, an empty answer, and a single NS RRset whose
// owner sits strictly below the zone queried and covers the name being chased.
// Anything else carrying NS records is lame or an upward referral.
func referral(resp *dns.Msg, zone, qname string) *trace.Delegation {
	if resp.Authoritative || len(resp.Answer) > 0 {
		return nil
	}

	child := ""
	for _, rr := range resp.Ns {
		if dns.RRToType(rr) != dns.TypeNS {
			continue
		}
		owner := rr.Header().Name
		if child == "" {
			child = owner
		} else if !dns.EqualName(owner, child) {
			return nil // more than one delegation, none of them trustworthy
		}
	}
	if child == "" {
		return nil
	}
	if dns.EqualName(child, zone) || !dnsutil.IsBelow(zone, child) || !dnsutil.IsBelow(child, qname) {
		return nil
	}

	delegation := &trace.Delegation{Zone: child, Glue: make(map[string][]netip.Addr)}
	for _, rr := range resp.Ns {
		switch {
		case dns.RRToType(rr) == dns.TypeDS && dnsutil.IsBelow(zone, rr.Header().Name):
			delegation.DSPresent = true
		case dns.RRToType(rr) == dns.TypeNS && dns.EqualName(rr.Header().Name, child):
			if len(delegation.NS) == 0 {
				// An RRset carries one TTL, so the first record speaks for the
				// set. Counted from the first rather than left until the last,
				// because a TTL of zero is a TTL and not an absence.
				delegation.TTL = rr.Header().TTL
			}
			delegation.NS = append(delegation.NS, rr.(*dns.NS).Ns)
		}
	}

	for _, name := range delegation.NS {
		// A server may vouch for anything at or below the zone it serves, which
		// is how the root hands out the addresses of the gTLD servers. Anything
		// further afield is unsolicited, and following it is how a resolver
		// gets poisoned.
		if !dnsutil.IsBelow(zone, name) {
			continue
		}
		for _, rr := range resp.Extra {
			if !dns.EqualName(rr.Header().Name, name) {
				continue
			}
			// A record with no rdata unpacks as one with no address in it.
			switch address := rr.(type) {
			case *dns.A:
				if address.Addr.IsValid() {
					delegation.Glue[name] = append(delegation.Glue[name], address.Addr)
				}
			case *dns.AAAA:
				if address.Addr.IsValid() {
					delegation.Glue[name] = append(delegation.Glue[name], address.Addr)
				}
			}
		}
	}
	for _, name := range delegation.NS {
		if len(delegation.Glue[name]) > 0 {
			continue
		}
		// A nameserver inside the zone it serves can only be reached through the
		// glue its parent hands out; without it the delegation is broken. One
		// named anywhere else can still be found, with a walk of its own.
		if dnsutil.IsBelow(child, name) {
			delegation.GlueLess = append(delegation.GlueLess, name)
		} else {
			delegation.OutOfBailiwick = append(delegation.OutOfBailiwick, name)
		}
	}
	return delegation
}
