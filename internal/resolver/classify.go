package resolver

import (
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// classify decides what a response means for the zone that was queried and the
// name being chased. It looks at nothing but the message, so a referral it
// reports still has to survive the walk's own checks.
func classify(resp *dns.Msg, zone, qname string, qtype uint16) (trace.StepKind, *trace.Delegation) {
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
			delegation.NS = append(delegation.NS, rr.(*dns.NS).Ns)
		}
	}

	for _, name := range delegation.NS {
		// Addresses for a name outside the delegated zone are unsolicited, and
		// following them is how a resolver gets poisoned.
		if !dnsutil.IsBelow(child, name) {
			continue
		}
		for _, rr := range resp.Extra {
			if !dns.EqualName(rr.Header().Name, name) {
				continue
			}
			switch address := rr.(type) {
			case *dns.A:
				delegation.Glue[name] = append(delegation.Glue[name], address.Addr)
			case *dns.AAAA:
				delegation.Glue[name] = append(delegation.Glue[name], address.Addr)
			}
		}
	}
	for _, name := range delegation.NS {
		if len(delegation.Glue[name]) == 0 {
			delegation.GlueLess = append(delegation.GlueLess, name)
		}
	}
	return delegation
}
