package transport

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"codeberg.org/miekg/dns/svcb"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// The question a walk answered the long way round, put to a recursive server
// instead: the other number a walk's cost is read against. It lives here
// rather than beside the comparison because asking takes the codec, and only
// the packages that speak the wire format may import it.

// ResolvConf is where a host keeps the servers it resolves through.
const ResolvConf = "/etc/resolv.conf"

// System is the first recursive server the host is set up to use, invalid when
// the host will not say: Windows keeps the list elsewhere, and a machine with
// no resolv.conf has none to give.
func System() netip.AddrPort { return SystemFrom(ResolvConf) }

// SystemFrom is System, reading a named file. It is the seam the tests use.
func SystemFrom(path string) netip.AddrPort {
	cfg, err := dnsconf.FromFile(path)
	if err != nil {
		return netip.AddrPort{}
	}

	port := uint16(PortDNS)
	if parsed, err := strconv.ParseUint(cfg.Port, 10, 16); err == nil && parsed > 0 {
		port = uint16(parsed)
	}
	for _, server := range cfg.Servers {
		if addr, err := netip.ParseAddr(server); err == nil {
			return netip.AddrPortFrom(addr, port)
		}
	}
	return netip.AddrPort{}
}

// Ask puts question to server with recursion desired and reports what came
// back. Like the origin AS lookups it is best effort: a server that stays
// silent or refuses leaves the reason in the result, since that is about the
// resolver and says nothing about the walk. An error means the question could
// not be asked at all.
func Ask(ctx context.Context, carrier Transport, server netip.AddrPort,
	question trace.Question, dnssec bool, subnet netip.Prefix) (*trace.Resolver, error) {
	return ask(ctx, carrier, nil, server, question, dnssec, subnet, 0, false)
}

// Recheck is Ask with checking disabled (RFC 4035): the resolver hands back
// what it found without validating it. Asked after a SERVFAIL, it tells a
// failed validation from a failure to get an answer at all.
func Recheck(ctx context.Context, carrier Transport, server netip.AddrPort,
	question trace.Question, dnssec bool, subnet netip.Prefix) (*trace.Resolver, error) {
	return ask(ctx, carrier, nil, server, question, dnssec, subnet, 0, true)
}

// Lookup is Ask for a question of the run's own, read whole: an answer too big
// for a datagram is asked again over fallback, since a policy cut short is not
// the policy. A resolver still resolving when the time ran out is asked again
// up to retries more times, the way the walk asks a silent server again, and
// then over fallback.
func Lookup(ctx context.Context, carrier, fallback Transport, server netip.AddrPort,
	name, qtype string, retries int) (*trace.Resolver, error) {
	return ask(ctx, carrier, fallback, server, trace.Question{Name: name, Type: qtype, Class: "IN"}, false, netip.Prefix{}, retries, false)
}

func ask(ctx context.Context, carrier, fallback Transport, server netip.AddrPort,
	question trace.Question, dnssec bool, subnet netip.Prefix, retries int, unchecked bool) (*trace.Resolver, error) {

	qtype, ok := dns.StringToType[strings.ToUpper(question.Type)]
	if !ok {
		return nil, fmt.Errorf("recursive: unknown query type %q", question.Type)
	}
	req, err := NewQuery(dnsutil.Fqdn(question.Name), qtype, DefaultUDPSize, dnssec)
	if err != nil {
		return nil, fmt.Errorf("recursive: %w", err)
	}
	WithSubnet(req, subnet)

	// The whole point: the server is asked to do the walking this time.
	req.RecursionDesired = true
	req.CheckingDisabled = unchecked

	resp, rtt, err := carrier.Exchange(ctx, req, server, "")
	for attempt := 0; attempt < retries && err != nil && IsTimeout(err); attempt++ {
		resp, rtt, err = carrier.Exchange(ctx, req, server, "")
	}
	// A big answer that never arrives is as common as one that arrives cut
	// short: something on the way drops the datagram it would have come in.
	if fallback != nil && (err == nil && resp.Truncated || err != nil && IsTimeout(err)) {
		var more time.Duration
		resp, more, err = fallback.Exchange(ctx, req, server, "")
		rtt += more
	}
	answer := &trace.Resolver{
		Server:  trace.Server{IP: server.Addr(), Port: server.Port()},
		Elapsed: rtt,
	}
	if err != nil {
		// An error can quote what the server sent, as the walk's own steps do.
		answer.Err = trace.Printable(err.Error(), trace.MaxErr)
	} else {
		answer.Rcode = dnsutil.RcodeToString(resp.Rcode)
		answer.Records = recursiveRecords(resp.Answer)
		answer.Extended = Extended(resp)
		answer.Subnet = EchoedSubnet(resp)
	}
	return answer, nil

}

// recursiveRecords flattens an answer section the way the walk does, minus the
// signatures. It is kept apart from the resolver's own copy: asking a
// recursive server is the opposite of walking, and the two only meet in the
// model.
func recursiveRecords(rrs []dns.RR) []trace.RR {
	var records []trace.RR
	for _, rr := range rrs {
		if dns.RRToType(rr) == dns.TypeRRSIG {
			continue
		}
		records = append(records, trace.RR{
			Name: rr.Header().Name,
			TTL:  rr.Header().TTL,
			Type: dnsutil.TypeToString(dns.RRToType(rr)),
			Data: fmt.Sprint(rr.Data()),
		})
	}
	return records
}

// DDRName is where a resolver says which encrypted resolvers stand for it
// (RFC 9462).
const DDRName = "_dns.resolver.arpa."

// Discover asks server which encrypted resolvers it designates. It is best
// effort like Ask: a server that will not say leaves the reason in the result.
// Nothing is connected to, so an offer is a claim and not a verified one.
//
// A truncated answer is asked again over fallback. Read as it stands, the
// records that did not fit would be offers the server never made.
func Discover(ctx context.Context, carrier, fallback Transport, server netip.AddrPort) *trace.Discovery {
	req, err := NewQuery(DDRName, dns.TypeSVCB, DefaultUDPSize, false)
	if err != nil {
		return &trace.Discovery{Err: trace.Printable(err.Error(), trace.MaxErr)}
	}
	req.RecursionDesired = true

	resp, _, err := carrier.Exchange(ctx, req, server, "")
	if err == nil && resp.Truncated {
		if fallback == nil {
			return &trace.Discovery{Err: "the answer was truncated, and nothing could ask again over tcp"}
		}
		resp, _, err = fallback.Exchange(ctx, req, server, "")
		if err == nil && resp.Truncated {
			return &trace.Discovery{Err: "the answer was truncated over tcp as well"}
		}
	}
	if err != nil {
		return &trace.Discovery{Err: trace.Printable(err.Error(), trace.MaxErr)}
	}
	found := &trace.Discovery{Rcode: dnsutil.RcodeToString(resp.Rcode)}
	for _, rr := range resp.Answer {
		// Only the records at the name asked: an alias to somewhere else is
		// not a designation, and AliasMode is not one either (RFC 9462 §4).
		record, ok := rr.(*dns.SVCB)
		if !ok || !strings.EqualFold(rr.Header().Name, DDRName) || record.Priority == 0 {
			continue
		}
		if offer, ok := designated(record.SVCB); ok {
			found.Designated = append(found.Designated, offer)
		}
	}
	return found
}

// understood are the keys a designation is read by. A record that makes any
// other key mandatory is one a client has to drop (RFC 9460 §8).
var understood = []uint16{svcb.KeyAlpn, svcb.KeyPort, svcb.KeyIPv4Hint, svcb.KeyIPv6Hint, svcb.KeyDohPath}

// designated decodes one ServiceMode record into what a client would dial, and
// reports false for one no client could use: a key it must understand and
// does not, no ALPN to say what is spoken, or a target of "." — the owner
// name, which for _dns.resolver.arpa is nowhere to connect to.
func designated(data rdata.SVCB) (trace.Designated, bool) {
	offer := trace.Designated{Priority: data.Priority, Target: dnsutil.Fqdn(data.Target)}
	if offer.Target == "." {
		return offer, false
	}
	for _, pair := range data.Value {
		switch pair := pair.(type) {
		case *svcb.MANDATORY:
			for _, key := range pair.Key {
				if !slices.Contains(understood, key) {
					return offer, false
				}
			}
		case *svcb.ALPN:
			offer.ALPN = pair.Alpn
		case *svcb.PORT:
			offer.Port = pair.Port
		case *svcb.DOHPATH:
			offer.DoHPath = pair.Template
		case *svcb.IPV4HINT:
			offer.Hints = append(offer.Hints, pair.Hint...)
		case *svcb.IPV6HINT:
			offer.Hints = append(offer.Hints, pair.Hint...)
		}
	}
	if len(offer.ALPN) == 0 {
		return offer, false
	}
	offer.Protocols = protocols(offer.ALPN, offer.DoHPath != "")
	return offer, true
}

// protocols reads the ALPN as transports (RFC 9461). HTTP is DoH only with a
// path to send the queries to, which is what the RFC requires of a DoH offer.
func protocols(alpn []string, path bool) []string {
	var named []string
	for _, id := range alpn {
		var proto string
		switch id {
		case "dot":
			proto = "dot"
		case "doq":
			proto = "doq"
		case "h2", "h3":
			if path {
				proto = "doh"
			}
		}
		if proto != "" && !slices.Contains(named, proto) {
			named = append(named, proto)
		}
	}
	return named
}

// ReportChannel is the agent a server asks DNS failures to be reported to
// (RFC 9567), empty where it named none. Servers send it unasked: a query is
// not allowed to carry the option.
func ReportChannel(resp *dns.Msg) string {
	if resp == nil {
		return ""
	}
	for _, rr := range resp.Pseudo {
		channel, ok := rr.(*dns.REPORTING)
		if !ok || channel.AgentDomain == "" || channel.AgentDomain == "." {
			continue
		}
		return dnsutil.Fqdn(channel.AgentDomain)
	}
	return ""
}

// ReportName is the name a report of an extended error is looked up as (RFC
// 9567 section 6.1.1): _er, the type asked as a number, the name asked, the
// error code, _er again and the agent. False where there is no such name: a
// type this build does not know, or a name longer than a name can be, which
// the RFC says is not to be sent.
func ReportName(question trace.Question, code uint16, agent string) (string, bool) {
	qtype, ok := dns.StringToType[strings.ToUpper(question.Type)]
	if !ok {
		return "", false
	}
	asked := strings.TrimSuffix(dnsutil.Fqdn(question.Name), ".")
	name := fmt.Sprintf("_er.%d.", qtype)
	if asked != "" {
		name += asked + "."
	}
	name += fmt.Sprintf("%d._er.%s", code, dnsutil.Fqdn(agent))
	// On the wire a name takes a length octet for each label and one for the
	// root, which is one octet more than it takes written out with its dots.
	return name, dnsutil.IsName(name) && len(name)+1 <= maxNameOctets
}

// maxNameOctets is the longest a name can be on the wire (RFC 1035 3.1).
const maxNameOctets = 255

// SendReport looks the report up, as a TXT query with recursion desired, the
// way any resolver would send one: the lookup is the report, and the agent's
// answer says nothing more than that it arrived. It hands back the rcode.
func SendReport(ctx context.Context, carrier, fallback Transport, server netip.AddrPort, name string) (string, error) {
	req, err := NewQuery(name, dns.TypeTXT, DefaultUDPSize, false)
	if err != nil {
		return "", err
	}
	req.RecursionDesired = true

	resp, _, err := carrier.Exchange(ctx, req, server, "")
	if err == nil && resp.Truncated && fallback != nil {
		resp, _, err = fallback.Exchange(ctx, req, server, "")
	}
	if err != nil {
		return "", err
	}
	return dnsutil.RcodeToString(resp.Rcode), nil
}
