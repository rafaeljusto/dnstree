package transport

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/trace"
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

	resp, rtt, err := carrier.Exchange(ctx, req, server, "")
	answer := &trace.Resolver{
		Server:  trace.Server{IP: server.Addr(), Port: server.Port()},
		Elapsed: rtt,
	}
	if err != nil {
		answer.Err = err.Error()
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
