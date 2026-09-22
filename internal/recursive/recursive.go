// Package recursive puts the question a walk answered the long way round to a
// recursive server, and times it. A walk from the root keeps no cache and takes
// every step itself, so what it costs only reads as slow or fast against what
// the ordinary path costs; this is that other number.
package recursive

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

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

	port := uint16(transport.PortDNS)
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
func Ask(ctx context.Context, carrier transport.Transport, server netip.AddrPort,
	question trace.Question, dnssec bool, subnet netip.Prefix) (*trace.Resolver, error) {

	qtype, ok := dns.StringToType[strings.ToUpper(question.Type)]
	if !ok {
		return nil, fmt.Errorf("recursive: unknown query type %q", question.Type)
	}
	req, err := transport.NewQuery(dnsutil.Fqdn(question.Name), qtype, transport.DefaultUDPSize, dnssec)
	if err != nil {
		return nil, fmt.Errorf("recursive: %w", err)
	}
	transport.WithSubnet(req, subnet)

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
		answer.Records = records(resp.Answer)
		answer.Extended = transport.Extended(resp)
		answer.Subnet = transport.EchoedSubnet(resp)
	}
	return answer, nil

}

// Compare sets how the resolver's answer stands against the one the walk found
// for itself, which is the whole reason for keeping both.
//
// They are allowed to differ honestly. A CDN answers for where the question
// seems to come from, and a walk from the root and a resolver are rarely in
// the same place; a short TTL can turn over between the two questions. What a
// difference is worth looking at for is the other reason: a resolver that is
// not resolving, but answering out of a policy, a split horizon or a filter.
// The tool reports the difference and leaves that reading to the reader.
func Compare(tr *trace.Trace) {
	if tr == nil {
		return
	}
	result := tr.Result()
	if result == nil {
		return // nothing of our own to set it against
	}
	for _, answer := range tr.Resolvers {
		compare(tr, result, answer)
	}
}

// compare is one resolver's answer held against the walk's. Each of them is
// judged on its own: several resolvers are several places to have asked from,
// and one of them disagreeing says nothing about the others.
func compare(tr *trace.Trace, result *trace.Step, answer *trace.Resolver) {
	if answer == nil || answer.Err != "" {
		return
	}

	// A resolver that answered REFUSED or SERVFAIL did not resolve anything,
	// so there is no answer of its own to hold against the walk's. The rcode
	// is already on the summary line and says the whole of it; calling that a
	// difference would be reading a broken resolver as a disagreeing one.
	switch answer.Rcode {
	case "NOERROR", "NXDOMAIN":
	default:
		return
	}

	// A different rcode is a difference whatever the records say, and it is the
	// loud one: the name is there for one of them and not for the other.
	if result.Rcode != "" && result.Rcode != answer.Rcode {

		answer.Match = trace.MatchDiffers
		return
	}

	// Only the records that answer the question are compared, by rdata and not
	// by order: a nameserver is free to rotate an RRset between two questions,
	// and an alias chain reaches the same records by a different name.
	ours := trace.Answers(result.Records, tr.Question.Type)
	theirs := trace.Answers(answer.Records, tr.Question.Type)
	if len(ours) == 0 && len(theirs) == 0 {
		return
	}
	if slices.Equal(ours, theirs) {
		answer.Match = trace.MatchSame
		return
	}
	answer.Match = trace.MatchDiffers
}

// records flattens an answer section the way the walk does, minus the
// signatures. This package keeps its own copy rather than reaching into the
// resolver: what it does is the opposite of walking, and the two only meet in
// the model.
func records(rrs []dns.RR) []trace.RR {
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
