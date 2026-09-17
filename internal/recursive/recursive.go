// Package recursive puts the question a walk answered the long way round to a
// recursive server, and times it. A walk from the root keeps no cache and takes
// every step itself, so what it costs only reads as slow or fast against what
// the ordinary path costs; this is that other number.
package recursive

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
	question trace.Question, dnssec bool) (*trace.Resolver, error) {

	qtype, ok := dns.StringToType[strings.ToUpper(question.Type)]
	if !ok {
		return nil, fmt.Errorf("recursive: unknown query type %q", question.Type)
	}
	req, err := transport.NewQuery(dnsutil.Fqdn(question.Name), qtype, transport.DefaultUDPSize, dnssec)
	if err != nil {
		return nil, fmt.Errorf("recursive: %w", err)
	}

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
	}
	return answer, nil
}
