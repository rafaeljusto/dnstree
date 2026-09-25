package transport_test

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

const zone = `
@      IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@      IN NS   ns1
ns1    IN A    127.0.0.1
www    IN A    192.0.2.1
www    IN AAAA 2001:db8::1
mail   IN MX   10 mx
`

// fastConfig keeps the failure cases from sitting on the default timeout.
var fastConfig = transport.Config{Timeout: 200 * time.Millisecond}

func TestExchange(t *testing.T) {
	tests := []struct {
		proto string
		newFn func(transport.Config) transport.Transport
	}{
		{proto: "udp", newFn: func(c transport.Config) transport.Transport { return transport.NewUDP(c) }},
		{proto: "tcp", newFn: func(c transport.Config) transport.Transport { return transport.NewTCP(c) }},
	}

	for _, test := range tests {
		t.Run(test.proto, func(t *testing.T) {
			server := newServer(t, fakens.Behaviour{})
			tr := test.newFn(fastConfig)

			if got := tr.Proto(); got != test.proto {
				t.Errorf("got proto %q, want %q", got, test.proto)
			}

			resp, rtt, err := tr.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), server.Addr, "")
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("got rcode %d, want NOERROR", resp.Rcode)
			}
			if !resp.Authoritative {
				t.Error("got no AA bit, want one from the authoritative server")
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want 1: %v", len(resp.Answer), resp.Answer)
			}
			if got, want := resp.Answer[0].String(), "192.0.2.1"; !strings.Contains(got, want) {
				t.Errorf("got answer %q, want it to carry %q", got, want)
			}
			if rtt <= 0 || rtt > time.Second {
				t.Errorf("got rtt %v, want a small positive duration", rtt)
			}

			queries := server.Queries()
			if len(queries) != 1 {
				t.Fatalf("got %d queries, want 1", len(queries))
			}
			if queries[0].Proto != test.proto {
				t.Errorf("server saw proto %q, want %q", queries[0].Proto, test.proto)
			}
			if queries[0].Name != "www.example.com." || queries[0].Type != dns.TypeA {
				t.Errorf("server saw %s %d, want www.example.com. A", queries[0].Name, queries[0].Type)
			}
		})
	}
}

// TestExchangeTruncated covers TC detection and the retry the resolver will
// make over TCP.
func TestExchangeTruncated(t *testing.T) {
	server := newServer(t, fakens.Behaviour{TruncateUDP: true})

	resp, _, err := transport.NewUDP(fastConfig).Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), server.Addr, "")
	if err != nil {
		t.Fatalf("Exchange over UDP: %v", err)
	}
	if !resp.Truncated {
		t.Error("got no TC bit over UDP, want one")
	}
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers in a truncated reply, want none", len(resp.Answer))
	}

	resp, _, err = transport.NewTCP(fastConfig).Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), server.Addr, "")
	if err != nil {
		t.Fatalf("Exchange over TCP: %v", err)
	}
	if resp.Truncated {
		t.Error("got a TC bit over TCP, want none")
	}
	if len(resp.Answer) != 1 {
		t.Errorf("got %d answers over TCP, want 1", len(resp.Answer))
	}
}

func TestExchangeTimeout(t *testing.T) {
	server := newServer(t, fakens.Behaviour{Drop: true})

	_, rtt, err := transport.NewUDP(fastConfig).Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), server.Addr, "")
	if err == nil {
		t.Fatal("got no error from a silent server, want one")
	}
	if !transport.IsTimeout(err) {
		t.Errorf("got error %v, want a timeout", err)
	}
	if rtt < fastConfig.Timeout {
		t.Errorf("got rtt %v, want at least the %v timeout", rtt, fastConfig.Timeout)
	}
}

func TestExchangeRcodes(t *testing.T) {
	tests := map[string]struct {
		behaviour fakens.Behaviour
		name      string
		rcode     uint16
		wantAA    bool
	}{
		"refused":       {behaviour: fakens.Behaviour{Refuse: true}, name: "www.example.com.", rcode: dns.RcodeRefused},
		"lame":          {behaviour: fakens.Behaviour{Lame: true}, name: "www.example.com.", rcode: dns.RcodeSuccess},
		"nxdomain":      {name: "nothing.example.com.", rcode: dns.RcodeNameError, wantAA: true},
		"out of zone":   {name: "www.example.org.", rcode: dns.RcodeRefused},
		"answer exists": {name: "www.example.com.", rcode: dns.RcodeSuccess, wantAA: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := newServer(t, test.behaviour)

			resp, _, err := transport.NewUDP(fastConfig).Exchange(t.Context(), query(t, test.name, dns.TypeA), server.Addr, "")
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if resp.Rcode != test.rcode {
				t.Errorf("got rcode %d, want %d", resp.Rcode, test.rcode)
			}
			if resp.Authoritative != test.wantAA {
				t.Errorf("got AA %v, want %v", resp.Authoritative, test.wantAA)
			}
		})
	}
}

func TestExchangeEDNS(t *testing.T) {
	server := newServer(t, fakens.Behaviour{})

	req, err := transport.NewQuery("www.example.com.", dns.TypeA, transport.DefaultUDPSize, true)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	resp, _, err := transport.NewUDP(fastConfig).Exchange(t.Context(), req, server.Addr, "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !resp.Security {
		t.Error("got no DO bit in the reply, want one")
	}

	queries := server.Queries()
	if len(queries) != 1 {
		t.Fatalf("got %d queries, want 1", len(queries))
	}
	if queries[0].UDPSize != transport.DefaultUDPSize {
		t.Errorf("server saw a buffer of %d, want %d", queries[0].UDPSize, transport.DefaultUDPSize)
	}
	if !queries[0].DO {
		t.Error("server saw no DO bit, want one")
	}
}

// TestExchangeFormErrEDNS covers the server that cannot parse EDNS0 at all, the
// case the resolver answers by retrying without it.
func TestExchangeFormErrEDNS(t *testing.T) {
	server := newServer(t, fakens.Behaviour{FormErrEDNS: true})
	tr := transport.NewUDP(fastConfig)

	req, err := transport.NewQuery("www.example.com.", dns.TypeA, transport.DefaultUDPSize, false)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	resp, _, err := tr.Exchange(t.Context(), req, server.Addr, "")
	if err != nil {
		t.Fatalf("Exchange with EDNS0: %v", err)
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("got rcode %d for an EDNS0 query, want FORMERR", resp.Rcode)
	}

	if req, err = transport.NewQuery("www.example.com.", dns.TypeA, 0, false); err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	if resp, _, err = tr.Exchange(t.Context(), req, server.Addr, ""); err != nil {
		t.Fatalf("Exchange without EDNS0: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("got rcode %d without EDNS0, want NOERROR", resp.Rcode)
	}
}

func TestExchangeIPv6(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this machine: %v", err)
	}
	listener.Close()

	server := fakens.New(t, fakens.Config{Origin: "example.com.", Zone: zone, Host: "::1"})
	if server.Addr.Addr().Is4() {
		t.Fatalf("got an IPv4 server at %s, want IPv6", server.Addr)
	}

	resp, _, err := transport.NewUDP(fastConfig).Exchange(t.Context(), query(t, "www.example.com.", dns.TypeAAAA), server.Addr, "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
}

func TestExchangeBadServer(t *testing.T) {
	tests := map[string]netip.AddrPort{
		"zero value": {},
		"no port":    netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
	}

	for name, server := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := transport.NewUDP(fastConfig).Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), server, ""); err == nil {
				t.Error("got no error, want one")
			}
		})
	}
}

func TestExchangeExpiredContext(t *testing.T) {
	server := newServer(t, fakens.Behaviour{})

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()

	if _, _, err := transport.NewUDP(fastConfig).Exchange(ctx, query(t, "www.example.com.", dns.TypeA), server.Addr, ""); err == nil {
		t.Error("got no error from an expired context, want one")
	}
	if got := len(server.Queries()); got != 0 {
		t.Errorf("got %d queries, want none to have left", got)
	}
}

func TestNewQuery(t *testing.T) {
	req, err := transport.NewQuery("example.com", dns.TypeNS, transport.DefaultUDPSize, true)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	if req.RecursionDesired {
		t.Error("got RD set, want it clear for an iterative query")
	}
	if !req.Security || req.UDPSize != transport.DefaultUDPSize {
		t.Errorf("got DO %v and buffer %d, want true and %d", req.Security, req.UDPSize, transport.DefaultUDPSize)
	}
	if got := req.Question[0].Header().Name; got != "example.com." {
		t.Errorf("got question %q, want it made fully qualified", got)
	}

	if _, err = transport.NewQuery("example.com.", 0, 0, false); err == nil {
		t.Error("got no error for an unknown type, want one")
	}
}

func newServer(tb testing.TB, behaviour fakens.Behaviour) *fakens.Server {
	tb.Helper()
	return fakens.New(tb, fakens.Config{Origin: "example.com.", Zone: zone, Behaviour: behaviour})
}

func query(tb testing.TB, name string, qtype uint16) *dns.Msg {
	tb.Helper()
	req, err := transport.NewQuery(name, qtype, 0, false)
	if err != nil {
		tb.Fatalf("NewQuery: %v", err)
	}
	return req
}
