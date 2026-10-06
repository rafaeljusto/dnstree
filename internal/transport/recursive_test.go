package transport_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

const recursiveZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    127.0.0.1
www   IN A    192.0.2.10
`

func TestAsk(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "test.", Zone: recursiveZone})
	carrier := transport.NewUDP(transport.Config{})

	answer, err := transport.Ask(t.Context(), carrier, server.Addr,
		trace.Question{Name: "www.test", Type: "A", Class: "IN"}, false, netip.Prefix{})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}

	if answer.Rcode != "NOERROR" {
		t.Errorf("got %s, want NOERROR", answer.Rcode)
	}
	if answer.Err != "" {
		t.Errorf("got error %q, want the server to have answered", answer.Err)
	}
	if answer.Elapsed <= 0 {
		t.Errorf("got %s, want a round trip that was measured", answer.Elapsed)
	}
	if answer.Server.IP != server.Addr.Addr() {
		t.Errorf("got %s, want the server that was asked", answer.Server.IP)
	}
}

// TestAskSilent covers the resolver being the thing that is broken, which says
// nothing about the walk and so is reported rather than returned as an error.
func TestAskSilent(t *testing.T) {
	carrier := transport.NewUDP(transport.Config{Timeout: 200 * time.Millisecond})

	// Port 1 is reserved and nothing answers there.
	answer, err := transport.Ask(t.Context(), carrier, netip.MustParseAddrPort("127.0.0.1:1"),
		trace.Question{Name: "www.test", Type: "A", Class: "IN"}, false, netip.Prefix{})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if answer.Err == "" {
		t.Errorf("got %+v, want the silence carried in the result", answer)
	}
}

// TestRecheck covers asking again with checking disabled, which is what tells
// a resolver that failed validation from one that could not get an answer.
func TestRecheck(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "test.", Zone: recursiveZone,
		Behaviour: fakens.Behaviour{ServFailUnlessCD: true}})
	carrier := transport.NewUDP(transport.Config{})
	question := trace.Question{Name: "www.test", Type: "A", Class: "IN"}

	first, err := transport.Ask(t.Context(), carrier, server.Addr, question, true, netip.Prefix{})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if first.Rcode != "SERVFAIL" {
		t.Fatalf("got %s, want SERVFAIL from a resolver that fails validation", first.Rcode)
	}

	again, err := transport.Recheck(t.Context(), carrier, server.Addr, question, true, netip.Prefix{})
	if err != nil {
		t.Fatalf("Recheck: %v", err)
	}
	if again.Rcode != "NOERROR" || len(again.Records) == 0 {
		t.Errorf("got %s with %v, want the answer it held back", again.Rcode, again.Records)
	}

	queries := server.Queries()
	if len(queries) != 2 || queries[0].CD || !queries[1].CD {
		t.Errorf("got %+v, want checking disabled on the second query alone", queries)
	}
}

func TestAskUnknownType(t *testing.T) {
	carrier := transport.NewUDP(transport.Config{})
	if _, err := transport.Ask(t.Context(), carrier, netip.MustParseAddrPort("127.0.0.1:53"),
		trace.Question{Name: "www.test", Type: "NONSENSE", Class: "IN"}, false, netip.Prefix{}); err == nil {
		t.Error("got no error, want a question that cannot be asked")
	}
}

func TestSystemFrom(t *testing.T) {
	tests := map[string]struct {
		file string
		want netip.AddrPort
	}{
		"the first server named": {
			file: "search example.com\nnameserver 192.0.2.1\nnameserver 192.0.2.2\n",
			want: netip.MustParseAddrPort("192.0.2.1:53"),
		},
		"a name is not an address": {
			file: "nameserver resolver.example.com\n",
		},
		"nothing at all": {file: "search example.com\n"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if err := os.WriteFile(path, []byte(test.file), 0o600); err != nil {
				t.Fatalf("writing the file: %v", err)
			}
			if got := transport.SystemFrom(path); got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}

	if got := transport.SystemFrom(filepath.Join(t.TempDir(), "missing")); got.IsValid() {
		t.Errorf("got %v, want nothing from a host that keeps no such file", got)
	}
}

// ddrZone is a resolver designating itself the way the public ones do: over
// TLS, over HTTPS at a path, and once with an ALPN that names no transport.
// The last four are records no client can use: AliasMode, a key it must
// understand and cannot, a target that is the owner name, and no ALPN at all.
const ddrZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    127.0.0.1
_dns  IN SVCB 1 dns.test. alpn=dot port=853 ipv4hint=192.0.2.53
_dns  IN SVCB 2 dns.test. alpn=h2,h3 dohpath=/dns-query{?dns}
_dns  IN SVCB 3 dns.test. alpn=h2
_dns  IN SVCB 0 elsewhere.test.
_dns  IN SVCB 4 dns.test. mandatory=key65000 alpn=dot key65000=x
_dns  IN SVCB 5 . alpn=dot
_dns  IN SVCB 6 dns.test. port=853
`

func TestDiscover(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "resolver.arpa.", Zone: ddrZone})
	carrier := transport.NewUDP(transport.Config{})

	found := transport.Discover(t.Context(), carrier, nil, server.Addr)
	if found.Err != "" || found.Rcode != "NOERROR" {
		t.Fatalf("got %+v, want the server to have answered", found)
	}

	byPriority := map[uint16]trace.Designated{}
	for _, offer := range found.Designated {
		byPriority[offer.Priority] = offer
	}
	if len(byPriority) != 3 {
		t.Fatalf("got %d offers, want the three in ServiceMode: %+v", len(byPriority), found.Designated)
	}

	dot := byPriority[1]
	if !slices.Equal(dot.Protocols, []string{"dot"}) || dot.Port != 853 || dot.Target != "dns.test." {
		t.Errorf("got %+v, want dot at dns.test.:853", dot)
	}
	if !slices.Equal(dot.Hints, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
		t.Errorf("got hints %v, want the address the record gave", dot.Hints)
	}
	if doh := byPriority[2]; !slices.Equal(doh.Protocols, []string{"doh"}) || doh.DoHPath != "/dns-query{?dns}" {
		t.Errorf("got %+v, want doh at its path", doh)
	}
	// HTTP with nowhere to send the query is not a DoH offer (RFC 9461).
	if bare := byPriority[3]; len(bare.Protocols) != 0 || !slices.Equal(bare.ALPN, []string{"h2"}) {
		t.Errorf("got %+v, want the ALPN kept and no protocol read into it", bare)
	}
}

// TestDiscoverNothing covers a resolver that answers and designates nothing,
// which is the common case and is not a failure.
func TestDiscoverNothing(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "test.", Zone: recursiveZone})
	carrier := transport.NewUDP(transport.Config{})

	found := transport.Discover(t.Context(), carrier, nil, server.Addr)
	if found.Err != "" || len(found.Designated) != 0 || found.Rcode == "" {
		t.Errorf("got %+v, want an rcode and no offers", found)
	}
}

func TestDiscoverSilent(t *testing.T) {
	carrier := transport.NewUDP(transport.Config{Timeout: 200 * time.Millisecond})
	if found := transport.Discover(t.Context(), carrier, nil, netip.MustParseAddrPort("127.0.0.1:1")); found.Err == "" {
		t.Errorf("got %+v, want the silence carried in the result", found)
	}
}

// TestDiscoverTruncated covers an answer too big for a datagram. Read as it
// came, the offers that did not fit would be offers never made, so it is asked
// again over TCP, and without TCP it says it could not tell.
func TestDiscoverTruncated(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "resolver.arpa.", Zone: ddrZone,
		Behaviour: fakens.Behaviour{TruncateUDP: true}})
	carrier := transport.NewUDP(transport.Config{})

	found := transport.Discover(t.Context(), carrier, transport.NewTCP(transport.Config{}), server.Addr)
	if found.Err != "" || len(found.Designated) != 3 {
		t.Errorf("got %+v, want the three offers asked again over tcp", found)
	}

	found = transport.Discover(t.Context(), carrier, nil, server.Addr)
	if found.Err == "" || len(found.Designated) != 0 {
		t.Errorf("got %+v, want the truncation said rather than read as no offers", found)
	}
}

// TestLookupTruncated covers a policy too long for a datagram, which is asked
// again over TCP rather than read short.
func TestLookupTruncated(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "example.test.", Zone: `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    127.0.0.1
@     IN TXT  "v=spf1 include:_spf.example.test -all"
`, Behaviour: fakens.Behaviour{TruncateUDP: true}})
	carrier := transport.NewUDP(transport.Config{})

	got, err := transport.Lookup(t.Context(), carrier, transport.NewTCP(transport.Config{}), server.Addr, "example.test.", "TXT", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Err != "" || len(got.Records) != 1 || got.Records[0].Data != `"v=spf1 include:_spf.example.test -all"` {
		t.Errorf("got %+v, want the policy asked again over tcp", got)
	}
}

// silent is a carrier whose answers never arrive, the way a datagram too big
// for something on the path is dropped.
type silent struct{ asked int }

func (s *silent) Proto() string { return transport.ProtoUDP }
func (s *silent) Port() uint16  { return 53 }
func (s *silent) Exchange(context.Context, *dns.Msg, netip.AddrPort, string) (*dns.Msg, time.Duration, error) {
	s.asked++
	return nil, 0, context.DeadlineExceeded
}

// TestLookupSilent covers a resolver whose answer never arrives over UDP: it is
// asked again as many times as retries allows, and then over TCP.
func TestLookupSilent(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "example.test.", Zone: `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    127.0.0.1
@     IN TXT  "v=spf1 -all"
`})
	carrier := &silent{}
	got, err := transport.Lookup(t.Context(), carrier, transport.NewTCP(transport.Config{}), server.Addr, "example.test.", "TXT", 1)
	if err != nil {
		t.Fatal(err)
	}
	if carrier.asked != 2 || got.Err != "" || len(got.Records) != 1 {
		t.Errorf("asked %d times over udp, got %+v; want 2, then the answer over tcp", carrier.asked, got)
	}

	carrier = &silent{}
	got, _ = transport.Lookup(t.Context(), carrier, nil, server.Addr, "example.test.", "TXT", 0)
	if carrier.asked != 1 || got.Err == "" {
		t.Errorf("asked %d times, got %+v; want once, and the silence said", carrier.asked, got)
	}
}
