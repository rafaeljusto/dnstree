package fakens_test

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// tldZone delegates example.com. and keeps an address for a nameserver it has
// no business handing out.
const tldZone = `
@                  IN SOA  a.gtld-servers.net. hostmaster 1 7200 3600 1209600 3600
@                  IN NS   a.gtld-servers.net.
a.gtld-servers.net. IN A   127.0.0.1
example            IN NS   ns.example
example            IN NS   ns2.outside.net.
ns.example         IN A    192.0.2.53
ns2.outside.net.   IN A    198.51.100.1
`

// leafZone has an empty non-terminal at b.example.com.
const leafZone = `
@       IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns1
ns1     IN A    127.0.0.1
www     IN A    192.0.2.1
a.b     IN A    192.0.2.2
`

func TestReferral(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "com.", Zone: tldZone})

	resp := exchange(t, server, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("got rcode %d, want NOERROR", resp.Rcode)
	}
	if resp.Authoritative {
		t.Error("got the AA bit on a referral, want it clear")
	}
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers on a referral, want none", len(resp.Answer))
	}
	if len(resp.Ns) != 2 {
		t.Fatalf("got %d NS records, want 2: %v", len(resp.Ns), resp.Ns)
	}
	if owner := resp.Ns[0].Header().Name; owner != "example.com." {
		t.Errorf("got a delegation of %q, want example.com.", owner)
	}

	// Only the in-bailiwick nameserver may come with glue.
	if len(resp.Extra) != 1 {
		t.Fatalf("got %d glue records, want 1: %v", len(resp.Extra), resp.Extra)
	}
	if owner := resp.Extra[0].Header().Name; owner != "ns.example.com." {
		t.Errorf("got glue for %q, want ns.example.com.", owner)
	}
}

// TestApexNSIsNotAReferral guards the zone cut rule: the NS set at the apex is
// the server's own, not a delegation.
func TestApexNSIsNotAReferral(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "com.", Zone: tldZone})

	resp := exchange(t, server, "com.", dns.TypeNS)
	if !resp.Authoritative {
		t.Error("got no AA bit, want one")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want the apex NS set", len(resp.Answer))
	}
}

func TestAnswerKinds(t *testing.T) {
	tests := map[string]struct {
		name      string
		qtype     uint16
		rcode     uint16
		answers   int
		authority int
	}{
		"answer":             {name: "www.example.com.", qtype: dns.TypeA, answers: 1},
		"nodata":             {name: "www.example.com.", qtype: dns.TypeAAAA, authority: 1},
		"empty non-terminal": {name: "b.example.com.", qtype: dns.TypeA, authority: 1},
		"nxdomain":           {name: "nope.example.com.", qtype: dns.TypeA, rcode: dns.RcodeNameError, authority: 1},
	}

	server := fakens.New(t, fakens.Config{Origin: "example.com.", Zone: leafZone})
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			resp := exchange(t, server, test.name, test.qtype)
			if resp.Rcode != test.rcode {
				t.Errorf("got rcode %d, want %d", resp.Rcode, test.rcode)
			}
			if !resp.Authoritative {
				t.Error("got no AA bit, want one")
			}
			if len(resp.Answer) != test.answers {
				t.Errorf("got %d answers, want %d", len(resp.Answer), test.answers)
			}
			if len(resp.Ns) != test.authority {
				t.Errorf("got %d authority records, want %d", len(resp.Ns), test.authority)
			}
			if test.authority > 0 && dns.RRToType(resp.Ns[0]) != dns.TypeSOA {
				t.Errorf("got %v in the authority section, want the SOA", resp.Ns[0])
			}
		})
	}
}

func TestDelay(t *testing.T) {
	const delay = 50 * time.Millisecond
	server := fakens.New(t, fakens.Config{
		Origin:    "example.com.",
		Zone:      leafZone,
		Behaviour: fakens.Behaviour{Delay: delay},
	})

	req, err := transport.NewQuery("www.example.com.", dns.TypeA, 0, false)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	_, rtt, err := transport.NewUDP(transport.Config{Timeout: time.Second}).Exchange(t.Context(), req, server.Addr, "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if rtt < delay {
		t.Errorf("got rtt %v, want at least the %v the server waited", rtt, delay)
	}
}

func TestQueries(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "example.com.", Zone: leafZone})

	exchange(t, server, "www.example.com.", dns.TypeA)
	exchange(t, server, "ns1.example.com.", dns.TypeAAAA)

	queries := server.Queries()
	if len(queries) != 2 {
		t.Fatalf("got %d queries, want 2", len(queries))
	}
	if queries[0].Name != "www.example.com." || queries[1].Type != dns.TypeAAAA {
		t.Errorf("got %+v, want them in the order they were asked", queries)
	}
}

func exchange(tb testing.TB, server *fakens.Server, name string, qtype uint16) *dns.Msg {
	tb.Helper()

	req, err := transport.NewQuery(name, qtype, 0, false)
	if err != nil {
		tb.Fatalf("NewQuery: %v", err)
	}
	resp, _, err := transport.NewUDP(transport.Config{Timeout: time.Second}).Exchange(tb.Context(), req, server.Addr, "")
	if err != nil {
		tb.Fatalf("Exchange: %v", err)
	}
	return resp
}
