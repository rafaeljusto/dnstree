package transport_test

import (
	"errors"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

func TestPublic(t *testing.T) {
	tests := map[string]struct {
		addr string
		want bool
	}{
		"a root server":                     {"198.41.0.4", true},
		"a root server over IPv6":           {"2001:503:ba3e::2:30", true},
		"loopback":                          {"127.0.0.1", false},
		"loopback over IPv6":                {"::1", false},
		"a private network":                 {"10.1.2.3", false},
		"another private network":           {"192.168.0.1", false},
		"carrier-grade NAT":                 {"100.64.0.1", false},
		"the metadata service of a cloud":   {"169.254.169.254", false},
		"the documentation range":           {"192.0.2.1", false},
		"a unique local IPv6 address":       {"fd00::1", false},
		"a link-local IPv6 address":         {"fe80::1", false},
		"loopback mapped into IPv6":         {"::ffff:127.0.0.1", false},
		"a private network behind NAT64":    {"64:ff9b::a00:1", false},
		"a private network behind 6to4":     {"2002:a00:1::1", false},
		"nothing at all":                    {"0.0.0.0", false},
		"the broadcast address":             {"255.255.255.255", false},
		"multicast":                         {"224.0.0.251", false},
		"a public address mapped into IPv6": {"::ffff:198.41.0.4", true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := transport.Public(netip.MustParseAddr(test.addr)); got != test.want {
				t.Errorf("Public(%s) = %t, want %t", test.addr, got, test.want)
			}
		})
	}
}

func TestGuard(t *testing.T) {
	server := newServer(t, fakens.Behaviour{})
	allowed := server.Addr.Addr()
	guarded := transport.Guard(transport.NewUDP(fastConfig), func(addr netip.Addr) bool { return addr == allowed })

	if _, _, err := guarded.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), server.Addr, ""); err != nil {
		t.Fatalf("got %v, want the allowed address asked", err)
	}

	elsewhere := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), server.Addr.Port())
	_, _, err := guarded.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), elsewhere, "")
	if !errors.Is(err, transport.ErrNotAllowed) {
		t.Fatalf("got %v, want %v", err, transport.ErrNotAllowed)
	}
	if got := len(server.Queries()); got != 1 {
		t.Errorf("got %d queries at the server, want only the allowed one", got)
	}
}
