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
	t.Parallel()

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
		"loopback compatible with IPv6":     {"::127.0.0.1", false},
		"loopback translated by SIIT":       {"::ffff:0:127.0.0.1", false},
		"a private network behind Teredo":   {"2001:0:a00:1::1", false},
		"a site-local IPv6 address":         {"fec0::1", false},
		"the 6to4 relays":                   {"192.88.99.1", false},
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
	t.Parallel()

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

func TestWithout(t *testing.T) {
	t.Parallel()

	server := newServer(t, fakens.Behaviour{})
	addr := server.Addr.Addr()

	tests := map[string]struct {
		down    transport.Down
		name    string
		removed bool
	}{
		"the server by its name": {
			down: transport.Down{Name: "ns1.example.com."}, name: "ns1.example.com.", removed: true,
		},
		"the server by its name in another case and without the dot": {
			down: transport.Down{Name: "ns1.example.com"}, name: "NS1.Example.COM.", removed: true,
		},
		"another server by name": {
			down: transport.Down{Name: "ns2.example.com."}, name: "ns1.example.com.",
		},
		"a name where the server's is not known": {
			down: transport.Down{Name: "ns1.example.com."},
		},
		"the server by its address": {
			down: transport.Down{Prefix: netip.PrefixFrom(addr, addr.BitLen())}, removed: true,
		},
		"the network the server is in": {
			down: transport.Down{Prefix: netip.MustParsePrefix("127.0.0.0/8")}, removed: true,
		},
		"another network": {
			down: transport.Down{Prefix: netip.MustParsePrefix("192.0.2.0/24")},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			before := len(server.Queries())
			var kept []transport.Down
			down := transport.Without(transport.NewUDP(fastConfig), []transport.Down{test.down},
				func(down transport.Down) { kept = append(kept, down) })
			_, _, err := down.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), server.Addr, test.name)

			if test.removed != (len(kept) == 1) {
				t.Errorf("got %v kept from the query, want it only when the server is left out", kept)
			}
			if test.removed {
				if !errors.Is(err, transport.ErrDown) {
					t.Fatalf("got %v, want %v", err, transport.ErrDown)
				}
				if got := len(server.Queries()) - before; got != 0 {
					t.Errorf("got %d queries at the server, want none", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("got %v, want the server asked", err)
			}
		})
	}
}

func TestWithoutMapped(t *testing.T) {
	t.Parallel()

	server := newServer(t, fakens.Behaviour{})
	mapped := netip.AddrPortFrom(netip.AddrFrom16(server.Addr.Addr().As16()), server.Addr.Port())
	down := transport.Without(transport.NewUDP(fastConfig), []transport.Down{{Prefix: netip.MustParsePrefix("127.0.0.0/8")}}, nil)

	_, _, err := down.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), mapped, "")
	if !errors.Is(err, transport.ErrDown) {
		t.Fatalf("got %v, want an IPv4 address mapped into IPv6 held to its IPv4 prefix", err)
	}
}
