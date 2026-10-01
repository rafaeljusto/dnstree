package resolver_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// TestWithout covers --without: the walk treats what it names as down and
// goes wherever it would go next, and nothing it names is ever asked.
func TestWithout(t *testing.T) {
	const comZone = `
@               IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@               IN NS   ns
ns              IN A    192.0.2.2
example         IN NS   ns1.example
example         IN NS   ns2.example
ns1.example     IN A    198.51.100.3
ns2.example     IN A    198.51.100.4
`
	const exampleZone = `
@     IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns1
@     IN NS   ns2
ns1   IN A    198.51.100.3
ns2   IN A    198.51.100.4
www   IN A    192.0.2.10
`

	newHierarchy := func(tb testing.TB) (harness, *fakens.Server, *fakens.Server) {
		hierarchy := fakens.NewHierarchy(tb)
		root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
		hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
		ns1 := hierarchy.Add(fakens.Config{Name: "ns1.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "198.51.100.3"})
		ns2 := hierarchy.Add(fakens.Config{Name: "ns2.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "198.51.100.4"})
		return harness{hierarchy, root}, ns1, ns2
	}

	tests := map[string]struct {
		down     []transport.Down
		answered bool
		left     []string // the servers drawn as left out
	}{
		"one nameserver by name, and the other answers": {
			down:     []transport.Down{{Name: "ns1.example.com."}},
			answered: true,
			left:     []string{"ns1.example.com."},
		},
		"one nameserver by address, and the other answers": {
			down:     []transport.Down{{Prefix: netip.MustParsePrefix("198.51.100.3/32")}},
			answered: true,
			left:     []string{"ns1.example.com."},
		},
		"both nameservers inside one network": {
			down: []transport.Down{{Prefix: netip.MustParsePrefix("198.51.100.0/24")}},
			left: []string{"ns1.example.com.", "ns2.example.com."},
		},
		"both nameservers by name": {
			down: []transport.Down{{Name: "ns1.example.com."}, {Name: "ns2.example.com."}},
			left: []string{"ns1.example.com.", "ns2.example.com."},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h, ns1, ns2 := newHierarchy(t)
			tr, err := newResolver(t, h, outage(h, test.down)).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			if got := tr.Result() != nil; got != test.answered {
				t.Fatalf("got an answer %t, want %t: %s", got, test.answered, format(steps(tr)))
			}

			left := make(map[string]int)
			for _, step := range steps(tr) {
				if slices.ContainsFunc(step.Notes, func(note string) bool { return strings.HasPrefix(note, "left out by --without") }) {
					if step.Kind != trace.KindSkipped {
						t.Errorf("got a %s hop for %s, want it never asked", step.Kind, step.Server.Name)
					}
					left[step.Server.Name]++
				}
			}
			for _, server := range test.left {
				if left[server] != 1 {
					t.Errorf("got %d hops to %s saying it was left out, want one: %s", left[server], server, format(steps(tr)))
				}
			}

			for _, server := range []*fakens.Server{ns1, ns2} {
				named := server.Nameserver()
				for _, down := range test.down {
					if (down.Name == named.Name || down.Prefix.Contains(named.IP)) && len(server.Queries()) > 0 {
						t.Errorf("got %d queries at %s, which was left out", len(server.Queries()), named.Name)
					}
				}
			}
		})
	}
}

// TestWithoutProbe asks every nameserver of the zone for its serial. The walk
// skips what is down before it asks, but a probe goes to every nameserver the
// zone names, so the transport has to keep it from the one left out.
func TestWithoutProbe(t *testing.T) {
	const comZone = `
@               IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@               IN NS   ns
ns              IN A    192.0.2.2
example         IN NS   ns1.example
example         IN NS   ns2.example
ns1.example     IN A    198.51.100.3
ns2.example     IN A    198.51.100.4
`
	const exampleZone = `
@     IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns1
@     IN NS   ns2
ns1   IN A    198.51.100.3
ns2   IN A    198.51.100.4
www   IN A    192.0.2.10
`
	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	ns1 := hierarchy.Add(fakens.Config{Name: "ns1.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "198.51.100.3"})
	hierarchy.Add(fakens.Config{Name: "ns2.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "198.51.100.4"})
	h := harness{hierarchy, root}

	cfg := outage(h, []transport.Down{{Name: "ns1.example.com."}})
	cfg.Serial = true
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Result() == nil {
		t.Fatalf("got no answer, want ns2.example.com.'s: %s", format(steps(tr)))
	}
	if got := len(ns1.Queries()); got > 0 {
		t.Errorf("got %d queries at ns1.example.com., which was left out: %s", got, format(steps(tr)))
	}
}

// outage is the walk --without makes: the servers inside down skipped before
// they are asked, and the transports kept from them for everything else.
func outage(h harness, down []transport.Down) resolver.Config {
	carry := func(inner transport.Transport) transport.Transport {
		return transport.Without(h.carry(inner), down, nil)
	}
	return resolver.Config{
		Transport: carry(transport.NewUDP(fast)),
		TCP:       carry(transport.NewTCP(fast)),
		Down: func(server trace.Server) string {
			for _, part := range down {
				if part.Covers(server.IP, server.Name) {
					return "left out by --without " + part.String()
				}
			}
			return ""
		},
	}
}

// TestWithoutHiddenDependency is the redundancy that is not there: the second
// nameserver sits with another provider, but its own zone is served from the
// first one's address, so taking that address away takes both.
func TestWithoutHiddenDependency(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
net.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
`
	const comZone = `
@           IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@           IN NS   ns
ns          IN A    192.0.2.2
example     IN NS   ns1.example
example     IN NS   ns.example.net.
ns1.example IN A    198.51.100.3
`
	const netZone = `
@           IN SOA  ns.com. hostmaster 1 7200 3600 1209600 3600
@           IN NS   ns.com.
example     IN NS   ns1.example.com.
`
	const exampleNetZone = `
@     IN SOA  ns1.example.com. hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns1.example.com.
ns    IN A    203.0.113.6
`
	const exampleZone = `
@     IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns1
@     IN NS   ns.example.net.
ns1   IN A    198.51.100.3
www   IN A    192.0.2.10
`

	newHierarchy := func(tb testing.TB) harness {
		hierarchy := fakens.NewHierarchy(tb)
		root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
		hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
		hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "net.", Zone: netZone, Declared: "192.0.2.2"})
		hierarchy.Add(fakens.Config{Name: "ns1.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "198.51.100.3"})
		hierarchy.Add(fakens.Config{Name: "ns1.example.com.", Origin: "example.net.", Zone: exampleNetZone, Declared: "198.51.100.3"})
		hierarchy.Add(fakens.Config{Name: "ns.example.net.", Origin: "example.com.", Zone: exampleZone, Declared: "203.0.113.6"})
		return harness{hierarchy, root}
	}

	t.Run("with everything up, the other provider answers", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if tr.Result() == nil {
			t.Fatalf("got no answer, want one: %s", format(steps(tr)))
		}
	})

	t.Run("without the first provider, nobody can find the second", func(t *testing.T) {
		h := newHierarchy(t)
		down := []transport.Down{{Prefix: netip.MustParsePrefix("198.51.100.3/32")}}
		tr, err := newResolver(t, h, outage(h, down)).Resolve(t.Context(), "www.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if tr.Result() != nil {
			t.Fatalf("got an answer, want none: the only way to ns.example.net. is through 198.51.100.3: %s",
				format(steps(tr)))
		}
		var looked bool
		for _, step := range steps(tr) {
			looked = looked || step.Zone == "net."
		}
		if !looked {
			t.Errorf("got no walk down net., want ns.example.net. looked for before giving up: %s", format(steps(tr)))
		}
	})
}
