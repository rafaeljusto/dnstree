package resolver_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// A zone whose two nameservers are named in another zone and come with no glue,
// under a net. served by two servers: the shape of most zones hosted by a DNS
// provider, and the one where a walk has to look its nameservers up first.
const (
	outsideRootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
net.                IN NS   ns1.net.
net.                IN NS   ns2.net.
ns1.net.            IN A    192.0.2.6
ns2.net.            IN A    192.0.2.8
test.               IN NS   ns1.host.net.
test.               IN NS   ns2.host.net.
`
	outsideNetZone = `
@        IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@        IN NS   ns1
@        IN NS   ns2
ns1      IN A    192.0.2.6
ns2      IN A    192.0.2.8
host     IN NS   ns.host
ns.host  IN A    192.0.2.20
`
	outsideHostZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.20
ns1   IN A    192.0.2.21
ns2   IN A    192.0.2.22
`
	outsideTestZone = `
@     IN SOA  ns1.host.net. hostmaster 7 7200 3600 1209600 3600
@     IN NS   ns1.host.net.
@     IN NS   ns2.host.net.
www   IN A    192.0.2.10
`
)

func outside(tb testing.TB) harness {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: outsideRootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns1.net.", Origin: "net.", Zone: outsideNetZone, Declared: "192.0.2.6"})
	hierarchy.Add(fakens.Config{Name: "ns2.net.", Origin: "net.", Zone: outsideNetZone, Declared: "192.0.2.8"})
	hierarchy.Add(fakens.Config{Name: "ns.host.net.", Origin: "host.net.", Zone: outsideHostZone, Declared: "192.0.2.20"})
	hierarchy.Add(fakens.Config{Name: "ns1.host.net.", Origin: "test.", Zone: outsideTestZone, Declared: "192.0.2.21"})
	hierarchy.Add(fakens.Config{Name: "ns2.host.net.", Origin: "test.", Zone: outsideTestZone, Declared: "192.0.2.22"})
	return harness{hierarchy, root}
}

// TestProbesReachNameserversNotLookedUp covers the sweeps that are about every
// nameserver of a zone. A walk looks up the first nameserver named outside the
// zone and goes on as soon as it has an address, so the sweep has to look up
// the rest itself, or it quietly checks one server of two.
func TestProbesReachNameserversNotLookedUp(t *testing.T) {
	t.Parallel()

	tests := map[string]resolver.Config{
		"the serial sweep asks both":    {Serial: true},
		"the recursion probe asks both": {CheckRecursion: true},
		"the transfer probe asks both":  {CheckTransfer: true},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			h := outside(t)
			cfg.TCP = h.carry(transport.NewTCP(fast))
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if tr.Result() == nil {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}

			probed := map[string]bool{}
			for step := range tr.Steps() {
				if step.Aside && step.Zone == "test." && step.Server.IP.IsValid() {
					probed[step.Server.IP.String()] = true
				}
			}
			for _, addr := range []string{"192.0.2.21", "192.0.2.22"} {
				if !probed[addr] {
					t.Errorf("got %v probed, want %s among them: %s", probed, addr, format(steps(tr)))
				}
			}
		})
	}
}

// TestAllLooksNameserversUpOnce covers what --all fans out over. It is about
// the nameservers of the zones on the way to the question; the lookup of a
// nameserver's address is a means to that, and asking every server of every
// zone above it spent a budget of 256 queries before a zone hosted on seven
// providers' nameservers was asked at all.
func TestAllLooksNameserversUpOnce(t *testing.T) {
	t.Parallel()

	tr, err := newResolver(t, outside(t), resolver.Config{All: true}).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Result() == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}

	var net, test int
	for _, step := range steps(tr) {
		if step.Kind == trace.KindSkipped {
			continue
		}
		switch step.Zone {
		case "net.":
			net++
		case "test.":
			test++
		}
	}
	if test != 2 {
		t.Errorf("got %d hops in test., want both of its nameservers asked: %s", test, format(steps(tr)))
	}
	// One lookup per nameserver name, each asking one server of net.
	if net != 2 {
		t.Errorf("got %d hops in net., want one for each of the two lookups: %s", net, format(steps(tr)))
	}
}

// TestSpentBudgetBlamesNoServer covers the warnings a walk gives when a zone
// goes unasked. Once the budget has run out, every server left is one nobody
// asked, and saying none of them answered sends somebody after servers that
// would have.
func TestSpentBudgetBlamesNoServer(t *testing.T) {
	t.Parallel()

	// The walk takes five: the root, then the root, net. and host.net. for
	// the address of ns1.host.net., then test. Every budget short of that runs
	// out somewhere along it.
	for budget := 1; budget < 5; budget++ {
		cfg := resolver.Config{Budget: resolver.Budget{MaxQueries: budget}}
		tr, err := newResolver(t, outside(t), cfg).Resolve(t.Context(), "www.test", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if tr.Result() != nil {
			continue
		}
		for _, text := range []string{"no server answered", "no usable address"} {
			if warned(tr, text) {
				t.Errorf("with %d queries got %q, want the budget blamed, not the servers", budget, tr.Warnings)
			}
		}
	}
}

// TestSweepStopsAtTheBudget covers a referral naming hundreds of nameservers
// outside the zone, each a walk of its own for the sweeps that look them all
// up. Once the budget is spent the walks ask nothing, and one saying it gave
// up is all the tree needs: the rest are lines a hostile zone chose to add.
func TestSweepStopsAtTheBudget(t *testing.T) {
	t.Parallel()

	var root, test strings.Builder
	root.WriteString(strings.Replace(outsideRootZone, "test.               IN NS   ns2.host.net.\n", "", 1))
	test.WriteString(outsideTestZone)
	for i := 3; i <= 200; i++ {
		fmt.Fprintf(&root, "test. IN NS ns%d.host.net.\n", i)
	}

	hierarchy := fakens.NewHierarchy(t)
	top := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: root.String(), Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns1.net.", Origin: "net.", Zone: outsideNetZone, Declared: "192.0.2.6"})
	hierarchy.Add(fakens.Config{Name: "ns2.net.", Origin: "net.", Zone: outsideNetZone, Declared: "192.0.2.8"})
	hierarchy.Add(fakens.Config{Name: "ns.host.net.", Origin: "host.net.", Zone: outsideHostZone, Declared: "192.0.2.20"})
	hierarchy.Add(fakens.Config{Name: "ns1.host.net.", Origin: "test.", Zone: test.String(), Declared: "192.0.2.21"})
	h := harness{hierarchy, top}

	const budget = 30
	cfg := resolver.Config{Serial: true, Budget: resolver.Budget{MaxQueries: budget}}
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Result() == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}
	var walks int
	for step := range tr.Steps() {
		for _, note := range step.Notes {
			if strings.HasPrefix(note, "resolving ") {
				walks++
			}
		}
	}
	if walks > budget {
		t.Errorf("got %d nameserver walks on a budget of %d queries, want none past it", walks, budget)
	}
}
