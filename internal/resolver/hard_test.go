package resolver_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/resolver"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// TestTruncated covers the TC bit: the answer did not fit, so it has to be
// fetched again over TCP.
func TestTruncated(t *testing.T) {
	newHierarchy := func(tb testing.TB) harness {
		hierarchy := fakens.NewHierarchy(tb)
		root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
		hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
		hierarchy.Add(fakens.Config{
			Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3",
			Behaviour: fakens.Behaviour{TruncateUDP: true},
		})
		return harness{hierarchy, root}
	}

	t.Run("retried over tcp", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{TCP: h.carry(transport.NewTCP(fast))}).
			Resolve(t.Context(), "www.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		answer := tr.Result()
		if answer == nil || answer.Kind != trace.KindAnswer {
			t.Fatalf("got %+v, want the answer TCP brought back: %s", answer, format(steps(tr)))
		}
		if answer.Proto != "tcp" {
			t.Errorf("got proto %s, want the hop to end up on tcp", answer.Proto)
		}
		if len(answer.Notes) != 1 || answer.Notes[0] != "truncated over udp" {
			t.Errorf("got notes %q, want the retry noted on the same hop", answer.Notes)
		}
		if answer.Flags.TC {
			t.Error("got the TC bit on the final answer, want the whole answer")
		}
		if len(answer.Records) != 1 {
			t.Errorf("got %d records, want the answer that did not fit in a datagram", len(answer.Records))
		}
	})

	t.Run("nothing to retry with", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		last := steps(tr)[len(steps(tr))-1]
		if !last.Flags.TC {
			t.Errorf("got %+v, want the truncation left visible", last)
		}
		if last.Proto != "udp" {
			t.Errorf("got proto %s, want it to stay on udp", last.Proto)
		}
	})
}

// TestEDNSFallback covers the server that cannot parse EDNS0 at all.
func TestEDNSFallback(t *testing.T) {
	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3",
		Behaviour: fakens.Behaviour{FormErrEDNS: true},
	})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{UDPSize: transport.DefaultUDPSize}).
		Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want the answer the second try brought: %s", answer, format(steps(tr)))
	}
	if len(answer.Notes) != 1 || answer.Notes[0] != "retried without EDNS0" {
		t.Errorf("got notes %q, want the fallback noted", answer.Notes)
	}
	if answer.Flags.EDNS {
		t.Error("got EDNS0 on the answer, want the one asked for without it")
	}
}

// TestCNAME covers the alias chase: a new walk from the root for the target,
// hanging under the answer that pointed at it.
func TestCNAME(t *testing.T) {
	const comZone = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
ns         IN A    192.0.2.2
example    IN NS   ns.example
ns.example IN A    192.0.2.3
target     IN NS   ns.target
ns.target  IN A    192.0.2.6
`
	const aliasZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.3
alias IN CNAME www.target.com.
loop  IN CNAME other.target.com.
`
	const targetZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.6
www   IN A    192.0.2.60
other IN CNAME loop.example.com.
`

	newHierarchy := func(tb testing.TB) harness {
		hierarchy := fakens.NewHierarchy(tb)
		root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
		hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
		hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: aliasZone, Declared: "192.0.2.3"})
		hierarchy.Add(fakens.Config{Name: "ns.target.com.", Origin: "target.com.", Zone: targetZone, Declared: "192.0.2.6"})
		return harness{hierarchy, root}
	}

	t.Run("chased to the end", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{}).Resolve(t.Context(), "alias.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(tr.Warnings) != 0 {
			t.Errorf("got warnings %q, want none", tr.Warnings)
		}

		answer := tr.Result()
		if answer == nil || answer.Kind != trace.KindAnswer {
			t.Fatalf("got %+v, want the A record of the target: %s", answer, format(steps(tr)))
		}
		if len(answer.Records) != 1 || answer.Records[0].Data != "192.0.2.60" {
			t.Errorf("got records %+v, want 192.0.2.60", answer.Records)
		}

		// The chase is a branch under the alias, starting again at the root.
		var alias *trace.Step
		for _, step := range steps(tr) {
			if step.Kind == trace.KindCNAME {
				alias = step
			}
		}
		if alias == nil {
			t.Fatalf("got no CNAME step: %s", format(steps(tr)))
		}
		if len(alias.Children) != 1 || alias.Children[0].Kind != trace.KindZone {
			t.Fatalf("got children %+v, want one walk from the root", alias.Children)
		}
		if note := alias.Children[0].Notes; len(note) != 1 || note[0] != "resolving www.target.com." {
			t.Errorf("got notes %q, want the branch to name its target", note)
		}
	})

	t.Run("not chased when asked for", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{}).Resolve(t.Context(), "alias.example.com", "CNAME")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		answer := tr.Result()
		if answer == nil || answer.Kind != trace.KindAnswer {
			t.Fatalf("got %+v, want the CNAME itself as the answer", answer)
		}
		if len(answer.Children) != 0 {
			t.Errorf("got %d children, want no chase when the CNAME is the question", len(answer.Children))
		}
	})

	t.Run("loop", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{}).Resolve(t.Context(), "loop.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		if len(tr.Warnings) != 1 || !strings.Contains(tr.Warnings[0], "comes back to") {
			t.Fatalf("got warnings %q, want one about the chain biting its tail", tr.Warnings)
		}
		if got := len(steps(tr)); got > 12 {
			t.Errorf("got %d steps, want the loop cut short: %s", got, format(steps(tr)))
		}
	})
}

// TestSideResolution covers a delegation to a nameserver named outside the
// zone: its address has to be found with a walk of its own.
func TestSideResolution(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
net.                IN NS   ns.net.
ns.net.             IN A    192.0.2.6
`
	const comZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns.outside.net.
`
	const netZone = `
@            IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@            IN NS   ns
ns           IN A    192.0.2.6
outside      IN NS   nsx.outside
nsx.outside  IN A    192.0.2.7
`
	// This zone is the only place that says where ns.outside.net. lives.
	const outsideZone = `
@     IN SOA  nsx hostmaster 1 7200 3600 1209600 3600
@     IN NS   nsx
nsx   IN A    192.0.2.7
ns    IN A    192.0.2.8
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns.net.", Origin: "net.", Zone: netZone, Declared: "192.0.2.6"})
	hierarchy.Add(fakens.Config{Name: "nsx.outside.net.", Origin: "outside.net.", Zone: outsideZone, Declared: "192.0.2.7"})
	hierarchy.Add(fakens.Config{Name: "ns.outside.net.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.8"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want the answer from the side-resolved server: %s", answer, format(steps(tr)))
	}
	if got := answer.Server.IP.String(); got != "192.0.2.8" {
		t.Errorf("got the answer from %s, want the address the side walk found", got)
	}
}

// TestGlueLess covers a nameserver inside the zone it serves with no glue:
// nothing can reach it, and trying to resolve it would only loop.
func TestGlueLess(t *testing.T) {
	const comZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns.example
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	referral := steps(tr)[1]
	if got := referral.Delegation.GlueLess; len(got) != 1 || got[0] != "ns.example.com." {
		t.Fatalf("got glue-less %v, want ns.example.com.", got)
	}
	if len(referral.Children) != 0 {
		t.Errorf("got %d children, want no attempt to resolve a name only it could answer", len(referral.Children))
	}
	if len(tr.Warnings) != 2 {
		t.Errorf("got warnings %q, want the broken delegation and the dead end", tr.Warnings)
	}
}

// TestSameServerForParentAndChild covers a server authoritative for both sides
// of a zone cut: the answer arrives where a referral was expected.
func TestSameServerForParentAndChild(t *testing.T) {
	const comZone = `
@               IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@               IN NS   ns
ns              IN A    192.0.2.2
www.example.com. IN A   192.0.2.10
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want the answer read from the flags, not from the hop count: %s", answer, format(steps(tr)))
	}
	if answer.Zone != "com." {
		t.Errorf("got zone %s, want the zone the walk believed it was in", answer.Zone)
	}
}

// TestCheckNS covers the parent and the child disagreeing about who serves the
// zone, which is only visible when both are asked.
func TestCheckNS(t *testing.T) {
	const strayZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
@     IN NS   stray.example.com.
ns    IN A    192.0.2.3
www   IN A    192.0.2.10
`

	tests := map[string]struct {
		zone     string
		warnings int
	}{
		"they agree":    {zone: exampleZone},
		"they disagree": {zone: strayZone, warnings: 1},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
			hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: test.zone, Declared: "192.0.2.3"})

			tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{CheckNS: true}).
				Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			if len(tr.Warnings) != test.warnings {
				t.Fatalf("got warnings %q, want %d", tr.Warnings, test.warnings)
			}
			if test.warnings > 0 && !strings.Contains(tr.Warnings[0], "stray.example.com.") {
				t.Errorf("got warning %q, want the name only the zone lists", tr.Warnings[0])
			}

			answer := tr.Result()
			if answer == nil {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}
			check := answer.Children[len(answer.Children)-1]
			if len(check.Notes) == 0 || check.Notes[0] != "parent/child NS check" {
				t.Errorf("got %+v under the answer, want the NS check", check)
			}
			if len(check.Records) != 0 {
				t.Errorf("got records %+v on the check, want only its verdict", check.Records)
			}
		})
	}
}

// TestAll covers the fanout: every nameserver of a zone is asked, and the tree
// keeps them in the order they were delegated.
func TestAll(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   lame.com.
com.                IN NS   ns.com.
com.                IN NS   slow.com.
lame.com.           IN A    192.0.2.5
ns.com.             IN A    192.0.2.2
slow.com.           IN A    192.0.2.9
`

	newHierarchy := func(tb testing.TB) harness {
		hierarchy := fakens.NewHierarchy(tb)
		root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
		hierarchy.Add(fakens.Config{
			Name: "lame.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.5",
			Behaviour: fakens.Behaviour{Refuse: true},
		})
		hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
		hierarchy.Add(fakens.Config{Name: "slow.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.9"})
		hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3"})
		return harness{hierarchy, root}
	}

	t.Run("every server is asked", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{All: true}).Resolve(t.Context(), "www.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		var atCom []*trace.Step
		for _, step := range steps(tr) {
			if step.Zone == "com." {
				atCom = append(atCom, step)
			}
		}
		if len(atCom) != 3 {
			t.Fatalf("got %d steps at com., want all three asked: %s", len(atCom), format(steps(tr)))
		}
		for i, want := range []string{"lame.com.", "ns.com.", "slow.com."} {
			if atCom[i].Server.Name != want {
				t.Errorf("step %d at com. is %s, want %s: the delegated order", i, atCom[i].Server.Name, want)
			}
			if atCom[i].Kind == trace.KindSkipped {
				t.Errorf("%s was skipped, want every server asked", want)
			}
		}
		if tr.Result() == nil {
			t.Errorf("got no answer, want the walk to go on from the first server that was any use")
		}
	})

	t.Run("the rest are shown but not asked", func(t *testing.T) {
		h := newHierarchy(t)
		tr, err := newResolver(t, h, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		var skipped int
		for _, step := range steps(tr) {
			if step.Kind == trace.KindSkipped {
				skipped++
			}
		}
		if skipped != 1 {
			t.Errorf("got %d unqueried servers, want slow.com. shown after the one that answered: %s",
				skipped, format(steps(tr)))
		}
	})
}

// TestFamily covers -4 and -6: a server without an address of the right family
// is shown as a sibling nobody asked, rather than a hop that failed.
func TestFamily(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN AAAA 2001:db8::1
com.                IN NS   four.com.
com.                IN NS   six.com.
four.com.           IN A    192.0.2.5
six.com.            IN AAAA 2001:db8::2
`
	const comZone = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
ns         IN AAAA 2001:db8::2
example    IN NS   ns.example
ns.example IN AAAA 2001:db8::3
`
	const exampleZone = `
@    IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@    IN NS   ns
ns   IN AAAA 2001:db8::3
www  IN A    192.0.2.10
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "2001:db8::1"})
	hierarchy.Add(fakens.Config{Name: "four.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.5"})
	hierarchy.Add(fakens.Config{Name: "six.com.", Origin: "com.", Zone: comZone, Declared: "2001:db8::2"})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "2001:db8::3"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{Family: 6}).
		Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var skipped, asked *trace.Step
	for _, step := range steps(tr) {
		if step.Zone != "com." {
			continue
		}
		if step.Kind == trace.KindSkipped {
			skipped = step
		} else {
			asked = step
		}
	}
	if skipped == nil || skipped.Server.Name != "four.com." {
		t.Fatalf("got %+v skipped, want the IPv4-only server: %s", skipped, format(steps(tr)))
	}
	if len(skipped.Notes) != 1 || skipped.Notes[0] != "no IPv6 address" {
		t.Errorf("got notes %q, want the reason it was passed over", skipped.Notes)
	}
	if asked == nil || asked.Server.Name != "six.com." {
		t.Fatalf("got %+v asked, want the IPv6 one", asked)
	}
	if tr.Result() == nil || tr.Result().Kind != trace.KindAnswer {
		t.Errorf("got %+v, want the walk to finish over IPv6: %s", tr.Result(), format(steps(tr)))
	}
}

func TestFamilyRejected(t *testing.T) {
	h := internet(t)
	if _, err := resolver.New(resolver.Config{
		Transport: h.carry(transport.NewUDP(fast)),
		Roots:     []trace.Server{h.root.Nameserver()},
		Family:    5,
	}); err == nil {
		t.Error("got no error for a family that is neither 4 nor 6, want one")
	}
}

// TestSideResolutionDepth covers two zones whose nameservers are named inside
// each other: chasing the names is bounded, so the walk still ends.
func TestSideResolutionDepth(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
a.test.             IN NS   ns.b.test.
b.test.             IN NS   ns.a.test.
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.a.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var capped bool
	for _, warning := range tr.Warnings {
		if strings.Contains(warning, "too far away") {
			capped = true
		}
	}
	if !capped {
		t.Errorf("got warnings %q, want one saying the names were chased far enough", tr.Warnings)
	}
	if tr.Result() != nil {
		t.Errorf("got result %+v, want none: neither zone can be reached", tr.Result())
	}
}
