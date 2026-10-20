package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// TestCheckGlue covers the parent's copy of a nameserver's addresses drifting
// from the zone's own, which nothing but asking the zone shows: the walk goes
// where the glue says and gets an answer either way.
func TestCheckGlue(t *testing.T) {
	t.Parallel()

	const withIPv6Glue = comZone + "ns.example IN AAAA 2001:db8::3\n"

	tests := map[string]struct {
		com, example string
		want         string // the warning, empty for none
		held         []string
	}{
		"they agree": {
			com: comZone, example: exampleZone, held: []string{"192.0.2.3"}},
		"a nameserver renumbered in the zone alone": {
			com: comZone, example: strings.Replace(exampleZone, "ns    IN A    192.0.2.3", "ns    IN A    198.51.100.53", 1),
			want: "com. hands out 192.0.2.3 for ns.example.com., which example.com. itself gives as 198.51.100.53; have the registrar update the glue",
			held: []string{"198.51.100.53"}},
		"an IPv6 address the glue never carried": {
			com: comZone, example: exampleZone + "ns IN AAAA 2001:db8::53\n",
			want: "com. hands out no IPv6 address for ns.example.com., which example.com. gives as 2001:db8::53; have the registrar add it to the glue",
			held: []string{"192.0.2.3", "2001:db8::53"}},
		"an IPv6 address the zone dropped": {
			com: withIPv6Glue, example: exampleZone,
			want: "com. hands out 2001:db8::3 for ns.example.com., which example.com. itself does not give; have the registrar remove it from the glue",
			held: []string{"192.0.2.3"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: test.com, Declared: "192.0.2.2"})
			hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: test.example, Declared: "192.0.2.3"})

			tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{CheckNS: true}).
				Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			var glue []string
			for _, warning := range tr.Warnings {
				if strings.Contains(warning, "glue") {
					glue = append(glue, warning)
				}
			}
			switch {
			case test.want == "" && len(glue) > 0:
				t.Errorf("got %q, want no glue warning", glue)
			case test.want != "" && !slices.Contains(glue, test.want):
				t.Errorf("got %q, want %q", glue, test.want)
			}

			var delegation *trace.Delegation
			for step := range tr.Steps() {
				if step.Delegation != nil && step.Delegation.Zone == "example.com." {
					delegation = step.Delegation
				}
			}
			if delegation == nil {
				t.Fatalf("got no delegation to example.com.: %s", format(steps(tr)))
			}
			var held []string
			for _, addr := range delegation.ZoneAddrs["ns.example.com."] {
				held = append(held, addr.String())
			}
			slices.Sort(held)
			if !slices.Equal(held, test.held) {
				t.Errorf("got zone addresses %q, want %q", held, test.held)
			}

			check := nsCheck(tr.Result())
			if check == nil || len(check.Children) != 3 || check.Children[0].Asked.Type != "A" || check.Children[1].Asked.Type != "AAAA" ||
				check.Children[2].Asked.Type != "CSYNC" {
				t.Errorf("got %+v under the NS check, want the A and AAAA of the nameserver, then the CSYNC", check)
			}
		})
	}
}

// TestCheckClippedGlue covers a parent leaving out of a referral over UDP glue
// it is required to carry, without setting TC (RFC 9471). The walk still gets
// in through what is left, so only asking again over TCP shows it.
func TestCheckClippedGlue(t *testing.T) {
	t.Parallel()

	const (
		com     = comZone + "ns.example IN AAAA 2001:db8::3\n"
		example = exampleZone + "ns IN AAAA 2001:db8::3\n"
		// ns.other.com. is a sibling: named outside example.com., so its glue
		// is the parent's to leave out.
		sibling = comZone + "example IN NS ns.other\nns.other IN A 192.0.2.3\nns.other IN AAAA 2001:db8::4\n"
		clipped = "ns.com. left 1 of the 2 addresses of example.com.'s nameservers out of its referral without setting TC, which RFC 9471 forbids; over tcp it carries all of them"
	)

	tests := map[string]struct {
		com      string
		behave   fakens.Behaviour
		walk     func(harness) transport.Transport
		want     string   // the warning, empty for none
		withheld []string // what the delegation says was left out
		asked    bool     // whether the referral was asked for again over tcp
	}{
		"a parent that leaves the IPv6 glue out is caught": {
			com: com, behave: fakens.Behaviour{ClipGlue: true},
			want: clipped, withheld: []string{"2001:db8::3"}, asked: true},
		"a parent that sends all of it is asked and passes": {
			com: com, asked: true},
		"a parent that sets TC instead is not asked again": {
			com: com, behave: fakens.Behaviour{TruncateUDP: true}},
		"a sibling's glue left out is not counted": {
			com: sibling, behave: fakens.Behaviour{ClipGlue: true}, asked: true},
		"a walk over tcp has nothing to compare": {
			com: com, behave: fakens.Behaviour{ClipGlue: true},
			walk: func(h harness) transport.Transport { return h.carry(transport.NewTCP(fast)) }},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: test.com, Declared: "192.0.2.2", Behaviour: test.behave})
			hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: example, Declared: "192.0.2.3"})
			h := harness{hierarchy, root}

			cfg := resolver.Config{CheckNS: true, TCP: h.carry(transport.NewTCP(fast))}
			if test.walk != nil {
				cfg.Transport = test.walk(h)
			}
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			var warned []string
			for _, warning := range tr.Warnings {
				if strings.Contains(warning, "RFC 9471") {
					warned = append(warned, warning)
				}
			}
			switch {
			case test.want == "" && len(warned) > 0:
				t.Errorf("got %q, want no warning", warned)
			case test.want != "" && !slices.Equal(warned, []string{test.want}):
				t.Errorf("got %q, want %q", warned, test.want)
			}

			var (
				withheld []string
				asked    bool
			)
			for step := range tr.Steps() {
				if step.Aside && slices.Contains(step.Notes, "glue check over tcp") {
					asked = true
					if step.Kind != trace.KindReferral || step.Proto != transport.ProtoTCP {
						t.Errorf("got a %s over %s, want a referral over tcp", step.Kind, step.Proto)
					}
				}
				if !step.Aside && step.Delegation != nil && step.Delegation.Zone == "example.com." {
					for _, addr := range step.Delegation.Withheld["ns.example.com."] {
						withheld = append(withheld, addr.String())
					}
				}
			}
			if asked != test.asked {
				t.Errorf("got asked again over tcp %t, want %t", asked, test.asked)
			}
			if !slices.Equal(withheld, test.withheld) {
				t.Errorf("got withheld %q, want %q", withheld, test.withheld)
			}
		})
	}
}

// nsCheck is the step --check-ns hangs under the answer, nil where there is
// none.
func nsCheck(answer *trace.Step) *trace.Step {
	for _, child := range answer.Children {
		if len(child.Notes) > 0 && child.Notes[0] == "parent/child NS check" {
			return child
		}
	}
	return nil
}
