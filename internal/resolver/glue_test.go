package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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

			check := tr.Result().Children[len(tr.Result().Children)-1]
			if len(check.Children) != 2 || check.Children[0].Asked.Type != "A" || check.Children[1].Asked.Type != "AAAA" {
				t.Errorf("got %+v under the NS check, want the A and AAAA of the nameserver", check.Children)
			}
		})
	}
}
