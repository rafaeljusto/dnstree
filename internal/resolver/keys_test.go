package resolver_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestCheckKeys covers a zone signed by two providers at once (RFC 8901). Each
// signs with keys of its own, and a resolver that took the key set from one
// checks the other's answers against it, so each has to publish both. A walk
// asking one server never sees the difference.
func TestCheckKeys(t *testing.T) {
	const (
		comZone = `
@        IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@        IN NS   ns
ns       IN A    192.0.2.2
example  IN NS   ns1.example
example  IN NS   ns2.example
ns1.example IN A 192.0.2.3
ns2.example IN A 192.0.2.5
`
		exampleZone = `
@     IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns1
@     IN NS   ns2
ns1   IN A    192.0.2.3
ns2   IN A    192.0.2.5
www   IN A    192.0.2.10
`
	)

	tests := map[string]struct {
		all            bool
		first, second  bool // whether each publishes the other's key
		lacking, signs string
	}{
		"each publishes both":            {all: true, first: true, second: true},
		"the second lacks the first's":   {all: true, first: true, lacking: "ns2.example.com.", signs: "ns1.example.com."},
		"neither publishes the other's":  {all: true, lacking: "ns", signs: "ns"},
		"without --all nothing is asked": {},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: true})
			one := hierarchy.Add(fakens.Config{Name: "ns1.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: true})
			two := hierarchy.Add(fakens.Config{Name: "ns2.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.5", DNSSEC: true})
			if test.first {
				one.Cosign(t, two)
			}
			if test.second {
				two.Cosign(t, one)
			}

			cfg := resolver.Config{All: test.all, DNSSEC: true, Anchors: root.Anchors(t)}
			tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			// --all leaves the verdict on the hop the walk went on with.
			if chain := tr.Chain(); chain == nil || chain.DNSSEC.State != trace.Secure {
				t.Fatalf("got %+v, want a secure walk: the verdict is not this check's to change", chain)
			}

			var keys []string
			for _, warning := range tr.Warnings {
				if strings.Contains(warning, "do not publish the same keys") {
					keys = append(keys, warning)
				}
			}
			switch {
			case test.lacking == "" && len(keys) > 0:
				t.Errorf("got %q, want none", keys)
			case test.lacking != "" && len(keys) == 0:
				t.Errorf("got %q, want %s named as lacking a key %s signs with", tr.Warnings, test.lacking, test.signs)
			}
			for _, warning := range keys {
				if !strings.Contains(warning, test.lacking) || !strings.Contains(warning, "RFC 8901") {
					t.Errorf("got %q, want %s named as lacking a key", warning, test.lacking)
				}
			}

			asked := 0
			for step := range tr.Steps() {
				for _, note := range step.Notes {
					if strings.HasPrefix(note, "keys check: ") {
						asked++
					}
				}
			}
			if want := map[bool]int{true: 4, false: 0}[test.all]; asked != want {
				t.Errorf("got %d keys checks under the answer, want %d", asked, want)
			}
		})
	}
}
