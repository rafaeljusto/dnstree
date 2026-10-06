package resolver_test

import (
	"slices"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
)

// TestDelegated covers where --rdap asks a registry: the zones a real walk
// was referred to below the TLD, which is what a registration is a record of.
func TestDelegated(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		name   string
		zones  []string
		parent []string
	}{
		"a name in a zone the TLD delegated": {
			name: "www.example.com", zones: []string{"example.com."}, parent: []string{"com."},
		},
		"the zone the TLD delegated itself": {
			name: "example.com", zones: []string{"example.com."}, parent: []string{"com."},
		},
		"a name the TLD said does not exist": {
			name: "gone.com",
		},
		"a name under a suffix the root delegated": {
			name: "www.example.co.uk", zones: []string{"co.uk."}, parent: []string{"."},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr, err := newResolver(t, internet(t), resolver.Config{}).Resolve(t.Context(), test.name, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			var zones, parent []string
			for _, step := range tr.Delegated() {
				zones, parent = append(zones, step.Delegation.Zone), append(parent, step.Zone)
			}
			if !slices.Equal(zones, test.zones) || !slices.Equal(parent, test.parent) {
				t.Errorf("got %v delegated by %v, want %v by %v: %s", zones, parent, test.zones, test.parent, format(steps(tr)))
			}
		})
	}
}
