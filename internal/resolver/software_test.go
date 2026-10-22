package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestSoftware covers --software: what each server says it runs is kept on
// every hop sent to it, in its own words but escaped and clipped, and a server
// that refuses to say is told apart from one that was never asked.
func TestSoftware(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		leaf  fakens.Behaviour
		asked bool
		want  *trace.Software
	}{
		"a server that answers version.bind is taken at its word": {
			leaf:  fakens.Behaviour{Version: "9.18.24"},
			asked: true,
			want:  &trace.Software{Version: "9.18.24"},
		},
		"a server that refuses version.bind is asked version.server": {
			leaf:  fakens.Behaviour{VersionServer: "Knot DNS 3.3.5"},
			asked: true,
			want:  &trace.Software{Version: "Knot DNS 3.3.5"},
		},
		"a server that refuses both has hidden it": {
			asked: true,
			want:  &trace.Software{},
		},
		"what a server says is escaped and clipped, never drawn raw": {
			leaf:  fakens.Behaviour{Version: `\027[2J\"` + strings.Repeat("x", 60)},
			asked: true,
			want:  &trace.Software{Version: `\027[2J\"` + strings.Repeat("x", 39) + "..."},
		},
		"a walk that did not ask has nothing to say": {
			leaf: fakens.Behaviour{Version: "9.18.24"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := service(t, false, tt.leaf)
			cfg.Software = tt.asked

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			answer := tr.Result()
			if answer == nil {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}
			if got := answer.Server.Software; !equalSoftware(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}

			// The root says nothing either way, and is asked as any server is.
			root := tr.Root.Children[0]
			if want := map[bool]*trace.Software{true: {}}[tt.asked]; !equalSoftware(root.Server.Software, want) {
				t.Errorf("got %+v at the root, want %+v", root.Server.Software, want)
			}
		})
	}
}

// TestSoftwareSpendsTheBudget covers a budget the walk used up. The servers
// go unasked, which costs the labels and says so, never the answer.
func TestSoftwareSpendsTheBudget(t *testing.T) {
	t.Parallel()

	h, cfg := service(t, false, fakens.Behaviour{Version: "9.18.24"})
	cfg.Software = true
	cfg.Budget = resolver.Budget{MaxQueries: 2}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want the answer: %s", answer, format(steps(tr)))
	}
	if answer.Server.Software != nil {
		t.Errorf("got %+v, want nothing: the budget left the server unasked", answer.Server.Software)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "which software it runs") }) {
		t.Errorf("got %q, want a warning that the budget ran out", tr.Warnings)
	}
}

func equalSoftware(a, b *trace.Software) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
