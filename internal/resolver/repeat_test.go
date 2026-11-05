package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestRepeat covers --repeat: every question of the walk's own hops is asked
// again of the same server, once each, and what came back is counted on the
// hop. The walk itself, and so its answer, is the same with it as without.
func TestRepeat(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		leaf      fakens.Behaviour
		repeat    int
		nsid      bool
		want      *trace.Repeated // at the answer, round trips left out
		warning   string
		instances []trace.Count
	}{
		"a healthy server answers every repeat": {
			repeat: 4,
			want:   &trace.Repeated{Asked: 4, Answered: 4, Rcodes: []trace.Count{{Value: "NOERROR", Times: 4}}},
		},
		"a server that drops every third query misses two of six, and says so": {
			leaf:    fakens.Behaviour{DropEvery: 3},
			repeat:  6,
			want:    &trace.Repeated{Asked: 6, Answered: 4, TimedOut: 2, Rcodes: []trace.Count{{Value: "NOERROR", Times: 4}}},
			warning: "ns.test. (192.0.2.5) answered 4 of 6 repeats of www.test. A; 2 timed out",
		},
		"the instance that answered is counted where the walk asks for it": {
			leaf:      fakens.Behaviour{NSID: "fra1"},
			repeat:    3,
			nsid:      true,
			want:      &trace.Repeated{Asked: 3, Answered: 3, Rcodes: []trace.Count{{Value: "NOERROR", Times: 3}}},
			instances: []trace.Count{{Value: "fra1", Times: 3}},
		},
		"a walk that did not ask repeats nothing": {
			leaf: fakens.Behaviour{DropEvery: 3},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := service(t, false, tt.leaf)
			cfg.Repeat, cfg.NSID = tt.repeat, tt.nsid

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			answer := tr.Result()
			if answer == nil || answer.Kind != trace.KindAnswer {
				t.Fatalf("got %+v, want the answer: %s", answer, format(steps(tr)))
			}

			got := answer.Repeated
			if tt.want == nil {
				if hops := tr.Repeats(); len(hops) > 0 {
					t.Errorf("got %d hops repeated, want none", len(hops))
				}
				return
			}
			if got == nil {
				t.Fatalf("got no repeats at the answer: %s", format(steps(tr)))
			}
			if got.Asked != tt.want.Asked || got.Answered != tt.want.Answered || got.TimedOut != tt.want.TimedOut ||
				got.Failed != tt.want.Failed || !slices.Equal(got.Rcodes, tt.want.Rcodes) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			if !slices.Equal(got.Instances, tt.instances) {
				t.Errorf("got instances %+v, want %+v", got.Instances, tt.instances)
			}
			if got.Best <= 0 || got.Best > got.Median || got.Median > got.Worst {
				t.Errorf("got best %s, median %s, worst %s, want them in order and above nothing", got.Best, got.Median, got.Worst)
			}

			// The root is asked again as any server is, and answered every time.
			if root := tr.Root.Children[0].Repeated; root == nil || root.Answered != tt.repeat {
				t.Errorf("got %+v at the root, want %d answered", root, tt.repeat)
			}

			repeats := slices.DeleteFunc(slices.Clone(tr.Warnings), func(w string) bool { return !strings.Contains(w, "repeats") })
			switch {
			case tt.warning == "" && len(repeats) > 0:
				t.Errorf("got %q, want no warning about the repeats", repeats)
			case tt.warning != "" && !slices.Contains(repeats, tt.warning):
				t.Errorf("got %q, want %q", repeats, tt.warning)
			}
		})
	}
}

// TestRepeatLeavesTheAsidesAlone covers the probes and lookups a check makes:
// they ask other questions than the walk's, and are not asked again.
func TestRepeatLeavesTheAsidesAlone(t *testing.T) {
	t.Parallel()

	h, cfg := service(t, false, fakens.Behaviour{})
	cfg.Repeat, cfg.CheckRecursion = 2, true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	probed := false
	for step := range tr.Steps() {
		if !step.Aside {
			continue
		}
		probed = probed || step.Probe != nil
		if step.Repeated != nil {
			t.Errorf("got %+v on the aside at %s, want it left alone", step.Repeated, step.Zone)
		}
	}
	if !probed {
		t.Fatalf("got no probe to hold the repeats against: %s", format(steps(tr)))
	}
	if len(tr.Repeats()) != 2 {
		t.Errorf("got %d hops repeated, want the root and the answer", len(tr.Repeats()))
	}
}
