package resolver_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestRollover catches example.com. at each step of a rollover, as the walk
// records it, and reads the step back off the trace.
func TestRollover(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		example fakens.Behaviour
		checkDS bool
		state   trace.RolloverState
		want    []string
	}{
		"a zone with one key of each kind": {
			state: trace.RolloverNone,
		},
		"a DS at the parent for a key the zone does not publish": {
			example: fakens.Behaviour{Rollover: fakens.RolloverExtraDS},
			state:   trace.RolloverRolling,
			want:    []string{"double-ds swap-key", "double-ds remove-ds"},
		},
		"a DS for a key not published yet, which the zone's CDS asks for": {
			example: fakens.Behaviour{Rollover: fakens.RolloverExtraDS, CDS: fakens.CDSNext},
			checkDS: true,
			state:   trace.RolloverRolling,
			want:    []string{"double-ds swap-key"},
		},
		"a second key signing key that signs the keys": {
			example: fakens.Behaviour{Rollover: fakens.RolloverExtraKSK},
			state:   trace.RolloverRolling,
			want:    []string{"double-ksk swap-ds", "double-ksk remove-key"},
		},
		"a second key signing key the zone's CDS asks for": {
			example: fakens.Behaviour{Rollover: fakens.RolloverExtraKSK, CDS: fakens.CDSNext},
			checkDS: true,
			state:   trace.RolloverRolling,
			want:    []string{"double-ksk swap-ds"},
		},
		"a second key signing key that signs nothing": {
			example: fakens.Behaviour{Rollover: fakens.RolloverIdleKSK},
			state:   trace.RolloverRolling,
			want:    []string{"double-ksk swap-ds", "double-ksk remove-key"},
		},
		"two key signing keys each with a DS": {
			example: fakens.Behaviour{Rollover: fakens.RolloverLinked},
			state:   trace.RolloverRolling,
			want:    []string{"double-rrset remove-old", "double-rrset remove-old"},
		},
		"a second zone signing key that signs nothing": {
			example: fakens.Behaviour{Rollover: fakens.RolloverIdleZSK},
			state:   trace.RolloverRolling,
			want:    []string{"pre-publish sign-with", "pre-publish remove-key"},
		},
		"a key signing key of another algorithm": {
			example: fakens.Behaviour{Rollover: fakens.RolloverAlgorithm},
			state:   trace.RolloverRolling,
			want:    []string{"algorithm "},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, test.example)
			cfg.CheckDS = test.checkDS

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if answer := tr.Result(); answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
				t.Fatalf("got %+v, want a secure answer: %s", answer, format(steps(tr)))
			}

			got := tr.Rolled(nil)
			if got.Zone != "example.com." || got.State != test.state {
				t.Fatalf("got %q at %s (%s), want %q at example.com.", got.State, got.Zone, got.Reason, test.state)
			}
			var readings []string
			for _, reading := range got.Readings {
				readings = append(readings, fmt.Sprintf("%s %s", reading.Method, reading.Next))
			}
			if !reflect.DeepEqual(readings, test.want) {
				t.Errorf("got readings %q, want %q", readings, test.want)
			}
		})
	}
}
