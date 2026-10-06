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

// exposed builds the replicated hierarchy with each nameserver of test.
// behaving as it is told, and a resolver that can reach them over TCP.
func exposed(tb testing.TB, first, second fakens.Behaviour) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: replicatedRootZone, Declared: "192.0.2.1",
	})
	for _, ns := range []struct {
		name, addr string
		behaviour  fakens.Behaviour
	}{{"ns1.test.", "192.0.2.5", first}, {"ns2.test.", "192.0.2.6", second}} {
		hierarchy.Add(fakens.Config{
			Name: ns.name, Origin: "test.", Declared: ns.addr, Behaviour: ns.behaviour,
			Zone: fmt.Sprintf(replicatedZone, 1, "192.0.2.10"),
		})
	}
	h := harness{hierarchy, root}
	return h, resolver.Config{TCP: h.carry(transport.NewTCP(fast))}
}

// probes are the asides the checks left, keyed by server and by what was asked.
func probes(tr *trace.Trace) map[string]*trace.Step {
	found := make(map[string]*trace.Step)
	for step := range tr.Steps() {
		if step.Probe != nil {
			found[step.Server.Name+" "+string(step.Probe.Kind)] = step
		}
	}
	return found
}

func TestExposure(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		first, second fakens.Behaviour
		want          map[string]trace.ProbeState
	}{
		"servers that keep both to themselves": {
			want: map[string]trace.ProbeState{
				"ns1.test. transfer": trace.ProbeClosed, "ns1.test. recursion": trace.ProbeClosed,
				"ns2.test. transfer": trace.ProbeClosed, "ns2.test. recursion": trace.ProbeClosed,
			},
		},
		"a secondary that hands the zone to anyone": {
			second: fakens.Behaviour{OpenTransfer: true},
			want: map[string]trace.ProbeState{
				"ns1.test. transfer": trace.ProbeClosed, "ns2.test. transfer": trace.ProbeOpen,
			},
		},
		"a provider that refuses a transfer by resetting the connection": {
			first: fakens.Behaviour{ResetTransfer: true},
			want: map[string]trace.ProbeState{
				"ns1.test. transfer": trace.ProbeClosed, "ns2.test. transfer": trace.ProbeClosed,
			},
		},
		"a server that resolves for anyone": {
			first: fakens.Behaviour{OpenRecursion: true},
			want: map[string]trace.ProbeState{
				"ns1.test. recursion": trace.ProbeOpen, "ns2.test. recursion": trace.ProbeClosed,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := exposed(t, tt.first, tt.second)
			cfg.CheckTransfer, cfg.CheckRecursion = true, true

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if tr.Result() == nil {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}

			got := probes(tr)
			if len(got) != 4 {
				t.Fatalf("got %d probes, want both questions put to both servers: %s", len(got), format(steps(tr)))
			}
			for key, want := range tt.want {
				step := got[key]
				if step == nil {
					t.Fatalf("got no probe for %s", key)
				}
				if step.Probe.State != want {
					t.Errorf("got %s for %s, want %s", step.Probe.State, key, want)
				}
				if !step.Aside {
					t.Errorf("got %s on the walk itself, want it drawn as an aside", key)
				}
				// A zone handed over is not ours to keep.
				if len(step.Records) != 0 {
					t.Errorf("got %d records kept from %s, want none", len(step.Records), key)
				}
			}
		})
	}
}

// TestExposureNotByDefault covers the cost, and the log line a transfer leaves
// on somebody else's server: neither is asked unless it is asked for.
func TestExposureNotByDefault(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{OpenTransfer: true}, fakens.Behaviour{OpenRecursion: true})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := probes(tr); len(got) != 0 {
		t.Errorf("got %d probes, want none: %s", len(got), format(steps(tr)))
	}
}

// TestExposureSilent covers a server that could not be asked. It said nothing
// either way, so it is unchecked rather than closed.
func TestExposureSilent(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{}, fakens.Behaviour{Drop: true})
	cfg.CheckRecursion = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	step := probes(tr)["ns2.test. recursion"]
	if step == nil || step.Probe.State != trace.ProbeUnchecked {
		t.Errorf("got %+v, want the silent server unchecked", step)
	}
}

// TestExposureWithoutTCP covers a walk with no way to carry a transfer. It
// says so once rather than drawing every server as unchecked.
func TestExposureWithoutTCP(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.TCP = nil
	cfg.CheckTransfer = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := probes(tr); len(got) != 0 {
		t.Errorf("got %d probes, want none without tcp", len(got))
	}
	if !warned(tr, "zone transfers of test. were not checked: they need tcp") {
		t.Errorf("got %q, want the missing transport said", tr.Warnings)
	}
}

// TestExposureSpendsTheBudget covers the rule every sweep keeps: it cannot
// spend more than the walk was given, and says where it stopped.
func TestExposureSpendsTheBudget(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.CheckTransfer, cfg.CheckRecursion = true, true
	cfg.Budget.MaxQueries = 3 // the walk takes two

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := probes(tr); len(got) != 1 {
		t.Errorf("got %d probes, want the one the budget had room for: %s", len(got), format(steps(tr)))
	}
	if !warned(tr, "the budget ran out before every nameserver of test. could be checked") {
		t.Errorf("got %q, want the budget said", tr.Warnings)
	}
}

// TestExposureReset makes sure a reset is what the closed transfer rests on,
// and that the hop still says what the socket did.
func TestExposureReset(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{ResetTransfer: true}, fakens.Behaviour{})
	cfg.CheckTransfer = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	step := probes(tr)["ns1.test. transfer"]
	if step == nil || step.Probe.State != trace.ProbeClosed || step.Kind != trace.KindError {
		t.Fatalf("got %+v, want a closed transfer resting on an error", step)
	}
	if !strings.Contains(step.Err, "connection reset") || !strings.Contains(strings.Join(step.Notes, ";"), "refuse a transfer") {
		t.Errorf("got %q and %q, want the reset said and read", step.Err, step.Notes)
	}
}

// TestExposureFallback covers a walk over a transport the zone's servers do not
// speak, picked up by --fallback. The lookup goes the way the walk's own
// questions went, rather than being left unchecked on every server.
func TestExposureFallback(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{OpenRecursion: true}, fakens.Behaviour{})
	cfg.Transport = h.carry(transport.NewDoT(fast))
	cfg.Fallback = h.carry(transport.NewUDP(fast))
	cfg.TCP = nil
	cfg.CheckRecursion = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := probes(tr)
	for key, want := range map[string]trace.ProbeState{
		"ns1.test. recursion": trace.ProbeOpen,
		"ns2.test. recursion": trace.ProbeClosed,
	} {
		step := got[key]
		if step == nil || step.Probe.State != want || step.Proto != transport.ProtoUDP {
			t.Errorf("got %+v for %s, want %s over udp", step, key, want)
		}
	}
}
