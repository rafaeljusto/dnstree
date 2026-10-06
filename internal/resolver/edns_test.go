package resolver_test

import (
	"maps"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// ednsTests are the asides --check-edns left, keyed by server and by shape.
func ednsTests(tr *trace.Trace) map[string]*trace.Step {
	found := make(map[string]*trace.Step)
	for step := range tr.Steps() {
		if step.EDNS != nil {
			found[step.Server.Name+" "+string(step.EDNS.Kind)] = step
		}
	}
	return found
}

func TestEDNS(t *testing.T) {
	t.Parallel()

	type verdict struct {
		state trace.EDNSState
		fault trace.EDNSFault
	}
	ok := verdict{trace.EDNSOK, ""}
	passes := map[trace.EDNSKind]verdict{
		trace.EDNSPlain: ok, trace.EDNSVersion: ok, trace.EDNSOption: ok, trace.EDNSFlag: ok,
	}
	// but is the second server passing every test except the one named.
	but := func(kind trace.EDNSKind, got verdict) map[trace.EDNSKind]verdict {
		want := maps.Clone(passes)
		want[kind] = got
		return want
	}
	for name, tt := range map[string]struct {
		behaviour fakens.Behaviour
		want      map[trace.EDNSKind]verdict // the second server's; a shape left out was not asked
	}{
		"a server that answers every shape as it should": {want: passes},
		"a server that answers a version it does not know as though it were 0": {
			behaviour: fakens.Behaviour{IgnoreEDNSVersion: true},
			want:      but(trace.EDNSVersion, verdict{trace.EDNSBroken, trace.EDNSRcode}),
		},
		"a server that answers BADVERS and the question as well": {
			behaviour: fakens.Behaviour{BadVersAnswer: true},
			want:      but(trace.EDNSVersion, verdict{trace.EDNSBroken, trace.EDNSAnswer}),
		},
		"a server that cannot parse an option it does not know": {
			behaviour: fakens.Behaviour{FormErrEDNSOption: true},
			want:      but(trace.EDNSOption, verdict{trace.EDNSBroken, trace.EDNSRcode}),
		},
		"a server that copies an option it does not know back": {
			behaviour: fakens.Behaviour{EchoEDNSOption: true},
			want:      but(trace.EDNSOption, verdict{trace.EDNSBroken, trace.EDNSEchoed}),
		},
		"a firewall that drops a flag it does not know": {
			behaviour: fakens.Behaviour{DropEDNSFlags: true},
			want:      but(trace.EDNSFlag, verdict{trace.EDNSBroken, trace.EDNSSilent}),
		},
		"a server that copies a flag it does not know back": {
			behaviour: fakens.Behaviour{EchoEDNSFlags: true},
			want:      but(trace.EDNSFlag, verdict{trace.EDNSBroken, trace.EDNSEchoed}),
		},
		"a server that answers FORMERR to EDNS0 itself": {
			behaviour: fakens.Behaviour{FormErrEDNS: true},
			want:      map[trace.EDNSKind]verdict{trace.EDNSPlain: {trace.EDNSBroken, trace.EDNSRcode}},
		},
		"a server that answers EDNS0 without an OPT record": {
			behaviour: fakens.Behaviour{NoEDNSReply: true},
			want:      map[trace.EDNSKind]verdict{trace.EDNSPlain: {trace.EDNSBroken, trace.EDNSNoOPT}},
		},
		"a server that answers with an OPT record of another version": {
			behaviour: fakens.Behaviour{EDNSReplyVersion: 1},
			want:      map[trace.EDNSKind]verdict{trace.EDNSPlain: {trace.EDNSBroken, trace.EDNSBadVers}},
		},
		"a server that refuses the zone, which is no fault of EDNS": {
			behaviour: fakens.Behaviour{Refuse: true},
			want:      map[trace.EDNSKind]verdict{trace.EDNSPlain: {trace.EDNSUnchecked, ""}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := exposed(t, fakens.Behaviour{}, tt.behaviour)
			cfg.CheckEDNS = true

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if tr.Result() == nil || tr.Result().Kind != trace.KindAnswer {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}

			got := ednsTests(tr)
			if len(got) != 4+len(tt.want) {
				t.Fatalf("got %d tests, want four of the first server and %d of the second: %s", len(got), len(tt.want), format(steps(tr)))
			}
			for server, want := range map[string]map[trace.EDNSKind]verdict{"ns1.test.": passes, "ns2.test.": tt.want} {
				for kind, want := range want {
					step := got[server+" "+string(kind)]
					if step == nil {
						t.Fatalf("got no %s test of %s", kind, server)
					}
					if verdict := (verdict{step.EDNS.State, step.EDNS.Fault}); verdict != want {
						t.Errorf("got %v for %s of %s, want %v", verdict, kind, server, want)
					}
					if !step.Aside {
						t.Errorf("got the %s test of %s on the walk itself, want it drawn as an aside", kind, server)
					}
				}
			}
			if step := got["ns1.test. version"]; step.Rcode != "BADVERS" {
				t.Errorf("got %q, want the version test answered BADVERS", step.Rcode)
			}
		})
	}
}

// TestEDNSTruncated covers a reply that did not fit and could not be fetched
// whole. What it left out is no fault of the server's, so it is unchecked.
func TestEDNSTruncated(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{}, fakens.Behaviour{TruncateUDP: true})
	cfg.TCP = nil
	cfg.CheckEDNS = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	step := ednsTests(tr)["ns2.test. edns"]
	if step == nil || step.EDNS.State != trace.EDNSUnchecked || step.Kind != trace.KindError {
		t.Errorf("got %+v, want the truncated baseline unchecked", step)
	}
}

// TestEDNSNotByDefault covers the cost: four queries a nameserver are asked
// only when they are asked for.
func TestEDNSNotByDefault(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{}, fakens.Behaviour{EchoEDNSFlags: true})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := ednsTests(tr); len(got) != 0 {
		t.Errorf("got %d tests, want none: %s", len(got), format(steps(tr)))
	}
}

// TestEDNSSilent covers a server that answers nothing at all. Its silence to
// a new version says nothing about EDNS, so it is unchecked, and is not asked
// the rest.
func TestEDNSSilent(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{}, fakens.Behaviour{Drop: true})
	cfg.CheckEDNS = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := ednsTests(tr)
	if step := got["ns2.test. edns"]; step == nil || step.EDNS.State != trace.EDNSUnchecked {
		t.Errorf("got %+v, want the silent server unchecked", step)
	}
	for _, kind := range []trace.EDNSKind{trace.EDNSVersion, trace.EDNSOption, trace.EDNSFlag} {
		if step := got["ns2.test. "+string(kind)]; step != nil {
			t.Errorf("got the silent server asked the %s test, want only the baseline", kind)
		}
	}
	if step := got["ns1.test. flag"]; step == nil || step.EDNS.State != trace.EDNSOK {
		t.Errorf("got %+v, want the other server checked", step)
	}
}

// TestEDNSSpendsTheBudget covers the rule every sweep keeps: it cannot spend
// more than the walk was given, and says where it stopped. Every server is
// asked the baseline first, and the rest go whole to the servers there is
// room for.
func TestEDNSSpendsTheBudget(t *testing.T) {
	t.Parallel()

	h, cfg := exposed(t, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.CheckEDNS = true
	cfg.Budget.MaxQueries = 7 // the walk takes two, the baselines two more

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := ednsTests(tr)
	if len(got) != 5 || got["ns2.test. edns"] == nil || got["ns1.test. flag"] == nil {
		t.Errorf("got %d tests, want both baselines and the rest of one server: %s", len(got), format(steps(tr)))
	}
	if !warned(tr, "the budget ran out before every nameserver of test. could be checked for how it handles edns; raise --max-queries") {
		t.Errorf("got %q, want the budget said", tr.Warnings)
	}
}
