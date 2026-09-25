package resolver_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// A zone served by two nameservers, which is the shape the whole question turns
// on: one of them can fall behind, and everything a walk otherwise does asks
// only one of them.
const (
	replicatedRootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
test.               IN NS   ns1.test.
test.               IN NS   ns2.test.
ns1.test.           IN A    192.0.2.5
ns2.test.           IN A    192.0.2.6
`

	// replicatedZone is written with the serial and the address of the server
	// that answers left to be filled in, so that one copy can be made older
	// than the other, or made to answer differently.
	replicatedZone = `
@    IN SOA  ns1 hostmaster %d 7200 3600 1209600 3600
@    IN NS   ns1
@    IN NS   ns2
ns1  IN A    192.0.2.5
ns2  IN A    192.0.2.6
www  IN A    %s
`
)

// replicated builds that hierarchy: two nameservers of test., each serving the
// serial and the answer it is given.
func replicated(tb testing.TB, first, second struct {
	serial uint32
	answer string
},
) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: replicatedRootZone, Declared: "192.0.2.1",
	})
	hierarchy.Add(fakens.Config{
		Name: "ns1.test.", Origin: "test.", Declared: "192.0.2.5",
		Zone: fmt.Sprintf(replicatedZone, first.serial, first.answer),
	})
	hierarchy.Add(fakens.Config{
		Name: "ns2.test.", Origin: "test.", Declared: "192.0.2.6",
		Zone: fmt.Sprintf(replicatedZone, second.serial, second.answer),
	})
	return harness{hierarchy, root}, resolver.Config{}
}

// caughtUp is a nameserver holding the same copy of the zone as the other.
var caughtUp = struct {
	serial uint32
	answer string
}{serial: 2, answer: "192.0.2.10"}

// TestSerialsAreAsked covers the sweep itself: every nameserver of the zone the
// walk ended in is asked which copy of it that server holds, whatever the walk
// itself got away with asking.
func TestSerialsAreAsked(t *testing.T) {
	h, cfg := replicated(t, caughtUp, caughtUp)
	cfg.Serial = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	asked := serialsIn(tr)
	if len(asked) != 2 {
		t.Fatalf("got %d serials, want one from each nameserver: %s", len(asked), format(steps(tr)))
	}
	for _, step := range asked {
		if step.SOA == nil || step.SOA.Serial != 2 {
			t.Errorf("got %+v, want the serial the zone was written with", step.SOA)
		}
		if !step.Aside {
			t.Error("got a serial on the walk itself, want it drawn as an aside")
		}
	}
	if warned(tr, "different copies") {
		t.Errorf("got %q, want no complaint: the two agree", tr.Warnings)
	}
}

// TestSerialsDisagree is the reason the sweep exists. A secondary left behind
// by a zone transfer answers every question correctly and answers it out of an
// older zone, and only the serials say so.
func TestSerialsDisagree(t *testing.T) {
	behind := caughtUp
	behind.serial = 1

	h, cfg := replicated(t, caughtUp, behind)
	cfg.Serial = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Result() == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}

	if !warned(tr, "the nameservers of test. are serving different copies of it") {
		t.Fatalf("got %q, want the disagreement reported", tr.Warnings)
	}
	warning := warning(tr, "different copies")
	for _, want := range []string{"2 at ns1.test.", "1 at ns2.test."} {
		if !strings.Contains(warning, want) {
			t.Errorf("got %q, want it to name %q", warning, want)
		}
	}
	// Serial arithmetic wraps, so the larger number is not the newer zone and
	// naming one of them as behind would send somebody to the wrong server.
	for _, avoid := range []string{"behind", "newer", "older", "stale"} {
		if strings.Contains(warning, avoid) {
			t.Errorf("got %q, want no claim about which copy is the newer", warning)
		}
	}
}

// TestSerialsAreNotAskedByDefault covers the cost. It is a query per
// nameserver, so it is a thing to ask for.
func TestSerialsAreNotAskedByDefault(t *testing.T) {
	behind := caughtUp
	behind.serial = 1

	h, cfg := replicated(t, caughtUp, behind)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := serialsIn(tr); len(got) != 0 {
		t.Errorf("got %d serial queries, want none: %s", len(got), format(steps(tr)))
	}
	if warned(tr, "different copies") {
		t.Errorf("got %q, want nothing: no serial was asked for", tr.Warnings)
	}
}

// TestAnswersDisagree covers the other half, which --all gets without asking:
// where the walk put the question to every nameserver itself, two of them
// answering differently is worth saying.
func TestAnswersDisagree(t *testing.T) {
	other := caughtUp
	other.answer = "192.0.2.99"

	h, cfg := replicated(t, caughtUp, other)
	cfg.All = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if !warned(tr, "do not answer www.test. A alike") {
		t.Fatalf("got %q, want the two answers held against each other", tr.Warnings)
	}
	warning := warning(tr, "do not answer")
	for _, want := range []string{"192.0.2.10 at ns1.test.", "192.0.2.99 at ns2.test."} {
		if !strings.Contains(warning, want) {
			t.Errorf("got %q, want it to name %q", warning, want)
		}
	}
}

// TestAnswersAgree covers the ordinary case, which is worth no room: two
// nameservers serving one zone answer alike, and saying so every time would
// bury the run that does not.
func TestAnswersAgree(t *testing.T) {
	h, cfg := replicated(t, caughtUp, caughtUp)
	cfg.All = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if warned(tr, "do not answer") {
		t.Errorf("got %q, want nothing: the two agree", tr.Warnings)
	}
}

// TestOneAnswerIsNotADisagreement covers the walk that never asked twice. A
// single answer has nothing to be held against, and a run without --all has
// only ever got one.
func TestOneAnswerIsNotADisagreement(t *testing.T) {
	other := caughtUp
	other.answer = "192.0.2.99"

	h, cfg := replicated(t, caughtUp, other)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if warned(tr, "do not answer") {
		t.Errorf("got %q, want nothing: only one nameserver was asked", tr.Warnings)
	}
}

// serialsIn is every hop the serial sweep made.
func serialsIn(tr *trace.Trace) []*trace.Step {
	var asked []*trace.Step
	for step := range tr.Steps() {
		for _, note := range step.Notes {
			if strings.HasPrefix(note, "SOA of ") {
				asked = append(asked, step)
			}
		}
	}
	return asked
}

// warning is the first warning carrying text, empty where there is none.
func warning(tr *trace.Trace, text string) string {
	for _, warning := range tr.Warnings {
		if strings.Contains(warning, text) {
			return warning
		}
	}
	return ""
}
