package resolver_test

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/resolver"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// deepZone has a name three labels below its apex with nothing at the two
// names between, which are empty non-terminals: they exist, and own nothing.
const deepZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.3
www   IN A    192.0.2.10
a.b.c IN A    192.0.2.30
`

// deep is the plain hierarchy with example.com. serving deepZone.
func deep(tb testing.TB, example fakens.Behaviour) (harness, *fakens.Server) {
	tb.Helper()
	return deepWith(tb, deepZone, example)
}

func deepWith(tb testing.TB, zone string, example fakens.Behaviour) (harness, *fakens.Server) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	server := hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: zone,
		Declared: "192.0.2.3", Behaviour: example})
	return harness{hierarchy, root}, server
}

// asked is what a server was asked, one "name type" each, oldest first.
func asked(server *fakens.Server) []string {
	var questions []string
	for _, query := range server.Queries() {
		questions = append(questions, query.Name+" "+dns.TypeToString[query.Type])
	}
	return questions
}

func TestMinimise(t *testing.T) {
	tests := map[string]struct {
		behaviour fakens.Behaviour
		name      string
		kind      trace.StepKind
		asked     []string // what example.com. was asked, in order
		warning   string
	}{
		"a name straight under the zone is asked for in full": {
			name:  "www.example.com",
			kind:  trace.KindAnswer,
			asked: []string{"www.example.com. A"},
		},
		"the empty non-terminals on the way are asked about one label at a time": {
			name:  "a.b.c.example.com",
			kind:  trace.KindAnswer,
			asked: []string{"c.example.com. A", "b.c.example.com. A", "a.b.c.example.com. A"},
		},
		"a server that denies an empty non-terminal is asked again in full": {
			behaviour: fakens.Behaviour{DenyEmptyNonTerminal: true},
			name:      "a.b.c.example.com",
			kind:      trace.KindAnswer,
			asked:     []string{"c.example.com. A", "a.b.c.example.com. A"},
			warning:   "NXDOMAIN for c.example.com.",
		},
		"a name that is not there is denied in full too": {
			name:  "nothere.gone.example.com",
			kind:  trace.KindNXDomain,
			asked: []string{"gone.example.com. A", "nothere.gone.example.com. A"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h, example := deep(t, test.behaviour)

			tr, err := newResolver(t, h, resolver.Config{Minimise: true}).Resolve(t.Context(), test.name, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			result := tr.Result()
			if result == nil || result.Kind != test.kind {
				t.Fatalf("got %+v, want %s: %s", result, test.kind, format(steps(tr)))
			}
			if result.Minimised {
				t.Error("got a minimised hop as the result, want the one that asked the whole name")
			}
			if got := asked(example); strings.Join(got, ", ") != strings.Join(test.asked, ", ") {
				t.Errorf("got example.com. asked %q, want %q", got, test.asked)
			}

			warnings := strings.Join(tr.Warnings, "\n")
			switch {
			case test.warning == "" && warnings != "":
				t.Errorf("got warnings %q, want none", tr.Warnings)
			case test.warning != "" && !strings.Contains(warnings, test.warning):
				t.Errorf("got warnings %q, want one about %q", tr.Warnings, test.warning)
			}
		})
	}
}

// TestMinimiseAbove covers the zones above the one that answers, which are
// asked for one label more than they are: the root never sees the name.
func TestMinimiseAbove(t *testing.T) {
	h, _ := deep(t, fakens.Behaviour{})

	tr, err := newResolver(t, h, resolver.Config{Minimise: true}).Resolve(t.Context(), "www.example.com", "AAAA")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := asked(h.root); len(got) != 1 || got[0] != "com. A" {
		t.Errorf("got the root asked %q, want only com. A", got)
	}

	var minimised []string
	for step := range tr.Mainline() {
		if step.Minimised {
			minimised = append(minimised, step.Zone+" "+step.Asked.Name)
			if !strings.Contains(strings.Join(step.Notes, "; "), "minimised to "+step.Asked.Name) {
				t.Errorf("got notes %q on %s, want it to say what it asked", step.Notes, step.Zone)
			}
		}
	}
	if want := []string{". com.", "com. example.com."}; strings.Join(minimised, ", ") != strings.Join(want, ", ") {
		t.Errorf("got minimised hops %q, want %q", minimised, want)
	}
}

// TestMinimiseCheckNS makes sure the parent/child comparison still finds the
// referral once minimised hops stand between it and the answer.
func TestMinimiseCheckNS(t *testing.T) {
	h, _ := deep(t, fakens.Behaviour{})

	tr, err := newResolver(t, h, resolver.Config{Minimise: true, CheckNS: true}).
		Resolve(t.Context(), "a.b.c.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(tr.Warnings) != 0 {
		t.Errorf("got warnings %q, want none", tr.Warnings)
	}

	checked := false
	for step := range tr.Steps() {
		checked = checked || strings.Contains(strings.Join(step.Notes, "; "), "parent/child NS check")
	}
	if !checked {
		t.Errorf("got no NS check, want one: %s", format(steps(tr)))
	}
}

// TestMinimiseDNSSEC walks a signed hierarchy minimising, which asks the zone
// more than once and must fetch its keys only the first time.
func TestMinimiseDNSSEC(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.Minimise = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
		t.Fatalf("got %+v, want a secure answer: %s", answer, format(steps(tr)))
	}

	keys := 0
	for step := range tr.Steps() {
		if step.Asked.Type == "DNSKEY" {
			keys++
		}
	}
	if keys != 3 {
		t.Errorf("got %d DNSKEY queries, want one for each of the three zones", keys)
	}
}

// TestMinimiseBudget is a name far below its zone, where every label is a
// question of its own: the budget ends the walk rather than the name.
func TestMinimiseBudget(t *testing.T) {
	labels := strings.TrimSuffix(strings.Repeat("x.", 40), ".")
	h, _ := deepWith(t, deepZone+labels+" IN A 192.0.2.40\n", fakens.Behaviour{})

	name := labels + ".example.com"
	tr, err := newResolver(t, h, resolver.Config{Minimise: true, Budget: resolver.Budget{MaxQueries: 8}}).
		Resolve(t.Context(), name, "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result := tr.Result(); result != nil {
		t.Errorf("got %+v, want no result from a minimised hop", result)
	}
	if !strings.Contains(format(steps(tr)), "gave up after 8 queries") {
		t.Errorf("got %s, want the budget to end the walk", format(steps(tr)))
	}
}

// TestMinimiseAll minimises with every nameserver asked at once and a watcher
// reading the whole trace at each hop, the way a live drawing does. Under
// -race, a minimised hop attached from anywhere but the walk would be caught.
func TestMinimiseAll(t *testing.T) {
	h, _ := deep(t, fakens.Behaviour{})

	hops := 0
	cfg := resolver.Config{Minimise: true, All: true, Stepped: func(tr *trace.Trace) {
		hops = len(steps(tr))
	}}
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "a.b.c.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result := tr.Result(); result == nil || result.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want an answer: %s", result, format(steps(tr)))
	}
	if hops != len(steps(tr)) {
		t.Errorf("got %d hops seen by the watcher, want all %d", hops, len(steps(tr)))
	}
}
