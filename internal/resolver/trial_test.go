package resolver_test

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// movedZone is example.com. as a new provider serves it, with an address the
// old one does not give.
const movedZone = `
@     IN SOA  ns1.new.co.uk. hostmaster 2 7200 3600 1209600 3600
@     IN NS   ns1.new.co.uk.
www   IN A    192.0.2.99
`

// TestTrial covers --try-ns: the zone walked as though its parent delegated it
// to the servers named, before the registry is told. The referral stays as the
// parent gave it, and the walk goes on to the new servers.
func TestTrial(t *testing.T) {
	t.Parallel()

	const coUKZone = `
@          IN SOA ns hostmaster 1 7200 3600 1209600 3600
@          IN NS  ns
ns         IN A   192.0.2.4
ns1.new    IN A   192.0.2.9
`
	tests := map[string]struct {
		trial   trace.Trial
		want    string // the address the walk ends on, empty for none
		warning string
	}{
		"a new server named with its address": {
			trial: trace.Trial{Zone: "example.com.", NS: []string{"ns1.new.co.uk."},
				Addrs: map[string][]netip.Addr{"ns1.new.co.uk.": {netip.MustParseAddr("192.0.2.9")}}},
			want: "192.0.2.99"},
		"a new server named alone, and looked up": {
			trial: trace.Trial{Zone: "example.com.", NS: []string{"ns1.new.co.uk."}},
			want:  "192.0.2.99"},
		"a new server named by its address alone": {
			trial: trace.Trial{Zone: "example.com.", NS: []string{"192.0.2.9"},
				Addrs: map[string][]netip.Addr{"192.0.2.9": {netip.MustParseAddr("192.0.2.9")}}},
			want: "192.0.2.99"},
		"a zone the walk never comes to": {
			trial: trace.Trial{Zone: "elsewhere.com.", NS: []string{"192.0.2.9"},
				Addrs: map[string][]netip.Addr{"192.0.2.9": {netip.MustParseAddr("192.0.2.9")}}},
			want:    "192.0.2.10",
			warning: "the walk never came to a delegation of elsewhere.com., so --try-ns changed nothing; name the zone a referral on the way delegates"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
			hierarchy.Add(fakens.Config{Name: "ns.co.uk.", Origin: "co.uk.", Zone: coUKZone, Declared: "192.0.2.4"})
			hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3"})
			hierarchy.Add(fakens.Config{Name: "ns1.new.co.uk.", Origin: "example.com.", Zone: movedZone, Declared: "192.0.2.9"})

			trial := test.trial
			tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{Try: &trial}).
				Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if tr.Trial == nil || tr.Trial.Zone != test.trial.Zone {
				t.Errorf("got trial %+v, want the walk marked as one", tr.Trial)
			}

			answer := tr.Result()
			if answer == nil || !slices.Equal(trace.Answers(answer.Records, "A"), []string{test.want}) {
				t.Fatalf("got %+v, want %s: %s", answer, test.want, format(steps(tr)))
			}

			replaced := 0
			for step := range tr.Steps() {
				if slices.Contains(step.Notes, "replaced by --try-ns") {
					replaced++
					if step.Delegation == nil || !slices.Contains(step.Delegation.NS, "ns.example.com.") {
						t.Errorf("got %+v, want the referral kept as the parent gave it", step.Delegation)
					}
				}
			}
			if want := map[bool]int{true: 0, false: 1}[test.warning != ""]; replaced != want {
				t.Errorf("got %d referrals marked replaced, want %d", replaced, want)
			}
			if test.warning != "" && !slices.Contains(tr.Warnings, test.warning) {
				t.Errorf("got %q, want %q", tr.Warnings, test.warning)
			}
		})
	}
}

// TestTrialKeepsTheParentsDS covers the move the trial is most worth making
// for: a signed zone moved to a provider that signs with keys of its own, while
// the parent still vouches for the old ones. On the day, every resolver that
// validates fails the zone, and the trial says so first.
func TestTrialKeepsTheParentsDS(t *testing.T) {
	t.Parallel()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns1.new.co.uk.", Origin: "example.com.", Zone: movedZone, Declared: "192.0.2.9",
		DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: true}})

	trial := trace.Trial{Zone: "example.com.", NS: []string{"ns1.new.co.uk."},
		Addrs: map[string][]netip.Addr{"ns1.new.co.uk.": {netip.MustParseAddr("192.0.2.9")}}}
	cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t), Try: &trial}
	tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	chain := tr.Chain()
	if chain == nil || chain.DNSSEC.State != trace.Bogus || !strings.Contains(chain.DNSSEC.Reason, "DS") {
		t.Fatalf("got %+v, want the old DS to break the new keys", chain)
	}
}

// TestTrialDS covers --try-ds: the zone walked as though its parent held the
// DS given rather than its own, so that a DS is checked before the registry
// publishes it. Each mistake is named in the terms of the registrar's form.
func TestTrialDS(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		zone     string
		unsigned bool // the zone has no DS at its parent yet
		bareCom  bool // com. is not signed, so nothing below it can be
		broken   bool // the zone's key set carries a signature that does not verify
		ds       func(example *fakens.Server) []trace.TrialDS
		state    trace.DNSSECState
		reason   string
		warning  string
	}{
		"an unsigned zone given the DS of its key signing key": {
			unsigned: true,
			ds:       func(example *fakens.Server) []trace.TrialDS { return []trace.TrialDS{example.DS(t)} },
			state:    trace.Secure},
		"a signed zone given the DS its parent already holds": {
			ds:    func(example *fakens.Server) []trace.TrialDS { return []trace.TrialDS{example.DS(t)} },
			state: trace.Secure},
		"a DS beside one for a key the zone does not publish yet": {
			unsigned: true,
			ds: func(example *fakens.Server) []trace.TrialDS {
				next := example.DS(t)
				next.Tag++
				return []trace.TrialDS{next, example.DS(t)}
			},
			state: trace.Secure},
		"the DS of the zone signing key": {
			unsigned: true,
			ds:       func(example *fakens.Server) []trace.TrialDS { return []trace.TrialDS{example.ZoneKeyDS(t)} },
			state:    trace.Bogus,
			reason:   "which signs the zone's data, not its keys; give the parent the DS of key "},
		"a DS whose digest was not copied whole": {
			unsigned: true,
			ds: func(example *fakens.Server) []trace.TrialDS {
				ds := example.DS(t)
				ds.Digest = ds.Digest[:len(ds.Digest)-2] + "00"
				return []trace.TrialDS{ds}
			},
			state:  trace.Bogus,
			reason: "but its digest is not that key's"},
		"the right DS over a key set whose signature is broken": {
			unsigned: true,
			broken:   true,
			ds:       func(example *fakens.Server) []trace.TrialDS { return []trace.TrialDS{example.DS(t)} },
			state:    trace.Bogus,
			reason:   "the DS is right, but the signature of key "},
		"a DS for a key the zone does not publish": {
			unsigned: true,
			ds: func(example *fakens.Server) []trace.TrialDS {
				ds := example.DS(t)
				ds.Tag++
				return []trace.TrialDS{ds}
			},
			state:  trace.Bogus,
			reason: "the zone publishes no key "},
		"a zone the walk never comes to": {
			zone:    "elsewhere.com.",
			ds:      func(example *fakens.Server) []trace.TrialDS { return []trace.TrialDS{example.ZoneKeyDS(t)} },
			state:   trace.Secure,
			warning: "the walk never came to a delegation of elsewhere.com., so --try-ds changed nothing; name the zone a referral on the way delegates"},
		"a zone under a parent that is not signed": {
			unsigned: true,
			bareCom:  true,
			ds:       func(example *fakens.Server) []trace.TrialDS { return []trace.TrialDS{example.DS(t)} },
			state:    trace.Insecure,
			warning:  "the chain of trust was already insecure above example.com., so the DS --try-ds gave was never checked"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2",
				DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: test.bareCom}})
			example := hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3",
				DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: test.unsigned, BadKeySignature: test.broken}})

			trial := trace.Trial{Zone: cmp.Or(test.zone, "example.com."), DS: test.ds(example)}
			cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t), Try: &trial}
			tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			chain := tr.Chain()
			if chain == nil || chain.DNSSEC.State != test.state || !strings.Contains(chain.DNSSEC.Reason, test.reason) {
				t.Fatalf("got %+v, want %s with %q: %s", chain, test.state, test.reason, format(steps(tr)))
			}
			if strings.Contains(test.reason, "give the parent") && !strings.HasSuffix(chain.DNSSEC.Reason, fmt.Sprint(example.DS(t).Tag)) {
				t.Errorf("got %q, want it to name key %d", chain.DNSSEC.Reason, example.DS(t).Tag)
			}

			replaced := 0
			for step := range tr.Steps() {
				if slices.Contains(step.Notes, "DS replaced by --try-ds") {
					replaced++
				}
			}
			if want := map[bool]int{true: 0, false: 1}[test.zone != ""]; replaced != want {
				t.Errorf("got %d steps marked replaced, want %d", replaced, want)
			}
			if test.warning != "" && !slices.Contains(tr.Warnings, test.warning) {
				t.Errorf("got %q, want %q", tr.Warnings, test.warning)
			}
		})
	}
}

// TestTrialMovesWithTheirDS covers a whole move tried at once: the zone
// delegated to a provider that signs with keys of its own, and the parent
// given the DS of those keys, which TestTrialKeepsTheParentsDS breaks without.
func TestTrialMovesWithTheirDS(t *testing.T) {
	t.Parallel()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: true})
	moved := hierarchy.Add(fakens.Config{Name: "ns1.new.co.uk.", Origin: "example.com.", Zone: movedZone, Declared: "192.0.2.9",
		DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: true}})

	trial := trace.Trial{Zone: "example.com.", NS: []string{"ns1.new.co.uk."},
		Addrs: map[string][]netip.Addr{"ns1.new.co.uk.": {netip.MustParseAddr("192.0.2.9")}},
		DS:    []trace.TrialDS{moved.DS(t)}}
	cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t), Try: &trial}
	tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if chain := tr.Chain(); chain == nil || chain.DNSSEC.State != trace.Secure {
		t.Fatalf("got %+v, want the new keys vouched for by the DS tried: %s", chain, format(steps(tr)))
	}
	if answer := tr.Result(); answer == nil || !slices.Equal(trace.Answers(answer.Records, "A"), []string{"192.0.2.99"}) {
		t.Errorf("got %+v, want the new provider's answer", answer)
	}
}

// TestTrialDSHiddenCut covers a DS tried for a zone the walk crosses into
// without a referral, from a server that serves both sides of the cut: the
// tried set stands in for the DS that query brings back, as it does for one a
// referral carries.
func TestTrialDSHiddenCut(t *testing.T) {
	t.Parallel()

	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
	hosted := h.hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "hosted.com.", Zone: hostedZone, Declared: "192.0.2.2",
		DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: true},
	})
	cfg.Try = &trace.Trial{Zone: "hosted.com.", DS: []trace.TrialDS{hosted.DS(t)}}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.hosted.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
		t.Fatalf("got %+v, want the answer vouched for by the DS tried: %s", answer, format(steps(tr)))
	}
	marked := false
	for step := range tr.Steps() {
		marked = marked || slices.Contains(step.Notes, "DS replaced by --try-ds")
	}
	if !marked {
		t.Errorf("got no step marked, want the DS query of hosted.com. marked: %s", format(steps(tr)))
	}
	if slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "--try-ds") }) {
		t.Errorf("got %q, want the trial counted as reached", tr.Warnings)
	}
}
