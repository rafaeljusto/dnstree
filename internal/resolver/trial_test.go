package resolver_test

import (
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
