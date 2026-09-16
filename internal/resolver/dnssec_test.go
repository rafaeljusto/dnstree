package resolver_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/resolver"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// signed builds the same three zones as the plain hierarchy, all signed, with
// one link broken by behaviour.
func signed(tb testing.TB, root, com, example fakens.Behaviour) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	rootServer := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1",
		DNSSEC: true, Behaviour: root,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2",
		DNSSEC: true, Behaviour: com,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3",
		DNSSEC: true, Behaviour: example,
	})

	return harness{hierarchy, rootServer}, resolver.Config{
		DNSSEC:  true,
		Anchors: rootServer.Anchors(tb),
	}
}

// TestDNSSECSecure walks a hierarchy signed from the root down, which is the
// only case where every link has to hold.
func TestDNSSECSecure(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(tr.Warnings) != 0 {
		t.Errorf("got warnings %q, want none", tr.Warnings)
	}

	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want an answer: %s", answer, format(steps(tr)))
	}
	if answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
		t.Fatalf("got %+v on the answer, want it secure", answer.DNSSEC)
	}
	if answer.DNSSEC.Algorithm != "ECDSAP256SHA256" {
		t.Errorf("got algorithm %q, want the one the zone signs with", answer.DNSSEC.Algorithm)
	}
	if len(answer.DNSSEC.KeyTags) != 1 {
		t.Errorf("got key tags %v, want the one that signed the answer", answer.DNSSEC.KeyTags)
	}

	// Every zone cut vouched for the one below it, starting at the anchors.
	if root := tr.Root.DNSSEC; root == nil || root.State != trace.Secure {
		t.Errorf("got %+v on the root, want the anchors to match its keys", root)
	}
	for _, step := range steps(tr) {
		if step.Kind != trace.KindReferral {
			continue
		}
		if step.DNSSEC == nil || step.DNSSEC.State != trace.Secure {
			t.Errorf("got %+v on the referral from %s, want it secure", step.DNSSEC, step.Zone)
		}
		if step.DNSSEC.Digest != "SHA256" {
			t.Errorf("got digest %q on the referral from %s, want the DS digest", step.DNSSEC.Digest, step.Zone)
		}
	}
}

// TestDNSSECBroken covers one broken link at a time, each of which has its own
// verdict: a missing DS is not a failure, a missing key set is not a forgery,
// and a signature that does not verify is.
func TestDNSSECBroken(t *testing.T) {
	tests := map[string]struct {
		example fakens.Behaviour
		state   trace.DNSSECState
		reason  string
	}{
		"the parent vouches for nobody": {
			example: fakens.Behaviour{NoDS: true},
			state:   trace.Insecure,
			reason:  "no DS",
		},
		"the keys cannot be fetched": {
			example: fakens.Behaviour{NoDNSKEY: true},
			state:   trace.Indeterminate,
			reason:  "could not be fetched",
		},
		"the keys are not the ones vouched for": {
			example: fakens.Behaviour{StrayDNSKEY: true},
			state:   trace.Bogus,
			reason:  "matches the DS",
		},
		"the key set did not sign itself": {
			example: fakens.Behaviour{BadKeySignature: true},
			state:   trace.Bogus,
			reason:  "not signed by the key the DS points at",
		},
		"the answer is not signed by the keys": {
			example: fakens.Behaviour{BadSignature: true},
			state:   trace.Bogus,
			reason:  "does not verify",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, test.example)

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			answer := tr.Result()
			if answer == nil {
				t.Fatalf("got no answer, want one that does not check out: %s", format(steps(tr)))
			}
			if answer.DNSSEC == nil || answer.DNSSEC.State != test.state {
				t.Fatalf("got %+v on the answer, want %s", answer.DNSSEC, test.state)
			}
			if !strings.Contains(answer.DNSSEC.Reason, test.reason) {
				t.Errorf("got reason %q, want it to mention %q", answer.DNSSEC.Reason, test.reason)
			}

			// Whatever went wrong, the records still came back: the tool says
			// what it found rather than refusing to show it.
			if len(answer.Records) != 1 {
				t.Errorf("got %d records, want the answer shown anyway", len(answer.Records))
			}
		})
	}
}

// TestDNSSECInsecureIsInherited covers an unsigned zone in the middle: nothing
// below it can be secure again, however well signed it is.
func TestDNSSECInsecureIsInherited(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{NoDS: true}, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Insecure {
		t.Fatalf("got %+v on the answer, want it insecure all the way down: %s", answer.DNSSEC, format(steps(tr)))
	}
	if root := tr.Root.DNSSEC; root == nil || root.State != trace.Secure {
		t.Errorf("got %+v on the root, want the part above the gap to stay secure", root)
	}
}

// TestDNSSECUnsignedHierarchy covers the ordinary case: nothing is signed, so
// nothing is bogus either.
func TestDNSSECUnsignedHierarchy(t *testing.T) {
	h := internet(t)
	root := h.root.Nameserver()

	res := newResolver(t, h, resolver.Config{DNSSEC: true, Roots: []trace.Server{root}})
	tr, err := res.Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil {
		t.Fatalf("got %+v, want a verdict: %s", answer, format(steps(tr)))
	}
	// The embedded anchors do not match a fake root, so the chain cannot start.
	if answer.DNSSEC.State == trace.Secure {
		t.Errorf("got %+v, want anything but secure against the real anchors", answer.DNSSEC)
	}
}

// TestDNSSECAsksForKeys covers the shape of the extra work: the key set of each
// zone is fetched once, as an aside that never hides the answer.
func TestDNSSECAsksForKeys(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	asked := map[string]int{}
	for _, step := range steps(tr) {
		for _, note := range step.Notes {
			if zone, found := strings.CutPrefix(note, "DNSKEY of "); found {
				asked[zone]++
				if !step.Aside {
					t.Errorf("the DNSKEY query for %s is not marked aside", zone)
				}
				if len(step.Records) != 0 {
					t.Errorf("got records on the DNSKEY query for %s, want them left out of the tree", zone)
				}
			}
		}
	}

	for _, zone := range []string{".", "com.", "example.com."} {
		if asked[zone] != 1 {
			t.Errorf("asked %s for its keys %d times, want once", zone, asked[zone])
		}
	}
}
