package resolver_test

import (
	"slices"
	"strings"
	"testing"
	"time"

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

// hostedZone is a child served by the machines of its parent, the way a
// registry serves both a ccTLD and its own domains. Nothing delegates to it:
// the server holding the parent answers for it straight away.
const hostedZone = `
@   IN SOA ns.com. hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns.com.
www IN A   192.0.2.11
`

// TestDNSSECHiddenCut covers a zone cut no referral crosses. A server
// authoritative for both sides of it answers for the child with the child's
// signatures, and a walk that only counts referrals is left checking them
// against the parent's keys, which calls a perfectly good answer bogus.
func TestDNSSECHiddenCut(t *testing.T) {
	tests := map[string]struct {
		hosted fakens.Behaviour
		state  trace.DNSSECState
		reason string
	}{
		"the child is properly signed": {
			state: trace.Secure,
		},
		"the keys of the child are not the ones vouched for": {
			hosted: fakens.Behaviour{StrayDNSKEY: true},
			state:  trace.Bogus,
			reason: "matches the DS",
		},
		"the child is not vouched for at all": {
			hosted: fakens.Behaviour{NoDS: true},
			state:  trace.Insecure,
			reason: "no DS",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
			// The same declared address as ns.com., so the walk never learns
			// there is a cut here except from the signatures.
			h.hierarchy.Add(fakens.Config{
				Name: "ns.com.", Origin: "hosted.com.", Zone: hostedZone, Declared: "192.0.2.2",
				DNSSEC: true, Behaviour: test.hosted,
			})

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.hosted.com", "A")
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
			if answer.Zone != "com." {
				t.Errorf("got the answer under %s, want the zone that was asked", answer.Zone)
			}
			if answer.DNSSEC == nil || answer.DNSSEC.State != test.state {
				t.Fatalf("got %+v on the answer, want %s: %s", answer.DNSSEC, test.state, format(steps(tr)))
			}
			if !strings.Contains(answer.DNSSEC.Reason, test.reason) {
				t.Errorf("got reason %q, want it to mention %q", answer.DNSSEC.Reason, test.reason)
			}

			// The cut is crossed where it happened: under the answer, with the
			// DS asked of the server that serves the parent side of it.
			var ds *trace.Step
			for _, step := range answer.Children {
				if len(step.Notes) > 0 && step.Notes[0] == "DS of hosted.com." {
					ds = step
				}
			}
			if ds == nil {
				t.Fatalf("the DS of hosted.com. was never asked for: %s", format(steps(tr)))
			}
			if !ds.Aside || len(ds.Records) != 0 {
				t.Errorf("got %+v for the DS query, want an aside with no records in the tree", ds)
			}
			if ds.DNSSEC == nil || ds.DNSSEC.State != test.state {
				t.Errorf("got %+v on the cut, want %s", ds.DNSSEC, test.state)
			}
		})
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
			reason:  "not signed by a key the DS points at",
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

// TestDNSSECExpiring signs the zone that answers for a fortnight and leaves it
// two days of that, where the zones above sign as the library does: the way a
// zone whose signer has stopped looks from outside. Everything validates, and
// the link late in its life is that one.
func TestDNSSECExpiring(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{},
		fakens.Behaviour{SignatureLeft: 48 * time.Hour})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
		t.Fatalf("got %+v, want a secure answer: %s", answer, format(steps(tr)))
	}
	if len(answer.DNSSEC.Signatures) == 0 {
		t.Fatal("got no signature lifetimes on the answer, want the one that held")
	}

	stale := tr.Stale()
	if stale == nil || !strings.EqualFold(stale.DNSSEC.Zone, "example.com.") {
		t.Fatalf("got %+v, want the verdict about example.com. late in its life", stale)
	}
	left, _ := tr.Expiring(stale.DNSSEC)
	if left < 47*time.Hour || left > 49*time.Hour {
		t.Errorf("got %s left, want about two days", left)
	}
	if _, ok := tr.Expiring(tr.Root.DNSSEC); ok {
		t.Error("got the root late in its life, want the fourteen days it was signed for")
	}
}

// TestCheckDS holds what the zone that answers asks its parent to publish, in
// its CDS and CDNSKEY, against the DS the parent publishes for it.
func TestCheckDS(t *testing.T) {
	tests := map[string]struct {
		example fakens.Behaviour
		state   trace.SignalState
		warning string
	}{
		"a zone that asks for nothing": {
			state: trace.SignalNone,
		},
		"a zone that asks for the key the parent holds": {
			example: fakens.Behaviour{CDS: fakens.CDSCurrent},
			state:   trace.SignalMatch,
		},
		"a zone rolling to a key the parent has not picked up": {
			example: fakens.Behaviour{CDS: fakens.CDSNext},
			state:   trace.SignalPending,
			warning: "a key rollover is waiting on the parent",
		},
		"a zone asking to be made insecure": {
			example: fakens.Behaviour{CDS: fakens.CDSDelete},
			state:   trace.SignalDelete,
			warning: "asks its parent to remove its DS",
		},
		"a CDS and a CDNSKEY for two different keys": {
			example: fakens.Behaviour{CDS: fakens.CDSMismatched},
			state:   trace.SignalInconsistent,
			warning: "do not describe the same keys",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, test.example)
			cfg.CheckDS = true

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if answer := tr.Result(); answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
				t.Fatalf("got %+v, want a secure answer: %s", answer, format(steps(tr)))
			}

			var signal *trace.Signal
			for step := range tr.Mainline() {
				if step.Delegation != nil && strings.EqualFold(step.Delegation.Zone, "example.com.") && step.DNSSEC != nil {
					signal = step.DNSSEC.Signal
				}
			}
			if signal == nil || signal.State != test.state {
				t.Fatalf("got %+v, want %s", signal, test.state)
			}
			if test.state == trace.SignalMatch && (len(signal.Requested) != 1 || !slices.Equal(signal.Requested, signal.Held)) {
				t.Errorf("got %v asked for and %v held, want the same key", signal.Requested, signal.Held)
			}

			warnings := strings.Join(tr.Warnings, "\n")
			switch {
			case test.warning == "" && warnings != "":
				t.Errorf("got warnings %q, want none", tr.Warnings)
			case test.warning != "" && !strings.Contains(warnings, test.warning):
				t.Errorf("got warnings %q, want one saying %q", tr.Warnings, test.warning)
			}
		})
	}
}

// TestCheckDSUnsigned is a zone whose signatures do not verify. Its request of
// the parent is nobody's, and is reported as unchecked rather than read.
func TestCheckDSUnsigned(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{},
		fakens.Behaviour{CDS: fakens.CDSNext, BadSignature: true})
	cfg.CheckDS = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var signal *trace.Signal
	for step := range tr.Mainline() {
		if step.DNSSEC != nil && step.DNSSEC.Signal != nil {
			signal = step.DNSSEC.Signal
		}
	}
	if signal == nil || signal.State != trace.SignalUnchecked || !strings.Contains(signal.Reason, "CDS is bogus") {
		t.Errorf("got %+v, want an unsigned request left unread", signal)
	}
	if !strings.Contains(strings.Join(tr.Warnings, "\n"), "could not be checked") {
		t.Errorf("got warnings %q, want one saying the request went unread", tr.Warnings)
	}
}

// TestCheckDSHiddenCut is a zone served by the machines of its parent, which the
// walk crosses into without a referral: its DS comes from the query made to
// cross the cut, and its request is held against that.
func TestCheckDSHiddenCut(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.CheckDS = true
	h.hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "hosted.com.", Zone: hostedZone, Declared: "192.0.2.2",
		DNSSEC: true, Behaviour: fakens.Behaviour{CDS: fakens.CDSNext},
	})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.hosted.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var signal *trace.Signal
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.Signal != nil {
			signal = step.DNSSEC.Signal
		}
	}
	if signal == nil || signal.State != trace.SignalPending {
		t.Fatalf("got %+v, want the rollover of hosted.com. seen: %s", signal, format(steps(tr)))
	}
}

// TestCheckDSInsecure is a zone the chain did not reach secure. There are no
// keys to check its request with, and it is left unread rather than skipped
// without a word.
func TestCheckDSInsecure(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{},
		fakens.Behaviour{NoDS: true, CDS: fakens.CDSCurrent})
	cfg.CheckDS = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var signal *trace.Signal
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.Signal != nil {
			signal = step.DNSSEC.Signal
		}
	}
	if signal == nil || signal.State != trace.SignalUnchecked || !strings.Contains(signal.Reason, "did not reach") {
		t.Errorf("got %+v, want the request left unread", signal)
	}
}
