package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// csyncExampleZone is example.com. with room for the CSYNC under test, and a
// nameserver its parent has not been told about.
const csyncExampleZone = `
@     IN SOA  ns hostmaster 10 7200 3600 1209600 3600
@     IN NS   ns
@     IN NS   ns2
ns    IN A    192.0.2.3
ns2   IN A    192.0.2.33
www   IN A    192.0.2.10
`

// TestCheckCSYNC holds the CSYNC a zone publishes against the delegation its
// parent hands out, and says what a parent acting on it would change.
func TestCheckCSYNC(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		csync   string
		dnssec  bool
		broken  bool
		state   trace.CSYNCState
		changes []string
		warning string
	}{
		"a zone with no CSYNC": {
			dnssec: true,
			state:  trace.CSYNCNone,
		},
		"a signed CSYNC a parent acts on": {
			csync:   "@ IN CSYNC 10 3 NS A AAAA",
			dnssec:  true,
			state:   trace.CSYNCReady,
			changes: []string{"+NS ns2.example.com.", "+A ns2.example.com. 192.0.2.33"},
		},
		"a CSYNC waiting for a serial the zone has not reached": {
			csync:   "@ IN CSYNC 11 3 NS",
			dnssec:  true,
			state:   trace.CSYNCWaiting,
			changes: []string{"+NS ns2.example.com."},
			warning: "waits for serial 11 and the zone serves 10",
		},
		"a CSYNC that waits for someone to approve it": {
			csync:   "@ IN CSYNC 10 2 NS",
			dnssec:  true,
			state:   trace.CSYNCManual,
			changes: []string{"+NS ns2.example.com."},
		},
		"a CSYNC whose signature does not hold": {
			csync:   "@ IN CSYNC 10 3 NS",
			dnssec:  true,
			broken:  true,
			state:   trace.CSYNCUnproven,
			changes: []string{"+NS ns2.example.com."},
			warning: "is not one a parent acts on",
		},
		"a CSYNC nobody checked the signature of": {
			csync:   "@ IN CSYNC 10 3 NS",
			state:   trace.CSYNCUnchecked,
			changes: []string{"+NS ns2.example.com."},
		},
		"a CSYNC naming a type no parent copies": {
			csync:   "@ IN CSYNC 10 1 TXT",
			dnssec:  true,
			state:   trace.CSYNCReady,
			warning: "names TXT, which a parent does not copy",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{
				Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: test.dnssec,
			})
			hierarchy.Add(fakens.Config{
				Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: test.dnssec,
			})
			hierarchy.Add(fakens.Config{
				Name: "ns.example.com.", Origin: "example.com.", Zone: csyncExampleZone + test.csync, Declared: "192.0.2.3",
				DNSSEC: test.dnssec, Behaviour: fakens.Behaviour{BadSignature: test.broken},
			})
			cfg := resolver.Config{CheckNS: true}
			if test.dnssec {
				cfg.DNSSEC, cfg.Anchors = true, root.Anchors(t)
			}

			tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "example.com", "SOA")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			var csync *trace.CSYNC
			for step := range tr.Mainline() {
				if step.Delegation != nil && step.Delegation.CSYNC != nil {
					csync = step.Delegation.CSYNC
				}
			}
			if csync == nil || csync.State != test.state {
				t.Fatalf("got %+v, want %s: %s", csync, test.state, format(steps(tr)))
			}

			var changes []string
			for _, change := range csync.Changes {
				sign := "-"
				if change.Add {
					sign = "+"
				}
				changes = append(changes, strings.TrimSpace(sign+change.Type+" "+change.Name+" "+change.Data))
			}
			if !slices.Equal(changes, test.changes) {
				t.Errorf("got changes %q, want %q", changes, test.changes)
			}

			warnings := strings.Join(tr.Warnings, "\n")
			if test.warning != "" && !strings.Contains(warnings, test.warning) {
				t.Errorf("got warnings %q, want one saying %q", tr.Warnings, test.warning)
			}
			if test.warning == "" && strings.Contains(warnings, "CSYNC") {
				t.Errorf("got warnings %q, want none about the CSYNC", tr.Warnings)
			}
		})
	}
}

// TestCheckCSYNCHollowGlue is a CSYNC asking the parent to copy the address of
// a nameserver the zone gives none for, which leaves the parent nothing to
// copy and the delegation as broken as it was.
func TestCheckCSYNCHollowGlue(t *testing.T) {
	t.Parallel()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Declared: "192.0.2.3", DNSSEC: true,
		Zone: `
@     IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@     IN NS    ns
@     IN NS    ns3
ns    IN A     192.0.2.3
@     IN CSYNC 1 1 NS A
`,
	})
	cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t), CheckNS: true}

	tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "example.com", "SOA")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.Contains(strings.Join(tr.Warnings, "\n"), "asks its parent to copy the addresses of ns3.example.com., which the zone does not give") {
		t.Errorf("got warnings %q, want one saying ns3 has no address to copy", tr.Warnings)
	}
}

// A zone signed but not yet secure, served under two names of a DNS
// operator's own signed zone, the shape RFC 9615 bootstraps.
const (
	bootRootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
net.                IN NS   ns.net.
ns.net.             IN A    192.0.2.5
`
	bootComZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns1.provider.net.
example IN NS   ns2.provider.net.
`
	bootNetZone = `
@           IN SOA ns hostmaster 1 7200 3600 1209600 3600
@           IN NS  ns
ns          IN A   192.0.2.5
provider    IN NS  ns.provider
ns.provider IN A   192.0.2.30
`
	bootProviderZone = `
@   IN SOA ns hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns
ns  IN A   192.0.2.30
ns1 IN A   192.0.2.31
ns2 IN A   192.0.2.31
`
	bootExampleZone = `
@   IN SOA ns1.provider.net. hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns1.provider.net.
@   IN NS  ns2.provider.net.
www IN A   192.0.2.10
`
)

// TestBootstrap holds the signals the operator of each nameserver publishes
// for a zone asking for its first DS against what the zone itself asks for.
func TestBootstrap(t *testing.T) {
	t.Parallel()

	ns1 := "_dsboot.example.com._signal.ns1.provider.net."
	ns2 := "_dsboot.example.com._signal.ns2.provider.net."
	tests := map[string]struct {
		signals  func(request func(owner string) string) string
		provider fakens.Behaviour
		state    trace.BootstrapState
		each     []trace.SignalingState
		warning  string
	}{
		"every nameserver vouches for the request": {
			signals: func(request func(string) string) string { return request(ns1) + request(ns2) },
			state:   trace.BootstrapReady,
			each:    []trace.SignalingState{trace.SignalingMatched, trace.SignalingMatched},
		},
		"one nameserver publishes nothing": {
			signals: func(request func(string) string) string { return request(ns1) },
			state:   trace.BootstrapRefused,
			each:    []trace.SignalingState{trace.SignalingMatched, trace.SignalingMissing},
			warning: "nothing is published under ns2.provider.net.",
		},
		"one nameserver publishes the CDS alone": {
			signals: func(request func(string) string) string {
				cds, _, _ := strings.Cut(request(ns2), "\n")
				return request(ns1) + cds + "\n"
			},
			state:   trace.BootstrapRefused,
			each:    []trace.SignalingState{trace.SignalingMatched, trace.SignalingDiffers},
			warning: "under ns2.provider.net. does not say what the zone does",
		},
		"the operator's zone is not secure": {
			signals:  func(request func(string) string) string { return request(ns1) + request(ns2) },
			provider: fakens.Behaviour{NoDS: true},
			state:    trace.BootstrapRefused,
			each:     []trace.SignalingState{trace.SignalingUnproven, trace.SignalingUnproven},
			warning:  "does not validate, so it proves nothing",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: bootRootZone, Declared: "192.0.2.1", DNSSEC: true})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: bootComZone, Declared: "192.0.2.2", DNSSEC: true})
			hierarchy.Add(fakens.Config{Name: "ns.net.", Origin: "net.", Zone: bootNetZone, Declared: "192.0.2.5", DNSSEC: true})
			example := hierarchy.Add(fakens.Config{
				Name: "ns1.provider.net.", Origin: "example.com.", Zone: bootExampleZone, Declared: "192.0.2.31",
				DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: true, CDS: fakens.CDSCurrent},
			})
			request := func(owner string) string { return example.Request(t, owner) }
			hierarchy.Add(fakens.Config{
				Name: "ns.provider.net.", Origin: "provider.net.", Zone: bootProviderZone + test.signals(request), Declared: "192.0.2.30",
				// An opt-out range proves nothing absent, and a signal left out
				// of one would read as unproven rather than missing.
				DNSSEC: true, Denial: fakens.DenialNSEC, Behaviour: test.provider,
			})

			cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t), CheckDS: true}
			tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if answer := tr.Result(); answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Insecure {
				t.Fatalf("got %+v, want an insecure answer: %s", answer, format(steps(tr)))
			}

			signal := signalOf(tr)
			if signal == nil || signal.State != trace.SignalPending || signal.Bootstrap == nil {
				t.Fatalf("got %+v, want a request for a first DS", signal)
			}
			boot := signal.Bootstrap
			if boot.State != test.state {
				t.Errorf("got %s (%s), want %s", boot.State, boot.Reason, test.state)
			}
			var each []trace.SignalingState
			for _, s := range boot.Signals {
				each = append(each, s.State)
				if s.State == trace.SignalingMatched && !slices.Equal(s.Requested, signal.Requested) {
					t.Errorf("got %v asked for under %s, want %v", s.Requested, s.NS, signal.Requested)
				}
			}
			if !slices.Equal(each, test.each) {
				t.Errorf("got %v, want %v", each, test.each)
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

// TestBootstrapInsideOnly is a zone every nameserver of which is named inside
// it: whatever it publishes, there is nobody outside it to vouch for it.
func TestBootstrapInsideOnly(t *testing.T) {
	t.Parallel()

	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{},
		fakens.Behaviour{NoDS: true, CDS: fakens.CDSCurrent})
	cfg.CheckDS = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	signal := signalOf(tr)
	if signal == nil || signal.Bootstrap == nil || signal.Bootstrap.State != trace.BootstrapRefused {
		t.Fatalf("got %+v, want a bootstrap refused", signal)
	}
	if got := signal.Bootstrap.Signals; len(got) != 1 || got[0].State != trace.SignalingUnasked || got[0].Lookup != nil {
		t.Errorf("got %+v, want the one nameserver left unasked", got)
	}
	if !strings.Contains(strings.Join(tr.Warnings, "\n"), "every nameserver of it is named inside it") {
		t.Errorf("got warnings %q, want one saying nothing can vouch for it", tr.Warnings)
	}
}

// TestBootstrapBudget is a run whose budget runs out before the signals are
// looked up. The walk still ends, and the bootstrap says it was not checked.
func TestBootstrapBudget(t *testing.T) {
	t.Parallel()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: bootRootZone, Declared: "192.0.2.1", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: bootComZone, Declared: "192.0.2.2", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns.net.", Origin: "net.", Zone: bootNetZone, Declared: "192.0.2.5", DNSSEC: true})
	example := hierarchy.Add(fakens.Config{
		Name: "ns1.provider.net.", Origin: "example.com.", Zone: bootExampleZone, Declared: "192.0.2.31",
		DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: true, CDS: fakens.CDSCurrent},
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.provider.net.", Origin: "provider.net.", Declared: "192.0.2.30", DNSSEC: true,
		Zone: bootProviderZone + example.Request(t, "_dsboot.example.com._signal.ns1.provider.net.") +
			example.Request(t, "_dsboot.example.com._signal.ns2.provider.net."),
	})

	// Enough to reach the answer and fetch the zone's own request, and no more.
	cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t), CheckDS: true}
	full, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cfg.Budget = resolver.Budget{MaxQueries: queriesBefore(full, "bootstrap")}

	tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	signal := signalOf(tr)
	if signal == nil || signal.Bootstrap == nil {
		t.Fatalf("got %+v, want a request for a first DS", signal)
	}
	if signal.Bootstrap.State != trace.BootstrapUnchecked {
		t.Errorf("got %s (%s), want it unchecked", signal.Bootstrap.State, signal.Bootstrap.Reason)
	}
	if !strings.Contains(strings.Join(tr.Warnings, "\n"), "could not all be checked") {
		t.Errorf("got warnings %q, want one saying the signals went unchecked", tr.Warnings)
	}
}

// signalOf is the request the zone the walk ended in makes of its parent.
func signalOf(tr *trace.Trace) *trace.Signal {
	var signal *trace.Signal
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.Signal != nil {
			signal = step.DNSSEC.Signal
		}
	}
	return signal
}

// queriesBefore is how many queries a trace made before the first aside noted
// for purpose.
func queriesBefore(tr *trace.Trace, purpose string) int {
	n := 0
	for step := range tr.Steps() {
		if step.Kind == trace.KindZone {
			if step.Aside && slices.ContainsFunc(step.Notes, func(note string) bool { return strings.HasSuffix(note, " for "+purpose) }) {
				return n
			}
			continue
		}
		n++
	}
	return n
}
