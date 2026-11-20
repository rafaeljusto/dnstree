package resolver_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// example.com. served by two providers, each signing with keys of its own and
// publishing the other's (RFC 8901), the way a zone moving between providers or
// kept on two for redundancy looks.
const (
	providersComZone = `
@           IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@           IN NS   ns
ns          IN A    192.0.2.2
example     IN NS   ns1.example
example     IN NS   ns2.example
ns1.example IN A    192.0.2.3
ns2.example IN A    192.0.2.5
`
	// providersZone takes the serial each provider serves, and then whatever
	// it publishes as a request of the parent.
	providersZone = `
@     IN SOA  ns1 hostmaster %d 7200 3600 1209600 3600
@     IN NS   ns1
@     IN NS   ns2
ns1   IN A    192.0.2.3
ns2   IN A    192.0.2.5
www   IN A    192.0.2.10
`
)

// provider is what one provider serves beyond the zone itself, given both
// servers so that it can ask for either's key.
type provider struct {
	serial   uint32
	requests func(t *testing.T, one, two *fakens.Server) string
	drop     bool // never answers
	alone    bool // does not publish the other's key, so its answers do not verify
}

// providers builds that hierarchy and hands back a config that walks it.
func providers(t *testing.T, first, second provider) (harness, resolver.Config) {
	t.Helper()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: providersComZone, Declared: "192.0.2.2", DNSSEC: true})
	one := hierarchy.Add(fakens.Config{Name: "ns1.example.com.", Origin: "example.com.", Zone: fmt.Sprintf(providersZone, 1), Declared: "192.0.2.3", DNSSEC: true})
	two := hierarchy.Add(fakens.Config{Name: "ns2.example.com.", Origin: "example.com.", Zone: fmt.Sprintf(providersZone, 1), Declared: "192.0.2.5", DNSSEC: true,
		Behaviour: fakens.Behaviour{Drop: second.drop}})
	two.Cosign(t, one)
	if !second.alone {
		one.Cosign(t, two)
	}
	for _, each := range []struct {
		server *fakens.Server
		serves provider
	}{{one, first}, {two, second}} {
		zone := fmt.Sprintf(providersZone, max(each.serves.serial, 1))
		if each.serves.requests != nil {
			zone += each.serves.requests(t, one, two)
		}
		each.server.Replace(t, zone)
	}
	return harness{hierarchy, root}, resolver.Config{DNSSEC: true, Anchors: root.Anchors(t)}
}

// Requests either provider can publish.
var (
	bothKeys = func(t *testing.T, one, two *fakens.Server) string {
		return one.Request(t, "@") + two.Request(t, "@")
	}
	ownKey = func(t *testing.T, one, _ *fakens.Server) string { return one.Request(t, "@") }
	theirs = func(t *testing.T, _, two *fakens.Server) string { return two.Request(t, "@") }
	remove = func(*testing.T, *fakens.Server, *fakens.Server) string {
		return "@ IN CDS 0 0 0 00\n@ IN CDNSKEY 0 3 0 AA==\n"
	}
	csync = func(record string) func(*testing.T, *fakens.Server, *fakens.Server) string {
		return func(*testing.T, *fakens.Server, *fakens.Server) string { return "@ IN CSYNC " + record + "\n" }
	}
)

// TestRequestsAgree covers RFC 9975: a parent asks every nameserver for the
// zone's CDS and CDNSKEY and acts on nothing unless every answer it got asks for
// the same keys. A walk reads them from one server, so a provider that alone
// asks for a key, or alone asks for nothing, is what it has to go looking for.
func TestRequestsAgree(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		first, second provider
		state         trace.AgreementState
		warning       string
	}{
		"both providers ask for both keys": {
			first: provider{requests: bothKeys}, second: provider{requests: bothKeys},
			state: trace.AgreementSame,
		},
		"neither provider asks for anything": {
			state: trace.AgreementSame,
		},
		"one provider asks for both keys and the other for nothing": {
			first: provider{requests: bothKeys},
			state: trace.AgreementDiffer, warning: "ns2.example.com. asks for nothing",
		},
		"each provider asks for its own key alone": {
			first: provider{requests: ownKey}, second: provider{requests: theirs},
			state: trace.AgreementDiffer, warning: "do not make the same request of the parent",
		},
		"one provider asks for the DS to go and the other for keys": {
			first: provider{requests: remove}, second: provider{requests: bothKeys},
			state: trace.AgreementDiffer, warning: "ns1.example.com. asks for no DS at all",
		},
		"a provider whose answers do not verify": {
			first: provider{requests: bothKeys}, second: provider{requests: bothKeys, alone: true},
			state: trace.AgreementDiffer, warning: "ns2.example.com. serves it with a signature that does not hold",
		},
		"a provider that does not answer": {
			first: provider{requests: bothKeys}, second: provider{requests: remove, drop: true},
			state: trace.AgreementPartial, warning: "ns2.example.com. did not answer for the CDS and CDNSKEY",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := providers(t, test.first, test.second)
			cfg.CheckDS = true
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if chain := tr.Chain(); chain == nil || chain.DNSSEC.State != trace.Secure {
				t.Fatalf("got %+v, want a secure walk: whether the servers agree is not the chain's to change", chain)
			}

			signal := signalOf(tr)
			if signal == nil || signal.Agreement == nil {
				t.Fatalf("got %+v, want every server asked: %s", signal, format(steps(tr)))
			}
			if signal.Agreement.State != test.state {
				t.Errorf("got %s %+v, want %s", signal.Agreement.State, signal.Agreement.Servers, test.state)
			}
			if got := len(signal.Agreement.Servers); got != 2 {
				t.Errorf("got %d servers, want both", got)
			}
			assertWarning(t, tr, "the same request of the parent", test.warning)
			if test.state == trace.AgreementDiffer && strings.Contains(strings.Join(tr.Warnings, "\n"), "waiting on the parent") {
				t.Errorf("got %q, want the disagreement alone named as why the parent waits", tr.Warnings)
			}
		})
	}
}

// TestRequestsAgreeOnOneServer is a zone with one address: there is nothing to
// hold its request against, and nothing is asked again.
func TestRequestsAgreeOnOneServer(t *testing.T) {
	t.Parallel()

	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{CDS: fakens.CDSNext})
	cfg.CheckDS = true
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if signal := signalOf(tr); signal == nil || signal.State != trace.SignalPending || signal.Agreement != nil {
		t.Fatalf("got %+v, want a pending request held against nothing", signal)
	}
}

// TestRequestsAgreeWithinBudget is a run whose budget runs out halfway through
// asking the servers. The walk still ends, and what was not asked is no
// difference.
func TestRequestsAgreeWithinBudget(t *testing.T) {
	t.Parallel()

	h, cfg := providers(t, provider{requests: bothKeys}, provider{requests: remove})
	cfg.CheckDS = true
	full, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Enough for every question but the last server's CDNSKEY.
	cfg.Budget = resolver.Budget{MaxQueries: queriesThrough(full, "request check: ") - 1}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	signal := signalOf(tr)
	if signal == nil || signal.Agreement == nil {
		t.Fatalf("got %+v, want the servers asked as far as the budget went", signal)
	}
	if signal.Agreement.State != trace.AgreementPartial || signal.Agreement.Reason == "" {
		t.Errorf("got %s (%q), want it partial, saying why", signal.Agreement.State, signal.Agreement.Reason)
	}
	assertWarning(t, tr, "budget ran out", "before every nameserver of example.com. could be asked")
}

// TestCSYNCAgree is the same rule for a CSYNC (RFC 9975 3.2): its flags and its
// types have to agree, each server's serial is held against that server's own
// SOA, and the NS set it asks to be copied has to be the same everywhere.
func TestCSYNCAgree(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		first, second provider
		state         trace.AgreementState
		warning       string
	}{
		"both servers ask for the same NS set": {
			first: provider{requests: csync("1 1 NS")}, second: provider{requests: csync("1 1 NS")},
			state: trace.AgreementSame,
		},
		"one server has a CSYNC and the other none": {
			first: provider{requests: csync("1 1 NS")},
			state: trace.AgreementDiffer, warning: "ns2.example.com. asks for nothing",
		},
		"one server waits for approval and the other does not": {
			first: provider{requests: csync("1 1 NS")}, second: provider{requests: csync("1 0 NS")},
			state: trace.AgreementDiffer, warning: "once approved",
		},
		"one server has reached the serial and the other has not": {
			first:  provider{serial: 3, requests: csync("3 3 NS")},
			second: provider{serial: 2, requests: csync("3 3 NS")},
			state:  trace.AgreementDiffer, warning: "once serial 3 is served",
		},
		"two servers with different serials that both reached their own": {
			first:  provider{serial: 5, requests: csync("5 3 NS")},
			second: provider{serial: 9, requests: csync("8 3 NS")},
			state:  trace.AgreementSame,
		},
		"two servers serving different NS sets": {
			first: provider{requests: csync("1 1 NS")},
			second: provider{requests: func(t *testing.T, one, two *fakens.Server) string {
				return csync("1 1 NS")(t, one, two) + "@ IN NS ns3.example.net.\n"
			}},
			state: trace.AgreementDiffer, warning: "ns3.example.net.",
		},
		"a server whose answers do not verify": {
			first: provider{requests: csync("1 1 NS")}, second: provider{requests: csync("1 1 NS"), alone: true},
			state: trace.AgreementDiffer, warning: "ns2.example.com. serves it with a signature that does not hold",
		},
		"a server that does not answer": {
			first: provider{requests: csync("1 1 NS")}, second: provider{drop: true},
			state: trace.AgreementPartial, warning: "ns2.example.com. did not answer for the CSYNC",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := providers(t, test.first, test.second)
			cfg.CheckNS = true
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			var agreement *trace.Agreement
			for step := range tr.Mainline() {
				if step.Delegation != nil && step.Delegation.CSYNC != nil && strings.EqualFold(step.Delegation.Zone, "example.com.") {
					agreement = step.Delegation.CSYNC.Agreement
				}
			}
			if agreement == nil {
				t.Fatalf("got no agreement, want every server asked: %s", format(steps(tr)))
			}
			if agreement.State != test.state {
				t.Errorf("got %s %+v, want %s", agreement.State, agreement.Servers, test.state)
			}
			assertWarning(t, tr, "CSYNC", test.warning)
		})
	}
}

// TestCSYNCAgreeNeedsDNSSEC is --check-ns without --dnssec: no answer can be
// told from a forged one, so the servers are not compared.
func TestCSYNCAgreeNeedsDNSSEC(t *testing.T) {
	t.Parallel()

	h, _ := providers(t, provider{requests: csync("1 1 NS")}, provider{})
	cfg := resolver.Config{CheckNS: true}
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for step := range tr.Mainline() {
		if step.Delegation != nil && step.Delegation.CSYNC != nil && step.Delegation.CSYNC.Agreement != nil {
			t.Fatalf("got %+v, want nothing compared", step.Delegation.CSYNC.Agreement)
		}
	}
}

// assertWarning checks the warnings about one subject: none where want is
// empty, and one saying want where it is not.
func assertWarning(t *testing.T, tr *trace.Trace, about, want string) {
	t.Helper()

	var found []string
	for _, warning := range tr.Warnings {
		if strings.Contains(warning, about) || want != "" && strings.Contains(warning, want) {
			found = append(found, warning)
		}
	}
	switch {
	case want == "" && len(found) > 0:
		t.Errorf("got %q, want no warning about %s", found, about)
	case want != "" && !strings.Contains(strings.Join(found, "\n"), want):
		t.Errorf("got %q, want one saying %q", tr.Warnings, want)
	}
}

// queriesThrough is how many queries a trace made up to and including the last
// aside noted with prefix.
func queriesThrough(tr *trace.Trace, prefix string) int {
	n, last := 0, 0
	for step := range tr.Steps() {
		if step.Kind == trace.KindZone {
			continue
		}
		n++
		for _, note := range step.Notes {
			if strings.HasPrefix(note, prefix) {
				last = n
			}
		}
	}
	return last
}
