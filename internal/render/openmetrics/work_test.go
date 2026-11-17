package openmetrics_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderWork(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindReferral, Delegation: &trace.Delegation{Zone: "test."},
			DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "test.", Keys: []trace.Key{
				{Tag: 7, Algorithm: "ED25519"}, {Tag: 7, Algorithm: "ED25519"}, {Tag: 7, Algorithm: "ECDSAP256SHA256"}, {Tag: 9, Algorithm: "ED25519"},
			}},
		}}},
		Dependencies: &trace.Dependencies{Name: "www.test.", Work: []trace.ZoneWork{
			{Zone: "test.", Queries: 5, Glueless: 3, Depth: 1, Via: "ns.other."},
		}},
	}
	out := render(t, tr)
	valid(t, out)
	for _, want := range []string{
		`dnstree_deps_queries{name="www.test.",type="A",zone="test."} 5`,
		`dnstree_deps_glueless_queries{name="www.test.",type="A",zone="test."} 3`,
		`dnstree_deps_glueless_depth{name="www.test.",type="A",zone="test."} 1`,
		`dnstree_dnssec_keys_per_tag{name="www.test.",type="A",zone="test."} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got\n%s\nwant %s", out, want)
		}
	}

	tr.Dependencies = nil
	tr.Root.Children[0].DNSSEC.Keys = nil
	if out := render(t, tr); strings.Contains(out, "dnstree_deps_") || strings.Contains(out, "dnstree_dnssec_keys_per_tag") {
		t.Errorf("got\n%s\nwant no work family where nothing counted it", out)
	}
}
