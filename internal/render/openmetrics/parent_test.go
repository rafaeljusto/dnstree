package openmetrics_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderRequests(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindReferral,
			Delegation: &trace.Delegation{Zone: "test.", CSYNC: &trace.CSYNC{State: trace.CSYNCReady,
				Changes: []trace.DelegationChange{{Add: true, Type: "NS", Name: "ns2.test."}}}},
			DNSSEC: &trace.DNSSECStatus{State: trace.Insecure, Signal: &trace.Signal{State: trace.SignalPending,
				Requested: []uint16{7}, Bootstrap: &trace.Bootstrap{State: trace.BootstrapRefused}}},
		}}},
	}
	out := render(t, tr)
	valid(t, out)
	for _, want := range []string{
		`dnstree_bootstrap{name="www.test.",type="A",state="refused"} 1`,
		`dnstree_csync{name="www.test.",type="A",state="ready"} 1`,
		`dnstree_csync_changes{name="www.test.",type="A"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got\n%s\nwant %s", out, want)
		}
	}

	tr.Root.Children[0].Delegation.CSYNC.State = trace.CSYNCNone
	tr.Root.Children[0].DNSSEC.Signal.Bootstrap = nil
	if out := render(t, tr); strings.Contains(out, "dnstree_csync") || strings.Contains(out, "dnstree_bootstrap") {
		t.Errorf("got\n%s\nwant no csync or bootstrap family", out)
	}
}
