package openmetrics_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderServicePath(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.7")
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "HTTPS"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		ServicePath: &trace.ServicePath{Name: "www.test.", Type: "HTTPS", Targets: []trace.ServiceTarget{
			{Name: "edge.test.", Addrs: []netip.Addr{addr}, Stray: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
			{Name: "gone.test.", IPv4: &trace.Lookup{Name: "gone.test."}},
		}},
	}
	out := render(t, tr)
	valid(t, out)
	for _, want := range []string{
		`dnstree_svcb_targets{name="www.test.",type="HTTPS"} 1`,
		`dnstree_svcb_stray_hints{name="www.test.",type="HTTPS"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got\n%s\nwant %s", out, want)
		}
	}

	tr.ServicePath.Cut = true
	if out := render(t, tr); strings.Contains(out, "dnstree_svcb_stray_hints") {
		t.Errorf("got\n%s\nwant no count of hints the budget left unjudged", out)
	}

	tr.ServicePath = nil
	if out := render(t, tr); strings.Contains(out, "dnstree_svcb") {
		t.Errorf("got\n%s\nwant no svcb family", out)
	}
}
