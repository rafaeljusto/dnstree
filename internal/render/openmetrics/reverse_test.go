package openmetrics_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderReverse(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.25")
	tr := &trace.Trace{
		Question: trace.Question{Name: "25.2.0.192.in-addr.arpa.", Type: "PTR"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		Reverse: &trace.Reverse{Addr: addr, PTR: trace.Lookup{Name: "25.2.0.192.in-addr.arpa."}, Names: []trace.ReverseName{
			{Name: "mail.test.", Lookup: trace.Lookup{Name: "mail.test."}, Addrs: []netip.Addr{addr}}}},
	}
	out := render(t, tr)
	valid(t, out)
	if want := `dnstree_ptr_confirmed{name="25.2.0.192.in-addr.arpa.",type="PTR"} 1`; !strings.Contains(out, want) {
		t.Errorf("got\n%s\nwant %s", out, want)
	}

	tr.Reverse.Names[0].Addrs = nil
	if want := `dnstree_ptr_confirmed{name="25.2.0.192.in-addr.arpa.",type="PTR"} 0`; !strings.Contains(render(t, tr), want) {
		t.Errorf("want %s", want)
	}

	tr.Reverse.Cut = true
	if out := render(t, tr); strings.Contains(out, "dnstree_ptr_confirmed") {
		t.Errorf("got\n%s\nwant no verdict the budget left unsaid", out)
	}

	tr.Reverse = nil
	if out := render(t, tr); strings.Contains(out, "dnstree_ptr") {
		t.Errorf("got\n%s\nwant no ptr family", out)
	}
}
