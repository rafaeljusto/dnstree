package openmetrics_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderSRV(t *testing.T) {
	addr := []netip.Addr{netip.MustParseAddr("192.0.2.7")}
	tr := &trace.Trace{
		Question: trace.Question{Name: "_xmpp._tcp.test.", Type: "SRV"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		SRV: &trace.SRV{Name: "_xmpp._tcp.test.", Targets: []trace.SRVTarget{
			{Name: "chat.test.", Port: 5222, Addrs: addr},
			{Name: "chat.test.", Port: 5223, Addrs: addr},
			{Name: "gone.test.", Port: 5222, IPv4: &trace.Lookup{Name: "gone.test."}},
		}},
	}
	out := render(t, tr)
	valid(t, out)
	if want := `dnstree_srv_targets{name="_xmpp._tcp.test.",type="SRV"} 1`; !strings.Contains(out, want) {
		t.Errorf("got\n%s\nwant %s", out, want)
	}

	tr.SRV.Cut = true
	if out := render(t, tr); strings.Contains(out, "dnstree_srv") {
		t.Errorf("got\n%s\nwant no count the budget cut short", out)
	}
}
