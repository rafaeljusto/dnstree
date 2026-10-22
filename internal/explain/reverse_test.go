package explain_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestReverse(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.25")
	ptr := trace.Lookup{Name: "25.2.0.192.in-addr.arpa."}
	back := trace.ReverseName{Name: "mail.example.", Lookup: trace.Lookup{Name: "mail.example."}, Addrs: []netip.Addr{addr}}
	elsewhere := trace.ReverseName{Name: "other.example.", Lookup: trace.Lookup{Name: "other.example."},
		Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.99")}}
	for name, tt := range map[string]struct {
		check *trace.Reverse
		want  string // empty for no finding about it
	}{
		"a name that points back": {
			check: &trace.Reverse{Addr: addr, PTR: ptr, Names: []trace.ReverseName{elsewhere, back}},
			want:  "mail.example. points back to 192.0.2.25, so the address is forward-confirmed",
		},
		"names that do not, each with its reason": {
			check: &trace.Reverse{Addr: addr, PTR: ptr, Names: []trace.ReverseName{elsewhere,
				{Name: "gone.example.", Lookup: trace.Lookup{Name: "gone.example."}},
				{Name: "broken.example.", Lookup: trace.Lookup{Name: "broken.example.", Err: "SERVFAIL"}}}},
			want: "no name the PTR of 192.0.2.25 gives points back to it, so a mail receiver that checks forward-confirmed reverse DNS distrusts it: " +
				"other.example. has 192.0.2.99; gone.example. has no A record; the A lookup of broken.example. failed (SERVFAIL)",
		},
		"an address with no name": {
			check: &trace.Reverse{Addr: addr, PTR: ptr},
			want:  "192.0.2.25 has no name",
		},
		"a budget that ran out before a name that points back": {
			check: &trace.Reverse{Addr: addr, PTR: ptr, Cut: true, Names: []trace.ReverseName{elsewhere,
				{Name: "late.example.", Lookup: trace.Lookup{Name: "late.example.", Err: "the budget ran out before it was made"}}}},
			want: "ran out of budget before every name was looked up, and none of those it reached points back",
		},
		"a PTR walk that failed": {
			check: &trace.Reverse{Addr: addr, PTR: trace.Lookup{Name: ptr.Name, Err: "no server answered"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := walk(answered(300))
			tr.Reverse = tt.check
			got := said(tr)
			if tt.want == "" && strings.Contains(got, "point back") {
				t.Errorf("got %q, want nothing about pointing back", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want it to say %q", got, tt.want)
			}
		})
	}
}
