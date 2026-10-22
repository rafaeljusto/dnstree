package tree_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderReverse(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.25")
	ptr := trace.Lookup{Name: "25.2.0.192.in-addr.arpa."}
	for name, tt := range map[string]struct {
		check *trace.Reverse
		want  []string
	}{
		"a name that points back": {
			check: &trace.Reverse{Addr: addr, PTR: ptr, Names: []trace.ReverseName{
				{Name: "mail.example.", Lookup: trace.Lookup{Name: "mail.example.", DNSSEC: &trace.DNSSECStatus{State: trace.Secure}},
					Addrs: []netip.Addr{addr}}}},
			want: []string{"ptr: mail.example. points back to 192.0.2.25  [secure]"},
		},
		"names that do not, each with its reason": {
			check: &trace.Reverse{Addr: addr, PTR: ptr, Names: []trace.ReverseName{
				{Name: "other.example.", Lookup: trace.Lookup{Name: "other.example.", Alias: "host.example."},
					Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.99")}},
				{Name: "gone.example.", Lookup: trace.Lookup{Name: "gone.example."}},
				{Name: "broken.example.", Lookup: trace.Lookup{Name: "broken.example.", Err: "SERVFAIL"}},
				{Name: "forged.example.", Lookup: trace.Lookup{Name: "forged.example.", DNSSEC: &trace.DNSSECStatus{State: trace.Bogus}},
					Addrs: []netip.Addr{addr}},
			}},
			want: []string{
				"ptr: other.example. (through host.example.) does not point back: it has 192.0.2.99, not 192.0.2.25",
				"ptr: gone.example. does not point back: it has no A record",
				"ptr: broken.example. was not confirmed: SERVFAIL",
				"ptr: forged.example. was not confirmed: its A set does not validate",
			},
		},
		"an address with no name": {
			check: &trace.Reverse{Addr: addr, PTR: ptr},
			want:  []string{"ptr: 192.0.2.25 has no name to point back to it"},
		},
		"a budget that ran out": {
			check: &trace.Reverse{Addr: addr, PTR: ptr, Cut: true, Names: []trace.ReverseName{
				{Name: "late.example.", Lookup: trace.Lookup{Name: "late.example.", Err: "the budget ran out before it was made"}}}},
			want: []string{
				"ptr: late.example. was not confirmed: the budget ran out before it was made",
				"ptr: the budget ran out before every name was looked up",
			},
		},
		"a PTR walk that failed is the summary's to say": {
			check: &trace.Reverse{Addr: addr, PTR: trace.Lookup{Name: ptr.Name, Err: "no server answered"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.Reverse = tt.check
			var got []string
			for line := range strings.Lines(draw(t, tr)) {
				if strings.HasPrefix(line, "ptr: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
