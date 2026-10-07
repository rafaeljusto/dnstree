package explain_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestService(t *testing.T) {
	asked := &trace.Lookup{Name: "edge.example."}
	addr := []netip.Addr{netip.MustParseAddr("192.0.2.7")}
	twoSets := []trace.ServiceSet{{Lookup: trace.Lookup{Name: "test."}}, {Lookup: trace.Lookup{Name: "cdn.example."}}}
	for name, tt := range map[string]struct {
		path *trace.ServicePath
		want string
	}{
		"a target reached through an alias": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Chain: twoSets,
				Targets: []trace.ServiceTarget{{Name: "edge.example.", IPv4: asked, Addrs: addr}}},
			want: "a client that reads the HTTPS records of test. connects to edge.example. through 1 alias",
		},
		"a hint that is not the target's": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Chain: twoSets[:1],
				Targets: []trace.ServiceTarget{{Name: "edge.example.", IPv4: asked, Addrs: addr,
					Stray: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}}},
			want: "hint at addresses edge.example. does not have",
		},
		"a target with no address": {
			path: &trace.ServicePath{Name: "test.", Type: "SVCB", Chain: twoSets[:1],
				Targets: []trace.ServiceTarget{{Name: "edge.example.", IPv4: asked}}},
			want: "lead to edge.example., which has no address",
		},
		"a target whose address lookups failed": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Chain: twoSets[:1],
				Targets: []trace.ServiceTarget{{Name: "edge.example.", IPv4: &trace.Lookup{Name: "edge.example.", Err: "SERVFAIL"}}}},
			want: "lead to edge.example., whose addresses could not be looked up",
		},
		"no records at all": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Fallback: true, Chain: twoSets[:1]},
			want: "test. publishes no HTTPS records, so a client connects as it would without them",
		},
		"an alias to a name with no records": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Fallback: true, Chain: twoSets,
				Targets: []trace.ServiceTarget{{Name: "cdn.example.", IPv4: asked, Addrs: addr}}},
			want: "the HTTPS aliases of test. end at cdn.example., which has no records",
		},
		"an alias to .": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", None: true, Chain: twoSets[:1]},
			want: "test. says, with an alias to ., that it offers no service",
		},
		"a chain that stopped": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Chain: twoSets, Stopped: "the aliases loop back to test."},
			want: "the HTTPS check of test. stopped: the aliases loop back to test.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := walk(answered(300))
			tr.ServicePath = tt.path
			if got := said(tr); !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want it to say %q", got, tt.want)
			}
		})
	}
}
