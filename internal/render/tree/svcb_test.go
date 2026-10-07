package tree_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderServicePath(t *testing.T) {
	secure := &trace.DNSSECStatus{State: trace.Secure}
	answered := &trace.Lookup{Name: "test."}
	alias := trace.RR{Name: "test.", Type: "HTTPS", Data: "0 cdn.example.", Service: &trace.Service{Target: "cdn.example."}}
	for name, tt := range map[string]struct {
		path *trace.ServicePath
		want []string
	}{
		"an alias to a server whose hints are its addresses": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS",
				Chain: []trace.ServiceSet{
					{Lookup: trace.Lookup{Name: "test.", DNSSEC: secure}, Records: []trace.RR{alias}},
					{Lookup: trace.Lookup{Name: "cdn.example."}, Records: []trace.RR{{Name: "cdn.example.", Type: "HTTPS", Data: "1 . ipv4hint=192.0.2.1",
						Service: &trace.Service{Priority: 1, Target: "."}}}},
				},
				Targets: []trace.ServiceTarget{{Name: "cdn.example.", Priority: 1, IPv4: answered,
					Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Hints: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}}},
			want: []string{
				"svcb: test. HTTPS 0 cdn.example.  [secure]",
				"svcb: cdn.example. HTTPS 1 . ipv4hint=192.0.2.1",
				"svcb:   cdn.example. 192.0.2.1",
			},
		},
		"several stray hints, a target with no address, and one that failed": {
			path: &trace.ServicePath{Name: "test.", Type: "SVCB",
				Chain: []trace.ServiceSet{{Lookup: trace.Lookup{Name: "test."}, Records: []trace.RR{
					{Name: "test.", Type: "SVCB", Data: "1 a.example.", Service: &trace.Service{Priority: 1, Target: "a.example."}},
					{Name: "test.", Type: "SVCB", Data: "2 b.example.", Service: &trace.Service{Priority: 2, Target: "b.example."}},
				}}},
				Targets: []trace.ServiceTarget{
					{Name: "a.example.", Priority: 1, IPv4: answered, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.3")},
						Stray: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}},
					{Name: "b.example.", Priority: 2, IPv4: answered},
					{Name: "c.example.", Priority: 3, IPv4: &trace.Lookup{Name: "c.example.", Err: "SERVFAIL"}},
				}},
			want: []string{
				"svcb: test. SVCB 1 a.example.",
				"svcb: test. SVCB 2 b.example.",
				"svcb:   a.example. 192.0.2.3; hints 192.0.2.1, 192.0.2.2 are not among them",
				"svcb:   b.example. no address",
				"svcb:   c.example. address lookup failed: SERVFAIL",
			},
		},
		"no records at the name": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Fallback: true, Chain: []trace.ServiceSet{{Lookup: trace.Lookup{Name: "test."}}}},
			want: []string{"svcb: no HTTPS records at test.", "svcb: so a client connects as it would without them"},
		},
		"an alias to a name with no records": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Fallback: true,
				Chain: []trace.ServiceSet{
					{Lookup: trace.Lookup{Name: "test."}, Records: []trace.RR{alias}},
					{Lookup: trace.Lookup{Name: "cdn.example."}},
				},
				Targets: []trace.ServiceTarget{{Name: "cdn.example.", IPv4: answered, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}}},
			want: []string{
				"svcb: test. HTTPS 0 cdn.example.",
				"svcb: no HTTPS records at cdn.example.",
				"svcb: so a client connects to cdn.example. by its addresses alone",
				"svcb:   cdn.example. 192.0.2.1",
			},
		},
		"an alias to . offers no service": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", None: true, Chain: []trace.ServiceSet{{Lookup: trace.Lookup{Name: "test."},
				Records: []trace.RR{{Name: "test.", Type: "HTTPS", Data: "0 .", Service: &trace.Service{Target: "."}}}}}},
			want: []string{"svcb: test. HTTPS 0 .", "svcb: test. says it offers no service"},
		},
		"a chain that stopped, and a budget that ran out": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", Cut: true, Stopped: "the HTTPS lookup of test. failed: SERVFAIL",
				Chain: []trace.ServiceSet{{Lookup: trace.Lookup{Name: "test.", Err: "SERVFAIL"}}}},
			want: []string{"svcb: stopped: the HTTPS lookup of test. failed: SERVFAIL", "svcb: the budget ran out before every target was looked up"},
		},
		"from a crafted file, none with no chain": {
			path: &trace.ServicePath{Name: "test.", Type: "HTTPS", None: true},
			want: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.ServicePath = tt.path
			var got []string
			for line := range strings.Lines(draw(t, tr)) {
				if strings.HasPrefix(line, "svcb: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
