package tree_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderDependencies(t *testing.T) {
	secure := &trace.DNSSECStatus{State: trace.Secure}
	insecure := &trace.DNSSECStatus{State: trace.Insecure}
	for name, tt := range map[string]struct {
		deps *trace.Dependencies
		want []string
	}{
		"zones grouped by the nameserver that brought them in": {
			deps: &trace.Dependencies{Name: "www.example.com.", Zones: []trace.DependencyZone{
				{Zone: "com.", DNSSEC: secure},
				{Zone: "example.com.", DNSSEC: secure},
				{Zone: "net.", Via: "ns1.dnshost.net.", For: "example.com.", DNSSEC: secure},
				{Zone: "dnshost.net.", Via: "ns1.dnshost.net.", For: "example.com.", DNSSEC: secure},
				{Zone: "cheap-vps.io.", Via: "ns1.cheap-vps.io.", For: "dnshost.net.", DNSSEC: insecure},
				{Zone: "broken.io.", Via: "ns1.cheap-vps.io.", For: "dnshost.net.", DNSSEC: &trace.DNSSECStatus{State: trace.Bogus}},
			}},
			want: []string{
				"deps: www.example.com. depends on 6 zones besides the root, 1 of them unsigned, 1 bogus",
				"deps:   com., example.com.  the walk",
				"deps:   net., dnshost.net.  by ns1.dnshost.net., a nameserver of example.com.",
				"deps:   cheap-vps.io. (unsigned), broken.io. (bogus)  by ns1.cheap-vps.io., a nameserver of dnshost.net.",
			},
		},
		"a nameserver that does not exist, and a budget that ran out": {
			deps: &trace.Dependencies{Name: "lost.com.",
				Zones:      []trace.DependencyZone{{Zone: "com."}},
				Unresolved: []trace.UnresolvedNS{{Name: "ns.gone.io.", For: "lost.com.", Err: "does not exist"}},
				Stopped:    "the budget ran out before every nameserver was looked up"},
			want: []string{
				"deps: lost.com. depends on at least 1 zone besides the root",
				"deps:   com.  the walk",
				"deps:   ns.gone.io., a nameserver of lost.com.: does not exist",
				"deps: stopped: the budget ran out before every nameserver was looked up",
			},
		},
		"from a crafted file, no zones at all": {
			deps: &trace.Dependencies{Name: "test."},
			want: []string{"deps: test. depends on 0 zones besides the root"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.Dependencies = tt.deps
			var got []string
			for line := range strings.Lines(draw(t, tr)) {
				if strings.HasPrefix(line, "deps: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
