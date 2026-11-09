package openmetrics_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// zoneChecked is a walk that ended in test., with what --check, --serial and
// --check-ns found there.
func zoneChecked(check *trace.Check, zoneNS []string, serials ...uint32) *trace.Trace {
	answer := &trace.Step{
		Zone: "test.", Kind: trace.KindAnswer, Rcode: "NOERROR",
		Server: trace.Server{Name: "ns1.test.", IP: netip.MustParseAddr("192.0.2.5")},
		Asked:  trace.Question{Name: "www.test.", Type: "A"},
	}
	for i, serial := range serials {
		answer.Children = append(answer.Children, &trace.Step{
			Zone: "test.", Kind: trace.KindAnswer, Rcode: "NOERROR", Aside: true,
			Server: trace.Server{Name: "ns1.test.", IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)})},
			Asked:  trace.Question{Name: "test.", Type: "SOA"},
			SOA:    &trace.SOA{Serial: serial},
		})
	}
	return &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindReferral,
			Server:     trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("198.41.0.4")},
			Asked:      trace.Question{Name: "www.test.", Type: "A"},
			Delegation: &trace.Delegation{Zone: "test.", NS: []string{"ns1.test.", "ns2.test."}, ZoneNS: zoneNS},
			Children:   []*trace.Step{answer},
		}}},
		Check: check,
	}
}

func TestRenderZone(t *testing.T) {
	graded := &trace.Check{Zone: "test.", Areas: []trace.Graded{
		{Area: trace.AreaAnswer, Grade: trace.GradePassed},
		{Area: trace.AreaConsistency, Grade: trace.GradeLook},
		{Area: trace.AreaStrangers, Grade: trace.GradeSkipped},
	}}
	tests := map[string]struct {
		trace   *trace.Trace
		want    []string
		without []string
	}{
		"a graded zone has one sample per grade, the one it got set": {
			trace: zoneChecked(graded, []string{"NS2.test.", "ns1.test."}, 7, 7),
			want: []string{
				`dnstree_check{name="www.test.",type="A",zone="test.",area="answer",grade="passed"} 1`,
				`dnstree_check{name="www.test.",type="A",zone="test.",area="answer",grade="look"} 0`,
				`dnstree_check{name="www.test.",type="A",zone="test.",area="consistency",grade="look"} 1`,
				`dnstree_check{name="www.test.",type="A",zone="test.",area="strangers",grade="skipped"} 1`,
				`dnstree_check{name="www.test.",type="A",zone="test.",area="strangers",grade="passed"} 0`,
				`dnstree_zone_copies{name="www.test.",type="A",zone="test."} 1`,
				`dnstree_delegation_agrees{name="www.test.",type="A",zone="test."} 1`,
			},
		},
		"nameservers on two serials serve two copies": {
			trace: zoneChecked(nil, nil, 7, 8, 7),
			want:  []string{`dnstree_zone_copies{name="www.test.",type="A",zone="test."} 2`},
		},
		"a zone that lists a nameserver the parent does not disagrees": {
			trace: zoneChecked(nil, []string{"ns1.test.", "ns2.test.", "ns3.test."}),
			want:  []string{`dnstree_delegation_agrees{name="www.test.",type="A",zone="test."} 0`},
		},
		"a parent that delegates to a nameserver the zone does not list disagrees": {
			trace: zoneChecked(nil, []string{"ns1.test."}),
			want:  []string{`dnstree_delegation_agrees{name="www.test.",type="A",zone="test."} 0`},
		},
		"a walk that checked nothing says nothing of the zone": {
			trace:   zoneChecked(nil, nil),
			without: []string{"dnstree_check", "dnstree_zone_copies", "dnstree_delegation_agrees"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out := render(t, test.trace)
			valid(t, out)
			for _, want := range test.want {
				if !strings.Contains(out, want+"\n") {
					t.Errorf("got\n%s\nwant %s", out, want)
				}
			}
			for _, family := range test.without {
				if strings.Contains(out, "# TYPE "+family+" ") {
					t.Errorf("got %s in\n%s\nwant it left out", family, out)
				}
			}
		})
	}
}
