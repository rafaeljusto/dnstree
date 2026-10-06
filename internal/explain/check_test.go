package explain_test

import (
	"net/netip"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestCheck(t *testing.T) {
	answer := func() *trace.Step {
		step := hop(trace.KindAnswer, "ns.test.")
		step.Records = []trace.RR{{Name: "www.test.", Type: "A", Data: "192.0.2.1"}}
		return step
	}
	signed := func(state trace.DNSSECState) *trace.Trace {
		step := answer()
		step.DNSSEC = &trace.DNSSECStatus{State: state, Zone: "test."}
		return walk(step)
	}
	warned := func(warnings map[string]trace.Concern) *trace.Trace {
		tr := walk(answer())
		tr.About = make(map[string]trace.Concern)
		for warning, concern := range warnings {
			tr.Warnings = append(tr.Warnings, warning)
			if concern.Area != "" {
				tr.About[warning] = concern
			}
		}
		return tr
	}

	tests := map[string]struct {
		tr   *trace.Trace
		want map[trace.Area]trace.Graded
	}{
		"a walk that checked nothing passes the answer and the servers and skips the rest": {
			tr: walk(answer()),
			want: map[trace.Area]trace.Graded{
				trace.AreaAnswer: {Grade: trace.GradePassed,
					Text: "www.test. A is 192.0.2.1, answered by ns.test. for test."},
				trace.AreaServers: {Grade: trace.GradePassed,
					Text: "every server of test. the walk asked answered, with authority and room to spare"},
				trace.AreaDNSSEC: {Grade: trace.GradeSkipped, Text: "not checked; --dnssec follows the chain of trust"},
				trace.AreaStrangers: {Grade: trace.GradeSkipped,
					Text: "not asked; --check-axfr and --check-recursion probe the nameservers, which is for your own zone"},
			},
		},
		"a walk that reached nothing breaks the answer": {
			tr: walk(hop(trace.KindTimeout, "ns.test.")),
			want: map[trace.Area]trace.Graded{
				trace.AreaAnswer:  {Grade: trace.GradeBroken, Text: "nothing answered for www.test. A, and the walk stopped at test."},
				trace.AreaServers: {Grade: trace.GradeLook, Text: "1 server did not answer in time: ns.test."},
			},
		},
		"a broken chain of trust breaks dnssec": {
			tr: signed(trace.Bogus),
			want: map[trace.Area]trace.Graded{
				trace.AreaDNSSEC: {Grade: trace.GradeBroken,
					Text: "the chain of trust breaks at test., so a resolver that validates answers SERVFAIL for this name"},
			},
		},
		"an unsigned zone is worth a look": {
			tr: signed(trace.Insecure),
			want: map[trace.Area]trace.Graded{
				trace.AreaDNSSEC: {Grade: trace.GradeLook, Text: "test. is not signed, so nothing here vouches for the answer"},
			},
		},
		"a secure chain passes": {
			tr: signed(trace.Secure),
			want: map[trace.Area]trace.Graded{
				trace.AreaDNSSEC: {Grade: trace.GradePassed, Text: "the chain of trust holds from the root to test."},
			},
		},
		"a warning the walk tagged is worth a look in its area, and the next one is counted": {
			tr: warned(map[string]trace.Concern{
				"test. lists ns2.test., which the delegation does not carry": {Area: trace.AreaDelegation},
				"test. did not return its own NS records":                    {Area: trace.AreaDelegation, Zone: "test."},
			}),
			want: map[trace.Area]trace.Graded{
				trace.AreaDelegation: {Grade: trace.GradeLook, More: 1},
			},
		},
		"a warning about no area grades none": {
			tr: warned(map[string]trace.Concern{"the origin AS lookups did not answer in time; --no-asn skips them": {}}),
			want: map[trace.Area]trace.Graded{
				trace.AreaAnswer:     {Grade: trace.GradePassed, Text: "www.test. A is 192.0.2.1, answered by ns.test. for test."},
				trace.AreaDelegation: {Grade: trace.GradeSkipped, Text: "not checked; --check-ns compares the parent and the zone"},
			},
		},
		"a warning about a zone above is not held against the zone": {
			tr: warned(map[string]trace.Concern{"no server answered for com.": {Area: trace.AreaServers, Zone: "com."}}),
			want: map[trace.Area]trace.Graded{
				trace.AreaServers: {Grade: trace.GradePassed},
			},
		},
		"a server that could not be asked is never a pass": {
			tr: func() *trace.Trace {
				step := answer()
				probe := hop(trace.KindTimeout, "ns.test.")
				probe.Aside, probe.Probe = true, &trace.Probe{Kind: trace.ProbeTransfer, State: trace.ProbeUnchecked}
				step.Children = []*trace.Step{probe}
				return walk(step)
			}(),
			want: map[trace.Area]trace.Graded{
				trace.AreaStrangers: {Grade: trace.GradeLook,
					Text: "ns.test. could not be asked for a zone transfer, so whether a zone transfer is open there is unknown"},
				// The probe says it went unanswered; the server answered the walk.
				trace.AreaServers: {Grade: trace.GradePassed},
			},
		},
		"a registry that publishes nothing is skipped, not passed": {
			tr: func() *trace.Trace {
				tr := walk(answer())
				tr.Registration = &trace.Registration{Domain: "test.", State: trace.Unpublished, Why: "the registry of test. publishes no rdap service"}
				return tr
			}(),
			want: map[trace.Area]trace.Graded{
				trace.AreaRegistration: {Grade: trace.GradeSkipped},
			},
		},
		"a registration with nothing to say passes as held": {
			tr: func() *trace.Trace {
				tr := walk(answer())
				tr.Registration = &trace.Registration{Domain: "test.", State: trace.Registered}
				return tr
			}(),
			want: map[trace.Area]trace.Graded{
				trace.AreaRegistration: {Grade: trace.GradePassed, Text: "the registry holds test."},
			},
		},
		"a server of a zone above that ran short of room is not the zone's to fix": {
			tr: walk(&trace.Step{
				Zone: ".", Kind: trace.KindReferral, Size: 1200, Limit: 1232,
				Server:     trace.Server{Name: "root.test.", IP: netip.MustParseAddr("192.0.2.53")},
				Delegation: &trace.Delegation{Zone: "test.", NS: []string{"ns.test."}},
				Children:   []*trace.Step{answer()},
			}),
			want: map[trace.Area]trace.Graded{
				trace.AreaServers: {Grade: trace.GradeLook,
					Text: "test. is delegated to one nameserver, ns.test., so it has nothing to fall back on"},
			},
		},
		"a zone whose servers all serve one copy passes": {
			tr: func() *trace.Trace {
				step := answer()
				step.Children = []*trace.Step{{
					Zone: "test.", Kind: trace.KindAnswer, Aside: true,
					Server: trace.Server{Name: "ns.test.", IP: netip.MustParseAddr("192.0.2.5")},
					Asked:  trace.Question{Name: "test.", Type: "SOA"}, SOA: &trace.SOA{Serial: 7},
				}}
				return walk(step)
			}(),
			want: map[trace.Area]trace.Graded{
				trace.AreaConsistency: {Grade: trace.GradePassed,
					Text: "every nameserver asked serves one copy of test., serial 7 (1 nameserver, 1 address)"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			check := explain.Check(tt.tr)
			if check.Zone != "test." {
				t.Errorf("got the zone %q, want test.", check.Zone)
			}
			if len(check.Areas) != len(trace.Areas) {
				t.Fatalf("got %d areas, want %d", len(check.Areas), len(trace.Areas))
			}
			for _, got := range check.Areas {
				want, ok := tt.want[got.Area]
				if !ok {
					continue
				}
				if got.Grade != want.Grade || got.More != want.More || (want.Text != "" && got.Text != want.Text) {
					t.Errorf("got %s %s %q (%d more), want %s %q (%d more)",
						got.Area, got.Grade, got.Text, got.More, want.Grade, want.Text, want.More)
				}
			}
		})
	}
}

func TestCheckNothing(t *testing.T) {
	if check := explain.Check(&trace.Trace{}); check != nil {
		t.Errorf("got %+v for a trace with no walk, want nothing", check)
	}
}
