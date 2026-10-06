package resolver_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestReportChannel covers a zone asking for failures to be reported (RFC
// 9567). Its servers say so unasked, on every answer, and the walk keeps it on
// the hop so that where a report would go is drawn before any is sent.
func TestReportChannel(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		leaf  fakens.Behaviour
		agent string
	}{
		"a sound zone says where reports go": {leaf: fakens.Behaviour{ReportAgent: "agent.example.net."}},
		"a broken zone is due one":           {leaf: fakens.Behaviour{ReportAgent: "agent.example.net.", BadSignature: true}, agent: "agent.example.net."},
		"a broken zone that names no agent":  {leaf: fakens.Behaviour{BadSignature: true}},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := signedAs(t, fakens.DenialNSEC, test.leaf)

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			answer := tr.Result()
			if answer == nil {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}
			if answer.ReportTo != test.leaf.ReportAgent {
				t.Errorf("got %q on the answer, want %q", answer.ReportTo, test.leaf.ReportAgent)
			}
			for step := range tr.Steps() {
				if step.Zone != "example.com." && step.ReportTo != "" {
					t.Errorf("got %q on a hop of %s, which named none", step.ReportTo, step.Zone)
				}
			}
			if agent, _ := tr.ReportAgent(); agent != test.agent {
				t.Errorf("got agent %q, want %q", agent, test.agent)
			}
			if test.agent != "" && tr.Chain().DNSSEC.State != trace.Bogus {
				t.Errorf("got %s, want the chain broken", tr.Chain().DNSSEC.State)
			}
		})
	}
}
