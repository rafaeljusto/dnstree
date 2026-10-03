package recursive_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/recursive"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// broken is a walk whose chain of trust broke at test., whose server named
// agent as where failures go.
func broken(name, agent string, state trace.DNSSECState) *trace.Trace {
	return &trace.Trace{
		Question: trace.Question{Name: name, Type: "A", Class: "IN"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: "test.", Kind: trace.KindAnswer, Rcode: "NOERROR", ReportTo: agent,
			DNSSEC: &trace.DNSSECStatus{State: state, Zone: "test."},
		}}},
	}
}

func TestReport(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + ".test."
	for name, test := range map[string]struct {
		tr      *trace.Trace
		failing bool
		want    *trace.Report // nil for nothing due
	}{
		"a broken chain is reported": {
			tr: broken("www.test.", "agent.example.", trace.Bogus),
			want: &trace.Report{Agent: "agent.example.", Code: 6, Rcode: "NOERROR",
				Name: "_er.1.www.test.6._er.agent.example."}},
		"a chain that holds is not": {
			tr: broken("www.test.", "agent.example.", trace.Secure)},
		"a chain that could not be checked is not": {
			tr: broken("www.test.", "agent.example.", trace.Indeterminate)},
		"a zone that names no agent is not": {
			tr: broken("www.test.", "", trace.Bogus)},
		"an agent under the name is refused": {
			tr:   broken("test.", "agent.test.", trace.Bogus),
			want: &trace.Report{Agent: "agent.test.", Code: 6, Err: "the agent is at or below the name it would be told about, which RFC 9567 rules out"}},
		"a report longer than a name is not sent": {
			tr:   broken(long, "agent."+strings.Repeat("d", 60)+".example.", trace.Bogus),
			want: &trace.Report{Agent: "agent." + strings.Repeat("d", 60) + ".example.", Code: 6, Err: "the report would be longer than a name can be"}},
		"a report that did not get through says why": {
			tr: broken("www.test.", "agent.example.", trace.Bogus), failing: true,
			want: &trace.Report{Agent: "agent.example.", Code: 6, Name: "_er.1.www.test.6._er.agent.example.", Err: "i/o timeout"}},
	} {
		t.Run(name, func(t *testing.T) {
			sent := ""
			recursive.Report(test.tr, func(name string) (string, error) {
				sent = name
				if test.failing {
					return "", errors.New("i/o timeout")
				}
				return "NOERROR", nil
			})

			got := test.tr.Report
			switch {
			case test.want == nil && got != nil:
				t.Fatalf("got %+v, want nothing due", got)
			case test.want == nil:
				return
			case got == nil:
				t.Fatalf("got nothing, want %+v", test.want)
			case *got != *test.want:
				t.Errorf("got %+v, want %+v", got, test.want)
			}
			if sent != test.want.Name {
				t.Errorf("sent %q, want %q", sent, test.want.Name)
			}
		})
	}
}
