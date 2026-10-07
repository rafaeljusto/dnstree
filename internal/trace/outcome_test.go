package trace_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestOutcome(t *testing.T) {
	tests := map[string]struct {
		step trace.Step
		want trace.Outcome
	}{
		"an answer":                        {trace.Step{Kind: trace.KindAnswer}, trace.OutcomeAnswer},
		"an alias":                         {trace.Step{Kind: trace.KindCNAME}, trace.OutcomeAnswer},
		"a name that is not there":         {trace.Step{Kind: trace.KindNXDomain}, trace.OutcomeDenial},
		"a type that is not there":         {trace.Step{Kind: trace.KindNoData}, trace.OutcomeDenial},
		"a lame server":                    {trace.Step{Kind: trace.KindLame}, trace.OutcomeDenial},
		"an answer somebody decided":       {trace.Step{Kind: trace.KindFiltered}, trace.OutcomeFiltered},
		"a timeout":                        {trace.Step{Kind: trace.KindTimeout}, trace.OutcomeFailed},
		"an error":                         {trace.Step{Kind: trace.KindError}, trace.OutcomeFailed},
		"a server never asked":             {trace.Step{Kind: trace.KindSkipped}, trace.OutcomeSkipped},
		"the node a trace starts from":     {trace.Step{Kind: trace.KindZone}, trace.OutcomeZone},
		"a referral":                       {trace.Step{Kind: trace.KindReferral}, trace.OutcomeNone},
		"a minimised answer is a way down": {trace.Step{Kind: trace.KindAnswer, Minimised: true}, trace.OutcomeNone},
		"a minimised nodata is a way down": {trace.Step{Kind: trace.KindNoData, Minimised: true}, trace.OutcomeNone},
		"a minimised nxdomain still denies": {trace.Step{Kind: trace.KindNXDomain, Minimised: true},
			trace.OutcomeDenial},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := test.step.Outcome(); got != test.want {
				t.Errorf("got %d, want %d", got, test.want)
			}
		})
	}
}
