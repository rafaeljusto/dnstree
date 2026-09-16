package trace_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// tree is a walk that tried two servers at the root before getting anywhere.
func tree() *trace.Trace {
	answer := &trace.Step{Zone: "example.com.", Kind: trace.KindAnswer}
	referral := &trace.Step{Zone: ".", Kind: trace.KindReferral, Children: []*trace.Step{answer}}
	return &trace.Trace{
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
			{Zone: ".", Kind: trace.KindLame},
			referral,
		}},
	}
}

func TestSteps(t *testing.T) {
	var kinds []trace.StepKind
	for step := range tree().Steps() {
		kinds = append(kinds, step.Kind)
	}

	want := []trace.StepKind{trace.KindZone, trace.KindLame, trace.KindReferral, trace.KindAnswer}
	if len(kinds) != len(want) {
		t.Fatalf("got %v, want %v", kinds, want)
	}
	for i, kind := range kinds {
		if kind != want[i] {
			t.Fatalf("got %v, want parents before children: %v", kinds, want)
		}
	}
}

func TestStepsStop(t *testing.T) {
	seen := 0
	for range tree().Steps() {
		seen++
		break
	}
	if seen != 1 {
		t.Errorf("got %d steps, want the walk to stop when the caller does", seen)
	}

	if steps := (&trace.Trace{}).Steps(); steps == nil {
		t.Fatal("got no iterator for an empty trace, want an empty one")
	}
	for range (&trace.Trace{}).Steps() {
		t.Error("got a step from an empty trace, want none")
	}
}

func TestResult(t *testing.T) {
	if got := tree().Result(); got == nil || got.Kind != trace.KindAnswer {
		t.Errorf("got %+v, want the answering step", got)
	}

	unanswered := &trace.Trace{Root: &trace.Step{Kind: trace.KindZone, Children: []*trace.Step{
		{Kind: trace.KindTimeout},
	}}}
	if got := unanswered.Result(); got != nil {
		t.Errorf("got %+v, want no result when nothing answered", got)
	}
}
