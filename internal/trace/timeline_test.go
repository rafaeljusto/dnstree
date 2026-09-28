package trace_test

import (
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func asked(name, qtype string) trace.Question { return trace.Question{Name: name, Type: qtype} }

// timed is a walk whose root servers were asked together, whose answer needed
// the address of a nameserver found on the way, and which gave up once.
func timed() *trace.Trace {
	address := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true, Children: []*trace.Step{
		{Zone: ".", Kind: trace.KindAnswer, Asked: asked("ns.example.net.", "A"), Start: 30 * time.Millisecond, RTT: 5 * time.Millisecond},
	}}
	first := &trace.Step{Zone: ".", Kind: trace.KindReferral, Asked: asked("example.com.", "A"),
		Start: time.Millisecond, RTT: 20 * time.Millisecond, Children: []*trace.Step{
			address,
			{Zone: "com.", Kind: trace.KindError, Err: "gave up"},
		}}
	second := &trace.Step{Zone: ".", Kind: trace.KindReferral, Asked: asked("example.com.", "A"),
		Start: 2 * time.Millisecond, RTT: 8 * time.Millisecond}
	return &trace.Trace{
		Question: asked("example.com.", "A"),
		Timed:    true,
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
			first, second, {Zone: ".", Kind: trace.KindSkipped},
		}},
	}
}

func TestTimeline(t *testing.T) {
	spans := timed().Timeline()

	type want struct {
		kind       trace.StepKind
		aside      bool
		start, end time.Duration
	}
	wants := []want{
		{trace.KindReferral, false, time.Millisecond, 21 * time.Millisecond},
		// Asked together with the first, and drawn under it, not after its subtree.
		{trace.KindReferral, false, 2 * time.Millisecond, 10 * time.Millisecond},
		// Aside because the walk it belongs to is, though the step itself is not marked.
		{trace.KindAnswer, true, 30 * time.Millisecond, 35 * time.Millisecond},
		// Giving up is placed after the last thing to finish before it.
		{trace.KindError, false, 35 * time.Millisecond, 35 * time.Millisecond},
	}
	if len(spans) != len(wants) {
		t.Fatalf("got %d spans, want %d: the zone nodes and the skipped server take no time", len(spans), len(wants))
	}
	for i, want := range wants {
		got := spans[i]
		if got.Step.Kind != want.kind || got.Aside != want.aside || got.Start != want.start || got.End != want.end {
			t.Errorf("span %d: got %s aside=%t %s-%s, want %s aside=%t %s-%s", i,
				got.Step.Kind, got.Aside, got.Start, got.End, want.kind, want.aside, want.start, want.end)
		}
	}
}

func TestTimelineUntimed(t *testing.T) {
	tr := timed()
	tr.Timed = false
	if spans := tr.Timeline(); spans != nil {
		t.Errorf("got %d spans from a walk that kept no start times, want none: a zero start is no position", len(spans))
	}
}

func TestAsks(t *testing.T) {
	tr := &trace.Trace{Question: asked("www.example.com.", "A")}
	tests := map[string]struct {
		step *trace.Step
		want bool
	}{
		"the question itself":             {&trace.Step{Asked: asked("www.example.com.", "A")}, false},
		"the question in another case":    {&trace.Step{Asked: asked("WWW.example.com.", "a")}, false},
		"the keys of a zone":              {&trace.Step{Asked: asked("example.com.", "DNSKEY")}, true},
		"a name cut short under --qmin":   {&trace.Step{Asked: asked("com.", "A")}, true},
		"a server that was never queried": {&trace.Step{Kind: trace.KindSkipped}, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tr.Asks(test.step); got != test.want {
				t.Errorf("got %t, want %t", got, test.want)
			}
		})
	}
}
