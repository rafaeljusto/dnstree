package trace

import (
	"cmp"
	"errors"
	"slices"
	"strings"
	"time"
)

// ErrUntimed is a timeline asked of a walk that cannot place its steps in time,
// because it was saved before they said when they started.
var ErrUntimed = errors.New("this walk was saved before dnstree kept when each query started, " +
	"so there is no timeline to draw; walk the name again to get one")

// Queried reports whether the hop put a question to a server. Only those took
// time the walk can place: a server listed and never asked, or a note about why
// the walk stopped, happened at no moment of their own.
func (s *Step) Queried() bool {
	return s.Asked != (Question{})
}

// Span is one hop's place on the timeline of a walk.
type Span struct {
	Step *Step

	// Aside is set for a hop inside work that answers another question, which
	// is marked on the step that starts it rather than on every step below.
	Aside bool

	Start, End time.Duration
}

// Timeline is every query of the walk in the order it went out, and every
// point the walk gave up at. A failure has no moment of its own, so it stands
// where the last thing before it finished. Nil for a walk that is not Timed.
func (t *Trace) Timeline() []Span {
	if t == nil || !t.Timed || t.Root == nil {
		return nil
	}

	var (
		spans []Span
		now   time.Duration
	)
	var visit func(step *Step, aside bool)
	visit = func(step *Step, aside bool) {
		aside = aside || step.Aside
		switch {
		case step.Queried():
			start := max(step.Start, 0)
			spans = append(spans, Span{Step: step, Aside: aside, Start: start, End: start + step.RTT})
			now = max(now, start+step.RTT)
		case step.Kind == KindError:
			spans = append(spans, Span{Step: step, Aside: aside, Start: now, End: now})
		}
		for _, child := range step.Children {
			visit(child, aside)
		}
	}
	visit(t.Root, false)

	// Depth first is the order hops joined the walk, which is not the order
	// they went out once --all asks a zone's servers together.
	slices.SortStableFunc(spans, func(a, b Span) int { return cmp.Compare(a.Start, b.Start) })
	return spans
}

// Asks reports whether the hop put some other question than the one the walk
// set out to answer: the keys of a zone, the address of a nameserver, a name
// cut short to find the next zone cut.
func (t *Trace) Asks(step *Step) bool {
	if !step.Queried() {
		return false
	}
	return !strings.EqualFold(step.Asked.Name, t.Question.Name) || !strings.EqualFold(step.Asked.Type, t.Question.Type)
}
