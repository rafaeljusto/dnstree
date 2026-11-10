package trace

import (
	"cmp"
	"slices"
	"time"
)

// MaxRepeat is the most times --repeat asks a hop's question again. The
// repeats spend no part of --max-queries, so this, times the hops the budget
// let the walk make, is what bounds them.
const MaxRepeat = 100

// Repeated is what a hop's question got when --repeat put it to the same
// server again, a number of times, once each: a silence is not asked again,
// since a retry would hide the loss this is here to find. The hop itself is
// not one of them, so what the walk saw and what the repeats saw stay apart.
type Repeated struct {
	Asked    int
	Answered int

	// TimedOut are the repeats nothing came back to, and Failed the ones that
	// went wrong some other way: refused at the socket, or a reply that would
	// not unpack. Asked is Answered, TimedOut and Failed together.
	TimedOut int
	Failed   int

	// Truncated are the answers that came back with TC set.
	Truncated int

	// Rcodes counts the answers by rcode, the most common first.
	Rcodes []Count

	// Best, Median and Worst are the round trips of the answers, zero where
	// nothing answered.
	Best, Median, Worst time.Duration

	// Instances counts the answers by the NSID they carried, the most common
	// first, where the walk asked for one. A repeat that timed out names no
	// instance, so these count answers only.
	Instances []Count

	// Copies counts the answers by the serial of the hop's zone they said
	// they came from, the most common first, where the walk asked (RFC 9660).
	Copies []Count
}

// Count is how many times one value came back.
type Count struct {
	Value string
	Times int
}

// Missed is how many repeats got no answer.
func (r *Repeated) Missed() int {
	return r.TimedOut + r.Failed
}

// Tally counts values, the most common first and ties in the order of the
// value, so that two runs that saw the same draw the same.
func Tally(values []string) []Count {
	var counts []Count
	for _, value := range values {
		i := slices.IndexFunc(counts, func(c Count) bool { return c.Value == value })
		if i < 0 {
			counts = append(counts, Count{Value: value})
			i = len(counts) - 1
		}
		counts[i].Times++
	}
	slices.SortFunc(counts, func(a, b Count) int {
		return cmp.Or(cmp.Compare(b.Times, a.Times), cmp.Compare(a.Value, b.Value))
	})
	return counts
}

// Repeats are the hops --repeat asked again, in the order of the tree. A
// question a run put to the same server twice is repeated on the first hop
// that asked it.
func (t *Trace) Repeats() []*Step {
	var hops []*Step
	for step := range t.Steps() {
		if step.Repeated != nil {
			hops = append(hops, step)
		}
	}
	return hops
}

func (r *Repeated) shown() *Repeated {
	if r == nil {
		return nil
	}
	shown := *r
	shown.Rcodes = shownCounts(r.Rcodes)
	shown.Instances = shownCounts(r.Instances)
	shown.Copies = shownCounts(r.Copies)
	return &shown
}

func shownCounts(counts []Count) []Count {
	if counts == nil {
		return nil
	}
	shown := make([]Count, len(counts))
	for i, c := range counts {
		shown[i] = Count{Value: Shown(c.Value), Times: c.Times}
	}
	return shown
}
