package jsonout

import (
	"fmt"
	"strconv"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

type repeated struct {
	Asked     int     `json:"asked"`
	Answered  int     `json:"answered"`
	TimedOut  int     `json:"timed_out,omitempty"`
	Failed    int     `json:"failed,omitempty"`
	Truncated int     `json:"truncated,omitempty"`
	Rcodes    []tally `json:"rcodes,omitempty"`
	BestMS    float64 `json:"best_ms,omitempty"`
	MedianMS  float64 `json:"median_ms,omitempty"`
	WorstMS   float64 `json:"worst_ms,omitempty"`
	Instances []tally `json:"instances,omitempty"`
	Copies    []tally `json:"copies,omitempty"`
}

type tally struct {
	Value string `json:"value"`
	Times int    `json:"times"`
}

func convertRepeated(from *trace.Repeated) *repeated {
	if from == nil {
		return nil
	}
	return &repeated{
		Asked: from.Asked, Answered: from.Answered,
		TimedOut: from.TimedOut, Failed: from.Failed, Truncated: from.Truncated,
		Rcodes:   convertTallies(from.Rcodes),
		BestMS:   milliseconds(from.Best),
		MedianMS: milliseconds(from.Median),
		WorstMS:  milliseconds(from.Worst),

		Instances: convertTallies(from.Instances),
		Copies:    convertTallies(from.Copies),
	}
}

func convertTallies(from []trace.Count) []tally {
	var to []tally
	for _, c := range from {
		to = append(to, tally{Value: c.Value, Times: c.Times})
	}
	return to
}

// readRepeated takes the counts only where they add up: a renderer draws them
// as fractions, and a share above the whole is no share.
func readRepeated(from *repeated) (*trace.Repeated, error) {
	if from == nil {
		return nil, nil
	}
	to := &trace.Repeated{
		Asked: from.Asked, Answered: from.Answered,
		TimedOut: from.TimedOut, Failed: from.Failed, Truncated: from.Truncated,
	}
	if to.Asked > trace.MaxRepeat {
		return nil, fmt.Errorf("asked again %d times, and --repeat asks no more than %d", to.Asked, trace.MaxRepeat)
	}
	if min(to.Answered, to.TimedOut, to.Failed, to.Truncated) < 0 ||
		to.Answered+to.TimedOut+to.Failed != to.Asked || to.Truncated > to.Answered {
		return nil, fmt.Errorf("%d asked again do not add up to %d answered, %d timed out and %d failed",
			to.Asked, to.Answered, to.TimedOut, to.Failed)
	}
	var err error
	if to.Rcodes, err = readTallies("rcodes", from.Rcodes, to.Answered, true); err != nil {
		return nil, err
	}
	if to.Instances, err = readTallies("instances", from.Instances, to.Answered, false); err != nil {
		return nil, err
	}
	if to.Copies, err = readTallies("copies", from.Copies, to.Answered, false); err != nil {
		return nil, err
	}
	for _, c := range to.Copies {
		if _, err := strconv.ParseUint(c.Value, 10, 32); err != nil {
			return nil, fmt.Errorf("copies counts %q, which is no serial", c.Value)
		}
	}
	if to.Best, err = duration("best_ms", from.BestMS); err != nil {
		return nil, err
	}
	if to.Median, err = duration("median_ms", from.MedianMS); err != nil {
		return nil, err
	}
	if to.Worst, err = duration("worst_ms", from.WorstMS); err != nil {
		return nil, err
	}
	return to, nil
}

// readTallies reads counts of the answers, which add up to all of them where
// every answer has a value, and to no more than all of them where it may not.
func readTallies(field string, from []tally, answered int, every bool) ([]trace.Count, error) {
	var to []trace.Count
	sum := 0
	for _, t := range from {
		if t.Times < 1 || t.Times > answered {
			return nil, fmt.Errorf("%s counts %q %d times, of %d answers", field, t.Value, t.Times, answered)
		}
		sum += t.Times
		to = append(to, trace.Count{Value: t.Value, Times: t.Times})
	}
	if sum > answered || every && len(from) > 0 && sum != answered {
		return nil, fmt.Errorf("%s count %d answers, of %d", field, sum, answered)
	}
	return to, nil
}
