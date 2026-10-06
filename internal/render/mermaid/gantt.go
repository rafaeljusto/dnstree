package mermaid

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Gantt writes the trace to w as a Mermaid gantt chart: the timeline --format
// waterfall draws, one task per query, for the places that draw Mermaid.
func Gantt(w io.Writer, tr *trace.Trace) error {
	if tr == nil {
		return nil
	}
	if !tr.Timed {
		return trace.ErrUntimed
	}
	tr = tr.Shown()
	spans := tr.Timeline()

	total := tr.Elapsed
	for _, span := range spans {
		total = max(total, span.End)
	}

	out := bufio.NewWriter(w)
	write := func(format string, args ...any) { _, _ = fmt.Fprintf(out, format, args...) }

	write("---\n")
	write("title: %s\n", yaml(title(tr)))
	write("---\n")
	write("gantt\n")
	// The chart reads the times as dates from 1970, so the axis prints only
	// the part of one that a walk spans.
	write("    dateFormat x\n")
	write("    axisFormat %s\n", axis(total))
	write("    todayMarker off\n")

	// A section per run of queries to one zone, in the order they went out,
	// which reads as the walk's way down and back up for an aside.
	result := tr.Result()
	section := ""
	for i, span := range spans {
		if zone := span.Step.Zone; i == 0 || zone != section {
			section = zone
			write("    section %s\n", text(zone))
		}
		write("    %s:%s\n", text(task(span).name(tr)), task(span).data(result))
	}
	return out.Flush()
}

// task is one query on the chart, or the moment the walk gave up.
type task trace.Span

// name is who was asked and what came of it.
func (t task) name(tr *trace.Trace) string {
	step := t.Step
	who := step.Server.Name
	if who == "" && step.Server.IP.IsValid() {
		who = step.Server.IP.String()
	}

	var said string
	switch step.Kind {
	case trace.KindReferral:
		said = "referral"
		if step.Delegation != nil {
			said += " to " + step.Delegation.Zone
		}
	case trace.KindNoData:
		said = "no data"
	case trace.KindError:
		// Not a colon, which would end the name.
		said = "error"
		if step.Err != "" {
			said += ", " + step.Err
		}
	default:
		said = string(step.Kind)
	}
	if tr.Asks(step) {
		said += ", " + step.Asked.Type + " " + step.Asked.Name
	}
	return strings.TrimSpace(who + " " + said)
}

// data is the part of a task after the colon: how it is drawn, and when. A
// failure is marked critical and an aside done, which is grey; the step the
// resolution ended on is the task Mermaid draws active.
func (t task) data(result *trace.Step) string {
	var tags []string
	switch {
	case t.Step.Kind == trace.KindTimeout, t.Step.Kind == trace.KindError, t.Step.Kind == trace.KindFiltered:
		tags = append(tags, "crit")
	case t.Step == result:
		tags = append(tags, "active")
	}
	if t.Aside && len(tags) == 0 {
		tags = append(tags, "done")
	}

	// Whole milliseconds, which is what the date format reads. A query that
	// answered in less is still given one, or it would not be drawn at all.
	start := int64(math.Floor(float64(t.Start) / float64(time.Millisecond)))
	end := max(int64(math.Round(float64(t.End)/float64(time.Millisecond))), start+1)
	if !t.Step.Queried() {
		// Giving up is a moment, not a span.
		tags = append([]string{"milestone"}, tags...)
		end = start
	}
	return strings.Join(append(tags, fmt.Sprint(start), fmt.Sprint(end)), ", ")
}

// axis is the date format the axis is labelled in: milliseconds for a walk that
// took less than a second, seconds for one that took less than a minute.
func axis(span time.Duration) string {
	switch {
	case span < time.Second:
		return "%L ms"
	case span < time.Minute:
		return "%S.%L s"
	}
	return "%M:%S"
}

// text is a task name or a section as a gantt chart can hold it. Neither can
// be quoted: a colon ends the name, and a hash or a percent sign starts a
// comment, so each is swapped for a character that looks the part. A name
// has none of them unless its zone put them there.
func text(name string) string {
	return unquotable.Replace(name)
}

var unquotable = strings.NewReplacer(":", "꞉", "#", "＃", "%", "％", ";", "；", "\n", " ")
