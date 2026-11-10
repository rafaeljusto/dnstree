package tree

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// repeats draws what --repeat counted, a line for each hop asked again: how
// many of its repeats came back, how long they took, and what the ones that
// did said where it was not all the same.
func (r *renderer) repeats(tr *trace.Trace) []string {
	mark := "repeat: "
	if r.glyphs.icons {
		mark = spaced("🔁")
	}
	var lines []string
	for _, step := range tr.Repeats() {
		got := step.Repeated
		server := step.Server.Name
		if step.Server.IP.IsValid() {
			server = strings.TrimSpace(server + " " + step.Server.IP.String())
		}
		fields := []string{
			mark + step.Asked.Name + " " + step.Asked.Type + " at " + server,
			fmt.Sprintf("%d/%d answered", got.Answered, got.Asked),
		}
		if got.Answered > 0 {
			fields = append(fields, r.duration(got.Best)+" best", r.duration(got.Median)+" median", r.duration(got.Worst)+" worst")
		}
		if got.TimedOut > 0 {
			fields = append(fields, fmt.Sprintf("%d timed out", got.TimedOut))
		}
		if got.Failed > 0 {
			fields = append(fields, fmt.Sprintf("%d failed", got.Failed))
		}
		if got.Truncated > 0 {
			fields = append(fields, fmt.Sprintf("%d truncated", got.Truncated))
		}
		// Only an answer the walk got has anything for the repeats to differ from.
		mixed := step.Rcode != "" && (len(got.Rcodes) > 1 || len(got.Rcodes) == 1 && got.Rcodes[0].Value != step.Rcode)
		if mixed {
			fields = append(fields, tallied(got.Rcodes, ""))
		}
		if len(got.Instances) > 0 {
			fields = append(fields, mostOf(got.Instances, "@"))
		}
		if len(got.Copies) > 0 {
			fields = append(fields, "serial "+mostOf(got.Copies, ""))
		}

		text := strings.Join(fields, "  ")
		if got.Missed() > 0 || mixed || len(got.Copies) > 1 {
			lines = append(lines, r.paint.paint(text, yellow))
		} else {
			lines = append(lines, r.paint.dim(text))
		}
	}
	return lines
}

// shownInstances is how many of the instances, or copies of the zone, that
// answered a line names, the most frequent; an anycast address can have a
// different one answer every time.
const shownInstances = 4

// mostOf is the most frequent of the counts, and how many more there were.
func mostOf(counts []trace.Count, prefix string) string {
	text := tallied(counts[:min(len(counts), shownInstances)], prefix)
	if more := len(counts) - shownInstances; more > 0 {
		text += fmt.Sprintf(" and %d more", more)
	}
	return text
}

// tallied is each value with the number of times it came back.
func tallied(counts []trace.Count, prefix string) string {
	parts := make([]string, len(counts))
	for i, c := range counts {
		parts[i] = fmt.Sprintf("%s%s %d", prefix, c.Value, c.Times)
	}
	return strings.Join(parts, ", ")
}
