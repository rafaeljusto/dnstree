// Package mermaid renders a trace as a Mermaid flowchart, which GitHub, GitLab
// and most wikis draw wherever a fenced mermaid block is pasted.
package mermaid

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/render/diagram"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Render writes the trace to w as a flowchart: one node per query, a subgraph
// per zone, and what each hop cost on the edge that reaches it. It is the same
// picture --format dot draws, for the places that draw Mermaid and not Graphviz.
func Render(w io.Writer, tr *trace.Trace) error {
	chart := &chart{out: bufio.NewWriter(w)}
	chart.render(tr.Shown())
	return chart.out.Flush()
}

type chart struct {
	out *bufio.Writer
}

func (c *chart) render(tr *trace.Trace) {
	layout := diagram.Layout(tr)

	if tr != nil {
		c.write("---\n")
		c.write("title: " + yaml(title(tr)) + "\n")
		c.write("---\n")
	}
	c.write("flowchart LR\n")

	for i, zone := range layout.Zones {
		c.writef("    subgraph z%d [%s]\n", i, quote(zone))
		for _, node := range layout.Nodes[zone] {
			c.writef("        %s%s\n", node.ID, shape(node.Step))
		}
		c.write("    end\n")
	}
	for _, edge := range layout.Edges {
		c.writef("    %s %s %s\n", edge.From, arrow(edge.Step), edge.To)
	}
	if tr != nil {
		if lines := margin(tr); len(lines) > 0 {
			c.write("    notes[" + quote(strings.Join(lines, "\n")) + "]\n")
			c.write("    class notes note\n")
		}
	}

	c.write("    classDef zone stroke:#666666\n")
	c.write("    classDef answer stroke:#006400,stroke-width:2px\n")
	c.write("    classDef denial stroke:#b8860b\n")
	c.write("    classDef filtered stroke:#ff8c00,stroke-width:3px\n")
	c.write("    classDef failed stroke:#b22222,stroke-width:2px\n")
	c.write("    classDef skipped stroke:#999999,stroke-dasharray:4 3,color:#666666\n")
	c.write("    classDef note stroke:#b8860b,stroke-dasharray:2 2\n")
	for _, zone := range layout.Zones {
		for _, node := range layout.Nodes[zone] {
			if class := classes[node.Step.Outcome()]; class != "" {
				c.writef("    class %s %s\n", node.ID, class)
			}
		}
	}
}

// write and writef add to the output. A bufio writer holds the first error it
// meets until Flush, which is what Render returns.
func (c *chart) write(text string) {
	_, _ = c.out.WriteString(text)
}

func (c *chart) writef(format string, args ...any) {
	_, _ = fmt.Fprintf(c.out, format, args...)
}

// shape is a node as Mermaid declares it: the zone a walk starts from in a
// stadium, every hop in a box.
func shape(step *trace.Step) string {
	if step.Kind == trace.KindZone {
		return "([" + quote(label(step)) + "])"
	}
	return "[" + quote(label(step)) + "]"
}

// label is what a node says: who was asked, how it went, and what came back.
func label(step *trace.Step) string {
	var lines []string

	switch {
	case step.Kind == trace.KindZone && step.Zone == ".":
		lines = append(lines, ". (root)")
	case step.Kind == trace.KindZone:
		lines = append(lines, step.Zone)
	case step.Server.Name != "":
		lines = append(lines, step.Server.Name)
	}
	if step.Server.IP.IsValid() {
		lines = append(lines, step.Server.IP.String())
	}
	if step.Server.ASN != nil {
		lines = append(lines, fmt.Sprintf("AS%d", step.Server.ASN.Number))
	}

	// A server nobody asked says so; the summary of the rest says it in its note.
	switch step.Kind {
	case trace.KindZone:
	case trace.KindSkipped:
		if step.Server.IP.IsValid() {
			lines = append(lines, "not queried")
		}
	default:
		verdict := string(step.Kind)
		if step.Kind == trace.KindReferral && step.Delegation != nil {
			verdict = "referral to " + step.Delegation.Zone
		}
		lines = append(lines, strings.TrimSpace(step.Rcode+" "+verdict))
	}

	lines = append(lines, diagram.Details(step)...)
	return strings.Join(lines, "\n")
}

// classes colour a node by how the hop went, following the legend the tree and
// the DOT graph use.
var classes = map[trace.Outcome]string{
	trace.OutcomeAnswer:   "answer",
	trace.OutcomeDenial:   "denial",
	trace.OutcomeFiltered: "filtered",
	trace.OutcomeFailed:   "failed",
	trace.OutcomeSkipped:  "skipped",
	trace.OutcomeZone:     "zone",
}

// arrow is the edge into a step, dashed where the step was never asked or asked
// something other than the question.
func arrow(step *trace.Step) string {
	line := "-->"
	if step.Kind == trace.KindSkipped || step.Aside {
		line = "-.->"
	}
	if step.RTT > 0 {
		line += "|" + quote(diagram.Duration(step.RTT)) + "|"
	}
	return line
}

// title is the question the chart answers.
func title(tr *trace.Trace) string {
	title := "dnstree"
	if question := strings.TrimSpace(tr.Question.Name + " " + tr.Question.Type); question != "" {
		title += " " + question
	}
	return title
}

// margin is what goes beside the chart rather than on a node: what recursive
// servers made of the same question, and whatever the walk could not do.
func margin(tr *trace.Trace) []string {
	var lines []string
	for _, answer := range tr.Resolvers {
		if line := diagram.Resolver(answer); line != "" {
			lines = append(lines, line)
		}
	}
	for _, warning := range tr.Warnings {
		lines = append(lines, "warning: "+warning)
	}
	return lines
}

// quote writes a Mermaid string. Inside one, Mermaid reads #name; as an entity
// and a GitHub page reads < as the start of a tag, so both are written as
// entities, and so is the quote that would end the string. A newline becomes
// the break Mermaid starts a new line of a label on.
func quote(text string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"':
			quoted.WriteString("#quot;")
		case '#':
			quoted.WriteString("#35;")
		case '<':
			quoted.WriteString("#lt;")
		case '>':
			quoted.WriteString("#gt;")
		case '&':
			quoted.WriteString("#amp;")
		case '`':
			quoted.WriteString("#96;")
		case '\n':
			quoted.WriteString("<br/>")
		default:
			quoted.WriteRune(r)
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

// yaml is the title as the front matter reads it: double quoted, so that a
// colon or a hash in a name cannot end it early.
func yaml(text string) string {
	return `"` + yamlQuoted.Replace(text) + `"`
}

var yamlQuoted = strings.NewReplacer(`\`, `\\`, `"`, `\"`)
