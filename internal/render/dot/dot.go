// Package dot renders a trace as a Graphviz DOT graph.
package dot

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/render/diagram"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Render writes the trace to w as a Graphviz graph: one node per query,
// grouped into a cluster per zone, with what each hop cost on the edge that
// reaches it.
func Render(w io.Writer, tr *trace.Trace) error {
	graph := &graph{out: bufio.NewWriter(w)}
	graph.render(tr.Shown())
	return graph.out.Flush()
}

type graph struct {
	out *bufio.Writer
}

func (g *graph) render(tr *trace.Trace) {
	layout := diagram.Layout(tr)

	g.write("digraph dnstree {\n")
	g.write("\trankdir=LR;\n")
	g.write("\tnode [shape=box, style=rounded, fontname=\"monospace\", fontsize=10];\n")
	g.write("\tedge [fontname=\"monospace\", fontsize=9];\n")
	if tr != nil {
		g.write("\tlabel=" + quote(caption(tr)) + ";\n")
		g.write("\tlabelloc=t;\n")
	}

	for i, zone := range layout.Zones {
		g.writef("\n\tsubgraph cluster_%d {\n", i)
		g.write("\t\tlabel=" + quote(zone) + ";\n")
		g.write("\t\tstyle=dashed;\n")
		g.write("\t\tcolor=gray60;\n")
		for _, node := range layout.Nodes[zone] {
			g.writef("\t\t%s [label=%s%s];\n", node.ID, quote(label(node.Step)), attributes[node.Step.Outcome()])
		}
		g.write("\t}\n")
	}

	if len(layout.Edges) > 0 {
		g.write("\n")
	}
	for _, edge := range layout.Edges {
		g.writef("\t%s -> %s%s;\n", edge.From, edge.To, edgeAttributes(edge.Step))
	}
	g.write("}\n")
}

// write and writef add to the output. A bufio writer holds the first error it
// meets until Flush, which is what Render returns, so the way there needs no
// checking of its own.
func (g *graph) write(text string) {
	_, _ = g.out.WriteString(text)
}

func (g *graph) writef(format string, args ...any) {
	_, _ = fmt.Fprintf(g.out, format, args...)
}

// label is what a node says: who was asked, how it went, and what came back.
func label(step *trace.Step) string {
	var lines []string

	switch {
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

	verdict := []string{step.Rcode, string(step.Kind)}
	if step.Kind == trace.KindZone {
		verdict = nil
	}
	if line := strings.TrimSpace(strings.Join(verdict, " ")); line != "" {
		lines = append(lines, line)
	}

	lines = append(lines, diagram.Details(step)...)
	return strings.Join(lines, "\n")
}

// attributes colour a node by how the hop went, following the same legend the
// tree does.
var attributes = map[trace.Outcome]string{
	trace.OutcomeAnswer:   ", color=darkgreen",
	trace.OutcomeDenial:   ", color=darkgoldenrod",
	trace.OutcomeFiltered: ", color=darkorange, style=\"rounded,bold\"",
	trace.OutcomeFailed:   ", color=firebrick",
	trace.OutcomeSkipped:  ", color=gray60, fontcolor=gray40, style=\"rounded,dashed\"",
	trace.OutcomeZone:     ", shape=oval, color=gray40",
}

func edgeAttributes(step *trace.Step) string {
	var attributes []string
	if step.RTT > 0 {
		attributes = append(attributes, "label="+quote(diagram.Duration(step.RTT)))
	}
	if step.Kind == trace.KindSkipped || step.Aside {
		attributes = append(attributes, "style=dashed", "color=gray60")
	}
	if len(attributes) == 0 {
		return ""
	}
	return " [" + strings.Join(attributes, ", ") + "]"
}

// caption is the question the graph answers, and whatever the walk could not
// do: a warning belongs on the picture rather than only in the tree.
func caption(tr *trace.Trace) string {
	var caption strings.Builder
	caption.WriteString("dnstree")
	if question := strings.TrimSpace(tr.Question.Name + " " + tr.Question.Type); question != "" {
		caption.WriteString(" " + question)
	}
	for _, answer := range tr.Resolvers {
		if line := diagram.Resolver(answer); line != "" {
			caption.WriteString("\n" + line)
		}
	}
	for _, warning := range tr.Warnings {
		caption.WriteString("\nwarning: " + warning)
	}
	return caption.String()
}

// quote writes a DOT string literal. Only the quote and the backslash need
// escaping; a newline becomes the \n that Graphviz breaks a label on.
func quote(text string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"', '\\':
			quoted.WriteByte('\\')
			quoted.WriteRune(r)
		case '\n':
			quoted.WriteString("\\n")
		default:
			quoted.WriteRune(r)
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}
