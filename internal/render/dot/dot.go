// Package dot renders a trace as a Graphviz DOT graph.
package dot

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// Render writes the trace to w as a Graphviz graph: one node per query,
// grouped into a cluster per zone, with what each hop cost on the edge that
// reaches it.
func Render(w io.Writer, tr *trace.Trace) error {
	graph := &graph{out: bufio.NewWriter(w)}
	graph.render(tr)
	return graph.out.Flush()
}

type graph struct {
	out *bufio.Writer

	// zones keeps the clusters in the order they were first reached, so that
	// the same trace always comes out the same way.
	zones []string
	nodes map[string][]node
	edges []edge
	next  int
}

type node struct {
	id   string
	step *trace.Step
}

type edge struct {
	from, to string
	step     *trace.Step
}

func (g *graph) render(tr *trace.Trace) {
	g.nodes = map[string][]node{}
	if tr != nil && tr.Root != nil {
		g.collect(tr.Root, "")
	}

	g.out.WriteString("digraph dnstree {\n")
	g.out.WriteString("\trankdir=LR;\n")
	g.out.WriteString("\tnode [shape=box, style=rounded, fontname=\"monospace\", fontsize=10];\n")
	g.out.WriteString("\tedge [fontname=\"monospace\", fontsize=9];\n")
	if tr != nil {
		g.out.WriteString("\tlabel=" + quote(caption(tr)) + ";\n")
		g.out.WriteString("\tlabelloc=t;\n")
	}

	for i, zone := range g.zones {
		fmt.Fprintf(g.out, "\n\tsubgraph cluster_%d {\n", i)
		g.out.WriteString("\t\tlabel=" + quote(zone) + ";\n")
		g.out.WriteString("\t\tstyle=dashed;\n")
		g.out.WriteString("\t\tcolor=gray60;\n")
		for _, node := range g.nodes[zone] {
			fmt.Fprintf(g.out, "\t\t%s [label=%s%s];\n", node.id, quote(label(node.step)), attributes(node.step))
		}
		g.out.WriteString("\t}\n")
	}

	if len(g.edges) > 0 {
		g.out.WriteString("\n")
	}
	for _, edge := range g.edges {
		fmt.Fprintf(g.out, "\t%s -> %s%s;\n", edge.from, edge.to, edgeAttributes(edge.step))
	}
	g.out.WriteString("}\n")
}

// collect walks the trace, giving every step a node and every parent an edge to
// its children.
func (g *graph) collect(step *trace.Step, parent string) {
	id := "n" + strconv.Itoa(g.next)
	g.next++
	if _, seen := g.nodes[step.Zone]; !seen {
		g.zones = append(g.zones, step.Zone)
	}
	g.nodes[step.Zone] = append(g.nodes[step.Zone], node{id: id, step: step})

	if parent != "" {
		g.edges = append(g.edges, edge{from: parent, to: id, step: step})
	}
	for _, child := range step.Children {
		g.collect(child, id)
	}
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

	if step.DNSSEC != nil {
		lines = append(lines, "["+string(step.DNSSEC.State)+"]")
	}
	for _, record := range step.Records {
		lines = append(lines, record.Name+" "+record.Type+" "+record.Data)
	}
	if step.Err != "" {
		lines = append(lines, step.Err)
	}
	for _, note := range step.Notes {
		lines = append(lines, "("+note+")")
	}
	return strings.Join(lines, "\n")
}

// attributes colour a node by how the hop went, following the same legend the
// tree does.
func attributes(step *trace.Step) string {
	switch step.Kind {
	case trace.KindAnswer, trace.KindCNAME:
		return ", color=darkgreen"
	case trace.KindNoData, trace.KindNXDomain, trace.KindLame:
		return ", color=darkgoldenrod"
	case trace.KindTimeout, trace.KindError:
		return ", color=firebrick"
	case trace.KindSkipped:
		return ", color=gray60, fontcolor=gray40, style=\"rounded,dashed\""
	case trace.KindZone:
		return ", shape=oval, color=gray40"
	}
	return ""
}

func edgeAttributes(step *trace.Step) string {
	var attributes []string
	if step.RTT > 0 {
		attributes = append(attributes, "label="+quote(duration(step.RTT)))
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
	caption := "dnstree"
	if question := strings.TrimSpace(tr.Question.Name + " " + tr.Question.Type); question != "" {
		caption += " " + question
	}
	for _, warning := range tr.Warnings {
		caption += "\nwarning: " + warning
	}
	return caption
}

// duration keeps an edge label short: a graph is read at a glance.
func duration(d time.Duration) string {
	switch {
	case d >= time.Second:
		return d.Round(10 * time.Millisecond).String()
	case d >= 10*time.Millisecond:
		return d.Round(time.Millisecond).String()
	case d >= time.Millisecond:
		return d.Round(100 * time.Microsecond).String()
	default:
		return d.Round(10 * time.Microsecond).String()
	}
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
