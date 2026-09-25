// Package mermaid renders a trace as a Mermaid flowchart, which GitHub, GitLab
// and most wikis draw wherever a fenced mermaid block is pasted.
package mermaid

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// Render writes the trace to w as a flowchart: one node per query, a subgraph
// per zone, and what each hop cost on the edge that reaches it. It is the same
// picture --format dot draws, for the places that draw Mermaid and not Graphviz.
func Render(w io.Writer, tr *trace.Trace) error {
	chart := &chart{out: bufio.NewWriter(w), nodes: map[string][]node{}}
	chart.render(tr.Shown())
	return chart.out.Flush()
}

type chart struct {
	out *bufio.Writer

	// zones keeps the subgraphs in the order they were first reached, so that
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

func (c *chart) render(tr *trace.Trace) {
	if tr != nil && tr.Root != nil {
		c.collect(tr.Root, "")
	}

	if tr != nil {
		c.write("---\n")
		c.write("title: " + yaml(title(tr)) + "\n")
		c.write("---\n")
	}
	c.write("flowchart LR\n")

	for i, zone := range c.zones {
		c.writef("    subgraph z%d [%s]\n", i, quote(zone))
		for _, node := range c.nodes[zone] {
			c.writef("        %s%s\n", node.id, shape(node.step))
		}
		c.write("    end\n")
	}
	for _, edge := range c.edges {
		c.writef("    %s %s %s\n", edge.from, arrow(edge.step), edge.to)
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
	for _, zone := range c.zones {
		for _, node := range c.nodes[zone] {
			if class := class(node.step); class != "" {
				c.writef("    class %s %s\n", node.id, class)
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

// collect walks the trace, giving every step a node and every parent an edge to
// its children.
func (c *chart) collect(step *trace.Step, parent string) {
	id := "n" + strconv.Itoa(c.next)
	c.next++
	if _, seen := c.nodes[step.Zone]; !seen {
		c.zones = append(c.zones, step.Zone)
	}
	c.nodes[step.Zone] = append(c.nodes[step.Zone], node{id: id, step: step})

	if parent != "" {
		c.edges = append(c.edges, edge{from: parent, to: id, step: step})
	}
	for _, child := range step.Children {
		c.collect(child, id)
	}
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

	if step.DNSSEC != nil {
		lines = append(lines, "["+string(step.DNSSEC.State)+"]")
		if step.DNSSEC.Signal != nil {
			lines = append(lines, "cds "+string(step.DNSSEC.Signal.State))
		}
	}
	for _, ede := range step.Extended {
		lines = append(lines, "ede "+ede.String())
	}
	if step.Subnet != nil {
		lines = append(lines, fmt.Sprintf("ecs scope /%d", step.Subnet.Scope))
	}
	if step.NSID != "" {
		lines = append(lines, "@"+step.NSID)
	}
	if step.Cookie != "" {
		lines = append(lines, "cookie "+string(step.Cookie))
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

// class colours a node by how the hop went, following the legend the tree and
// the DOT graph use.
func class(step *trace.Step) string {
	// An answer about a shorter name than the question is only a way down.
	if step.Minimised && (step.Kind == trace.KindAnswer || step.Kind == trace.KindNoData) {
		return ""
	}
	switch step.Kind {
	case trace.KindAnswer, trace.KindCNAME:
		return "answer"
	case trace.KindNoData, trace.KindNXDomain, trace.KindLame:
		return "denial"
	case trace.KindFiltered:
		return "filtered"
	case trace.KindTimeout, trace.KindError:
		return "failed"
	case trace.KindSkipped:
		return "skipped"
	case trace.KindZone:
		return "zone"
	}
	return ""
}

// arrow is the edge into a step, dashed where the step was never asked or asked
// something other than the question.
func arrow(step *trace.Step) string {
	line := "-->"
	if step.Kind == trace.KindSkipped || step.Aside {
		line = "-.->"
	}
	if step.RTT > 0 {
		line += "|" + quote(duration(step.RTT)) + "|"
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
		if line := resolver(answer); line != "" {
			lines = append(lines, line)
		}
	}
	for _, warning := range tr.Warnings {
		lines = append(lines, "warning: "+warning)
	}
	return lines
}

func resolver(answer *trace.Resolver) string {
	if answer == nil {
		return ""
	}
	who := "a resolver"
	if answer.Server.IP.IsValid() {
		who = answer.Server.IP.String()
	}
	if answer.Err != "" {
		return who + " did not answer"
	}
	line := who + " answered in " + duration(answer.Elapsed)
	if answer.Match == trace.MatchDiffers {
		line += ", and not what the walk found"
	}
	return line
}

// duration keeps an edge label short: a chart is read at a glance.
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
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}
