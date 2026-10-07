// Package diagram is what the DOT graph and the Mermaid flowchart draw alike:
// a node per hop, grouped by zone, and what each node says below who was asked.
// How it is written down is left to each format.
package diagram

import (
	"fmt"
	"strconv"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Diagram is a trace laid out as nodes and the edges between them.
type Diagram struct {
	// Zones keeps the groups in the order they were first reached, so that
	// the same trace always comes out the same way.
	Zones []string
	Nodes map[string][]Node
	Edges []Edge

	next int
}

// Node is one step, under the identifier the edges name it by.
type Node struct {
	ID   string
	Step *trace.Step
}

// Edge is the way into a step from the one before it.
type Edge struct {
	From, To string
	Step     *trace.Step
}

// Layout gives every step a node and every parent an edge to its children.
func Layout(tr *trace.Trace) *Diagram {
	d := &Diagram{Nodes: map[string][]Node{}}
	if tr != nil && tr.Root != nil {
		d.collect(tr.Root, "")
	}
	return d
}

func (d *Diagram) collect(step *trace.Step, parent string) {
	id := "n" + strconv.Itoa(d.next)
	d.next++
	if _, seen := d.Nodes[step.Zone]; !seen {
		d.Zones = append(d.Zones, step.Zone)
	}
	d.Nodes[step.Zone] = append(d.Nodes[step.Zone], Node{ID: id, Step: step})

	if parent != "" {
		d.Edges = append(d.Edges, Edge{From: parent, To: id, Step: step})
	}
	for _, child := range step.Children {
		d.collect(child, id)
	}
}

// Details is what a node says after who was asked and how it went: the chain
// of trust, what the server said about itself, and what came back.
func Details(step *trace.Step) []string {
	var lines []string
	if step.DNSSEC != nil {
		lines = append(lines, "["+string(step.DNSSEC.State)+"]")
		if step.DNSSEC.Signal != nil {
			lines = append(lines, "cds "+string(step.DNSSEC.Signal.State))
			if boot := step.DNSSEC.Signal.Bootstrap; boot != nil {
				lines = append(lines, "bootstrap "+string(boot.State))
			}
		}
	}
	if step.Delegation != nil && step.Delegation.CSYNC != nil && step.Delegation.CSYNC.State != trace.CSYNCNone {
		lines = append(lines, "csync "+string(step.Delegation.CSYNC.State))
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
	return lines
}

// Resolver is what a recursive server made of the same question, to be drawn
// beside what the walk cost.
func Resolver(answer *trace.Resolver) string {
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
	line := who + " answered in " + Duration(answer.Elapsed)
	if answer.Match == trace.MatchDiffers {
		line += ", and not what the walk found"
	}
	return line
}

// Duration keeps an edge label short: a diagram is read at a glance.
func Duration(d time.Duration) string {
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
