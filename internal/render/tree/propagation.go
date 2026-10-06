package tree

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// changes names each kind of change the way the block says it.
var changes = map[trace.Change]string{
	trace.ChangeAnswer:      "change the answer",
	trace.ChangeDenial:      "create a missing record",
	trace.ChangeNameservers: "move the nameservers",
	trace.ChangeDS:          "change the DS",
	trace.ChangeKeys:        "change the keys",
}

// propagation draws what --propagation worked out: how long each kind of
// change to the zone takes to reach every cache, and the TTLs it was read
// off. What the walk did not read is said with the flag that reads it.
func (r *renderer) propagation(p *trace.Propagation) []string {
	if p == nil {
		return nil
	}
	mark := "propagation: "
	if r.glyphs.icons {
		mark = spaced("⏳")
	}
	if len(p.Waits) == 0 {
		return []string{r.paint.paint(mark+"the walk read no TTL to work out how long a change takes", yellow)}
	}

	lines := []string{r.paint.dim(mark + "how long a change to " + p.Zone + " takes to reach every cache, at worst")}
	var labels, spans []string
	for _, wait := range p.Waits {
		labels = append(labels, changes[wait.Change])
		spans = append(spans, span(wait.Seconds))
	}
	labelWidth := len(slices.MaxFunc(labels, func(a, b string) int { return len(a) - len(b) }))
	spanWidth := len(slices.MaxFunc(spans, func(a, b string) int { return len(a) - len(b) }))
	for i, wait := range p.Waits {
		lines = append(lines, fmt.Sprintf("%s  %-*s  %-*s  %s %s", mark,
			labelWidth, labels[i], spanWidth, spans[i], r.paint.rrtype(wait.Type), sources(wait.Held)))
	}

	for _, hint := range hints(r.trace, p) {
		lines = append(lines, r.paint.dim(mark+hint))
	}
	return lines
}

// sources says where each TTL of a wait was read, naming a zone once for the
// numbers it served in a row.
func sources(held []trace.Held) string {
	var said []string
	for i, h := range held {
		number := strconv.FormatUint(uint64(h.TTL), 10)
		if h.Field != "" {
			number = h.Field + " " + number
		}
		if i+1 < len(held) && strings.EqualFold(held[i+1].Zone, h.Zone) {
			said = append(said, number+",")
			continue
		}
		said = append(said, number+" at "+h.Zone+",")
	}
	return strings.TrimSuffix(strings.Join(said, " "), ",")
}

// hints are the waits the walk had no TTL for, and the flag that reads it.
func hints(tr *trace.Trace, p *trace.Propagation) []string {
	has := func(change trace.Change) *trace.Wait {
		for i := range p.Waits {
			if p.Waits[i].Change == change {
				return &p.Waits[i]
			}
		}
		return nil
	}

	var said []string
	if has(trace.ChangeDenial) == nil {
		said = append(said, "--serial reads the SOA, which says how long a missing record is kept")
	}
	if ns := has(trace.ChangeNameservers); ns != nil && len(ns.Held) == 1 {
		said = append(said, "the zone's own NS set may keep the nameservers longer; --check-ns reads it")
	}
	if has(trace.ChangeDS) == nil && has(trace.ChangeKeys) == nil && !checked(tr) {
		said = append(said, "--dnssec reads how long the DS and the keys are kept")
	}
	return said
}

// checked is whether the walk followed a chain of trust at all.
func checked(tr *trace.Trace) bool {
	if tr == nil {
		return false
	}
	for step := range tr.Steps() {
		if step.DNSSEC != nil {
			return true
		}
	}
	return false
}

// span is a TTL in the two largest units it fills.
func span(seconds uint32) string {
	units := []struct {
		size uint32
		name string
	}{{86400, "d"}, {3600, "h"}, {60, "m"}, {1, "s"}}
	for i, unit := range units {
		if seconds < unit.size && unit.size > 1 {
			continue
		}
		text := strconv.FormatUint(uint64(seconds/unit.size), 10) + unit.name
		if i+1 < len(units) {
			below := units[i+1]
			if rest := seconds % unit.size / below.size; rest > 0 {
				text += strconv.FormatUint(uint64(rest), 10) + below.name
			}
		}
		return text
	}
	return "0s"
}
