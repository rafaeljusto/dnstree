package tree

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// dependencies draws what --deps found: how many zones the name depends on,
// then the zones a line for each nameserver that brought some in, the walk's
// own first. The lookups themselves are in the tree.
func (r *renderer) dependencies(d *trace.Dependencies) []string {
	if d == nil {
		return nil
	}
	mark := "deps: "
	if r.glyphs.icons {
		mark = spaced("🕸️")
	}

	count := fmt.Sprintf("%d zones", len(d.Zones))
	if len(d.Zones) == 1 {
		count = "1 zone"
	}
	if d.Stopped != "" {
		count = "at least " + count
	}
	head := mark + d.Name + " depends on " + count + " besides the root"
	if n := d.Unsigned(); n > 0 {
		head += fmt.Sprintf(", %d of them unsigned", n)
	}
	if n := d.Bogus(); n > 0 {
		head += fmt.Sprintf(", %d bogus", n)
	}
	lines := []string{r.paint.dim(head)}

	for start := 0; start < len(d.Zones); {
		end, warn := start, false
		var zones []string
		for ; end < len(d.Zones) && d.Zones[end].Via == d.Zones[start].Via && d.Zones[end].For == d.Zones[start].For; end++ {
			zone := d.Zones[end]
			if state := unsigned(zone.DNSSEC); state != "" {
				zones = append(zones, zone.Zone+" ("+state+")")
				warn = true
				continue
			}
			zones = append(zones, zone.Zone)
		}
		by := "the walk"
		if via := d.Zones[start].Via; via != "" {
			by = "by " + via + ", a nameserver of " + d.Zones[start].For
		}
		text := mark + "  " + strings.Join(zones, ", ") + "  " + by
		if warn {
			lines = append(lines, r.paint.paint(text, yellow))
		} else {
			lines = append(lines, r.paint.dim(text))
		}
		start = end
	}

	lines = append(lines, r.work(mark, d.Work)...)

	for _, ns := range d.Unresolved {
		lines = append(lines, r.paint.paint(mark+"  "+ns.Name+", a nameserver of "+ns.For+": "+ns.Err, yellow))
	}
	if d.Stopped != "" {
		lines = append(lines, r.paint.paint(mark+"stopped: "+d.Stopped, yellow))
	}
	return lines
}

// work says what a resolver with an empty cache must do to reach each zone on
// the walk's way whose delegation, or one above it, came without glue, or the
// last zone where every one came with it.
func (r *renderer) work(mark string, work []trace.ZoneWork) []string {
	var lines []string
	for _, w := range work {
		if w.Glueless == 0 {
			continue
		}
		lines = append(lines,
			r.paint.dim(fmt.Sprintf("%sa resolver with an empty cache makes at least %s before it can ask %s anything", mark, queries(w.Queries), w.Zone)),
			r.paint.dim(fmt.Sprintf("%s  %d of them look up nameserver addresses no glue gave, %s, %s", mark, w.Glueless, through(w.Via), deep(w.Depth))))
	}
	if lines == nil && len(work) > 0 {
		w := work[len(work)-1]
		lines = append(lines, r.paint.dim(fmt.Sprintf("%sa resolver with an empty cache makes at least %s before it can ask %s anything, every delegation on the way with glue", mark, queries(w.Queries), w.Zone)))
	}
	return lines
}

func queries(n int) string {
	if n == 1 {
		return "1 query"
	}
	return fmt.Sprintf("%d queries", n)
}

// through names the nameserver the fewest queries reach a zone by, where its
// own delegation came without glue.
func through(via string) string {
	if via == "" {
		return "for a zone above it"
	}
	return "the fewest by " + via
}

// deep says how many delegations without glue are stacked on the way.
func deep(depth int) string {
	if depth == 1 {
		return "1 delegation without glue deep"
	}
	return fmt.Sprintf("%d delegations without glue deep", depth)
}

// unsigned is what a zone's delegation is worth saying about, empty for one
// that is signed or was never checked.
func unsigned(status *trace.DNSSECStatus) string {
	switch {
	case status == nil:
		return ""
	case status.State == trace.Insecure:
		return "unsigned"
	case status.State == trace.Bogus:
		return "bogus"
	}
	return ""
}
