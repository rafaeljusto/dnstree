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

	for _, ns := range d.Unresolved {
		lines = append(lines, r.paint.paint(mark+"  "+ns.Name+", a nameserver of "+ns.For+": "+ns.Err, yellow))
	}
	if d.Stopped != "" {
		lines = append(lines, r.paint.paint(mark+"stopped: "+d.Stopped, yellow))
	}
	return lines
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
