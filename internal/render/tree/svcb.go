package tree

import (
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// servicePath draws what --svcb found: each set of the alias chain, the
// servers the last one names with their addresses, and where it stopped. The
// lookups themselves are in the tree.
func (r *renderer) servicePath(p *trace.ServicePath) []string {
	if p == nil {
		return nil
	}
	mark := "svcb: "
	if r.glyphs.icons {
		mark = spaced("🧭")
	}

	var lines []string
	for _, set := range p.Chain {
		verdict := r.dnssec(set.Lookup.DNSSEC)
		if set.Lookup.Err != "" {
			continue // Stopped says why
		}
		at := set.Lookup.Name
		if set.Lookup.Alias != "" {
			at = set.Lookup.Alias
		}
		if len(set.Records) == 0 {
			lines = append(lines, join(r.paint.dim(mark+"no "+p.Type+" records at "+at), verdict))
			continue
		}
		for i, record := range set.Records {
			line := r.paint.dim(mark + record.Name + " " + record.Type + " " + record.Data)
			if record.Service != nil && record.Service.ECH {
				line += "  " + r.paint.paint("[ech]", green)
			}
			if i == 0 {
				line = join(line, verdict)
			}
			lines = append(lines, line)
		}
	}

	switch {
	case p.None && len(p.Chain) > 0:
		lines = append(lines, r.paint.dim(mark+p.Chain[len(p.Chain)-1].Lookup.Name+" says it offers no service"))
	case p.Fallback && len(p.Targets) > 0:
		lines = append(lines, r.paint.dim(mark+"so a client connects to "+p.Targets[0].Name+" by its addresses alone"))
	case p.Fallback:
		lines = append(lines, r.paint.dim(mark+"so a client connects as it would without them"))
	}

	for _, target := range p.Targets {
		text := mark + "  " + target.Name + " "
		var addrs []string
		for _, addr := range target.Addrs {
			addrs = append(addrs, addr.String())
		}
		switch {
		case len(addrs) > 0:
			text += strings.Join(addrs, ", ")
		case target.IPv4 == nil && target.IPv6 == nil:
			text += "not looked up"
		case target.Failed() != "":
			text += "address lookup failed: " + target.Failed()
		default:
			text += "no address"
		}
		var stray []string
		for _, hint := range target.Stray {
			stray = append(stray, hint.String())
		}
		switch {
		case len(stray) == 1:
			lines = append(lines, r.paint.paint(text+"; hint "+stray[0]+" is not among them", yellow))
		case len(stray) > 1:
			lines = append(lines, r.paint.paint(text+"; hints "+strings.Join(stray, ", ")+" are not among them", yellow))
		case len(addrs) == 0:
			lines = append(lines, r.paint.paint(text, yellow))
		default:
			lines = append(lines, r.paint.dim(text))
		}
	}

	if p.Stopped != "" {
		lines = append(lines, r.paint.paint(mark+"stopped: "+p.Stopped, yellow))
	}
	if p.Cut {
		lines = append(lines, r.paint.paint(mark+"the budget ran out before every target was looked up", yellow))
	}
	return lines
}
