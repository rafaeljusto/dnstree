package tree

import (
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// srv draws what --srv found: the records of the set, by priority, each with
// what its target resolves to, and where the check stopped. The lookups
// themselves are in the tree.
func (r *renderer) srv(s *trace.SRV) []string {
	if s == nil {
		return nil
	}
	mark := "srv: "
	if r.glyphs.icons {
		mark = spaced("📍")
	}

	at := s.Name
	if s.Lookup.Alias != "" {
		at = s.Lookup.Alias
	}
	verdict := r.dnssec(s.Lookup.DNSSEC)
	var lines []string
	switch {
	case s.Stopped != "":
	case s.None:
		lines = append(lines, join(r.paint.dim(mark+at+" says the service is not offered there"), verdict))
	case len(s.Targets) == 0 && s.Left == 0:
		lines = append(lines, join(r.paint.dim(mark+"no SRV records at "+at), verdict))
	default:
		lines = append(lines, join(r.paint.dim(mark+plural(len(s.Targets)+s.Left, "SRV record", "SRV records")+" at "+at), verdict))
	}

	for _, target := range s.Targets {
		text := mark + "  " + strconv.Itoa(int(target.Priority)) + " " + strconv.Itoa(int(target.Weight)) + " " +
			strconv.Itoa(int(target.Port)) + " " + target.Name + " "
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
		case target.Nowhere():
			text += "no address"
		default:
			text += "address unknown"
		}
		if alias := target.Alias(); alias != "" {
			text += "; an alias for " + alias
		}
		var unreachable []string
		for _, addr := range target.Unreachable {
			unreachable = append(unreachable, addr.String())
		}
		if len(unreachable) > 0 {
			text += "; " + strings.Join(unreachable, ", ") + " cannot be reached from the internet"
		}
		if len(addrs) == 0 || target.Alias() != "" || len(unreachable) > 0 {
			lines = append(lines, r.paint.paint(text, yellow))
		} else {
			lines = append(lines, r.paint.dim(text))
		}
	}

	if s.Stopped != "" {
		lines = append(lines, r.paint.paint(mark+"stopped: "+s.Stopped, yellow))
	}
	if s.Left > 0 {
		lines = append(lines, r.paint.paint(mark+"the budget ran out before "+plural(s.Left, "target was", "targets were")+" looked up", yellow))
	} else if s.Cut {
		lines = append(lines, r.paint.paint(mark+"the budget ran out before every target was looked up", yellow))
	}
	return lines
}
