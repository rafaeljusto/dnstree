package tree

import (
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// reverse draws whether each name the PTR set gives points back to the
// address -x asked about. The lookups themselves are in the tree, and a walk
// that found no PTR set to read is the summary's to say.
func (r *renderer) reverse(c *trace.Reverse) []string {
	if c == nil || !c.PTR.Answered() {
		return nil
	}
	mark := "ptr: "
	if r.glyphs.icons {
		mark = spaced("🔁")
	}
	addr := c.Addr.String()
	if len(c.Names) == 0 {
		return []string{r.paint.dim(mark + addr + " has no name to point back to it")}
	}

	qtype := "AAAA"
	if c.Addr.Is4() {
		qtype = "A"
	}
	var lines []string
	for _, name := range c.Names {
		text := mark + name.Name
		if name.Lookup.Alias != "" {
			text += " (through " + name.Lookup.Alias + ")"
		}
		switch {
		case name.Back(c.Addr):
			lines = append(lines, join(r.paint.dim(text+" points back to "+addr), r.dnssec(name.Lookup.DNSSEC)))
			continue
		case name.Lookup.Err != "":
			text += " was not confirmed: " + name.Lookup.Err
		case !name.Lookup.Answered():
			text += " was not confirmed: its " + qtype + " set does not validate"
		case len(name.Addrs) == 0:
			text += " does not point back: it has no " + qtype + " record"
		default:
			var addrs []string
			for _, a := range name.Addrs {
				addrs = append(addrs, a.String())
			}
			text += " does not point back: it has " + strings.Join(addrs, ", ") + ", not " + addr
		}
		lines = append(lines, r.paint.paint(text, yellow))
	}
	if c.Cut {
		lines = append(lines, r.paint.paint(mark+"the budget ran out before every name was looked up", yellow))
	}
	return lines
}
