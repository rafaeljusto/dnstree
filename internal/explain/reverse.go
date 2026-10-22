package explain

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// reverse is whether the names the PTR set gives point back to the address -x
// asked about. A walk that found no PTR set to read is the outcome's to say.
func reverse(tr *trace.Trace) (Finding, bool) {
	c := tr.Reverse
	if c == nil || !c.PTR.Answered() {
		return Finding{}, false
	}
	if len(c.Names) == 0 {
		return Finding{Topic: Mail, Level: Note, Text: fmt.Sprintf(
			"%s has no name, so a mail receiver that checks forward-confirmed reverse DNS distrusts it", c.Addr)}, true
	}

	var back, why []string
	for _, name := range c.Names {
		if name.Back(c.Addr) {
			back = append(back, name.Name)
			continue
		}
		why = append(why, elsewhere(c, name))
	}
	switch {
	case len(back) > 0:
		return Finding{Topic: Mail, Level: Note, Text: fmt.Sprintf(
			"%s %s back to %s, so the address is forward-confirmed", strings.Join(back, ", "), agrees(back, "points", "point"), c.Addr)}, true
	case c.Cut:
		return Finding{Topic: Mail, Level: Warn, Text: fmt.Sprintf(
			"the reverse check of %s ran out of budget before every name was looked up, and none of those it reached points back", c.Addr)}, true
	}
	return Finding{Topic: Mail, Level: Warn, Text: fmt.Sprintf(
		"no name the PTR of %s gives points back to it, so a mail receiver that checks forward-confirmed reverse DNS distrusts it: %s",
		c.Addr, strings.Join(why, "; "))}, true
}

// elsewhere is why a name does not point back.
func elsewhere(c *trace.Reverse, name trace.ReverseName) string {
	qtype := "AAAA"
	if c.Addr.Is4() {
		qtype = "A"
	}
	switch {
	case name.Lookup.Err != "":
		return fmt.Sprintf("the %s lookup of %s failed (%s)", qtype, name.Name, name.Lookup.Err)
	case !name.Lookup.Answered():
		return fmt.Sprintf("the %s set of %s does not validate (%s)", qtype, name.Name, name.Lookup.DNSSEC.Reason)
	case len(name.Addrs) == 0:
		return fmt.Sprintf("%s has no %s record", name.Name, qtype)
	}
	var addrs []string
	for _, addr := range name.Addrs {
		addrs = append(addrs, addr.String())
	}
	return fmt.Sprintf("%s has %s", name.Name, strings.Join(addrs, ", "))
}
