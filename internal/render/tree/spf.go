package tree

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// policy draws the sender policy --spf followed, as the tree of lookups a
// receiving mail server makes for it, and what a check of it comes to.
func (r *renderer) policy(spf *trace.SPF) []string {
	if spf == nil {
		return nil
	}
	mark := "spf: "
	if r.glyphs.icons {
		mark = spaced("📨")
	}

	var lines []string
	if spf.Record != "" {
		short := spf.Cut || spf.Result == trace.SPFUndecided
		count := fmt.Sprintf("%s takes %s of %d lookups", spf.Name, floor(spf.Lookups, short), trace.SPFLookupLimit)
		if spf.Void > 0 {
			count += fmt.Sprintf(", %s of %d finding nothing", floor(spf.Void, short), trace.SPFVoidLimit)
		}
		if spf.Server.IP.IsValid() {
			count += ", asked of " + spf.Server.IP.String()
		}
		lines = append(lines, r.paint.dim(mark+count))
		lines = r.terms(lines, spf.Terms, "")
	}

	switch spf.Result {
	case trace.SPFOK:
		if spf.Lookups == trace.SPFLookupLimit {
			lines = append(lines, r.paint.paint(mark+"ok, at the limit: one more lookup in any policy it includes is a permerror", yellow))
			break
		}
		lines = append(lines, r.paint.paint(mark+"ok: nothing in it fails a check", green))
	case trace.SPFNone:
		lines = append(lines, r.paint.dim(mark+"none: "+spf.Why))
	case trace.SPFPermError:
		lines = append(lines, r.paint.paint(mark+"permerror: "+spf.Why, red))
	default:
		lines = append(lines, r.paint.paint(mark+string(spf.Result)+": "+spf.Why, yellow))
	}
	return lines
}

// floor is a count, said as the least it can be where the check was cut short.
func floor(n int, cut bool) string {
	if cut {
		return "at least " + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// terms draws one policy's terms. The address ranges are drawn as one line,
// since a provider's policy can list dozens and none of them costs a lookup,
// and the terms no check reaches as another.
func (r *renderer) terms(lines []string, terms []trace.SPFTerm, prefix string) []string {
	type row struct {
		label string
		terms []trace.SPFTerm
	}
	var rows []row
	ranges, folded := 0, -1
	var unreached []string
	for _, term := range terms {
		switch {
		case term.Unreached:
			unreached = append(unreached, term.Term)
		case (term.Kind == "ip4" || term.Kind == "ip6") && term.Problem == "":
			if folded < 0 {
				folded = len(rows)
				rows = append(rows, row{})
			}
			ranges++
		default:
			rows = append(rows, row{label: r.term(term), terms: term.Terms})
		}
	}
	if folded >= 0 {
		rows[folded].label = r.paint.dim(plural(ranges, "address range", "address ranges"))
	}
	if len(unreached) > 0 {
		rows = append(rows, row{label: r.paint.dim("never reached: " + strings.Join(unreached, " "))})
	}

	for i, row := range rows {
		last := i == len(rows)-1
		lines = append(lines, prefix+r.branch(last, false)+row.label)
		lines = r.terms(lines, row.terms, prefix+r.continuation(last))
	}
	return lines
}

// term is one term and what it cost.
func (r *renderer) term(term trace.SPFTerm) string {
	var about []string
	if term.Lookup > 0 {
		about = append(about, "lookup "+strconv.Itoa(term.Lookup))
	}
	switch {
	case term.Sender:
		about = append(about, "depends on the sender")
	case term.Void:
		about = append(about, "found nothing")
	case term.Kind == "mx":
		about = append(about, plural(len(term.Found), "mail server", "mail servers"))
	case len(term.Found) > 0:
		about = append(about, plural(len(term.Found), "address", "addresses"))
	}

	label := term.Term
	if len(about) > 0 {
		label += " " + r.paint.dim("("+strings.Join(about, ", ")+")")
	}
	switch {
	case term.Fatal:
		label += ": " + r.paint.paint(term.Problem, red)
	case term.Problem != "":
		label += ": " + r.paint.paint(term.Problem, yellow)
	}
	return label
}
