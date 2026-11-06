package tree

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/served"
)

// Compared is what --compare-ns prints in place of trees: a line to each
// question saying whether the servers tried serve what the zone's own do, and
// a count of both under them. The matches are of one zone tried at the same
// servers.
func Compared(w io.Writer, matches []served.Match, opts Options) {
	if len(matches) == 0 {
		return
	}
	paint := painter(ColorEnabled(w, opts.Color))
	zone, servers := matches[0].Zone, strings.Join(matches[0].Servers, ", ")
	arrow := " " + cmp.Or(charsets[opts.Charset], charsets[Unicode]).arrow + " "

	out := bufio.NewWriter(w)
	defer out.Flush()
	fmt.Fprintf(out, "%s at the servers it is delegated to, against %s: %s\n",
		paint.server(zone), paint.server(servers), plural(len(matches), "question", "questions"))

	// Before the move, many providers refuse a zone nobody has delegated to
	// them yet, which is one fact and not a record missing per question.
	silent := 0
	for _, match := range matches {
		if match.Tried.Kind == "" && match.Current.Kind != "" {
			silent++
		}
	}
	if silent == len(matches) {
		fmt.Fprintf(out, "  %s\n", paint.paint("the new servers answered none of them: they may not serve "+zone+" yet", red))
		return
	}

	width := 0
	for _, match := range matches {
		width = max(width, len(match.Question.Name)+1+len(match.Question.Type))
	}
	same := 0
	for _, match := range matches {
		label := match.Question.Name + " " + match.Question.Type
		pad := strings.Repeat(" ", width-len(label)+2)
		label = paint.server(match.Question.Name) + " " + paint.rrtype(match.Question.Type)
		if match.Same() {
			same++
			fmt.Fprintf(out, "  %s%s%s\n", label, pad, paint.dim("same"))
			continue
		}
		color := yellow
		if match.Tried.Kind == "" {
			color = red
		}
		fmt.Fprintf(out, "  %s%s%s\n", label, pad, paint.paint(strings.Join(differences(match, arrow), "; "), color))
	}

	differ := len(matches) - same
	verb := "differ"
	if differ == 1 {
		verb = "differs"
	}
	sep := separator(opts.Charset)
	fmt.Fprintln(out, paint.dim(fmt.Sprintf("%d the same, %d %s%sonly the questions asked were compared", same, differ, verb, sep)))
}

// differences is what one question came to on each side, most telling first.
func differences(match served.Match, arrow string) []string {
	var said []string
	current, tried := match.Current.Kind, match.Tried.Kind
	switch {
	case tried == "":
		return []string{"no answer at the new servers"}
	case current == "":
		said = append(said, "no answer at the old servers")
	case current != tried:
		said = append(said, fmt.Sprintf("%s at the new servers, %s at the old", tried, current))
	}
	if len(match.Missing) > 0 {
		said = append(said, "missing at the new servers: "+records(match, match.Missing))
	}
	if len(match.Extra) > 0 && current != "" {
		said = append(said, "only at the new servers: "+records(match, match.Extra))
	}
	for _, ttl := range match.TTLs {
		set := ""
		if unowned := unowned(match, ttl.Set); !strings.EqualFold(unowned, match.Question.Type) {
			set = unowned + " "
		}
		said = append(said, set+"ttl "+strconv.FormatUint(uint64(ttl.Current), 10)+arrow+strconv.FormatUint(uint64(ttl.Tried), 10))
	}
	return said
}

// records lists records the way the line names them: by type and data alone
// where they belong to the name asked about.
func records(match served.Match, list []string) string {
	written := make([]string, 0, len(list))
	for _, record := range list {
		written = append(written, unowned(match, record))
	}
	return strings.Join(written, ", ")
}

// unowned is a record, or a set, without its owner where that is the name
// asked about. The owner is cut off by the name rather than at a space: a
// label may hold one.
func unowned(match served.Match, record string) string {
	if rest, ok := strings.CutPrefix(record, strings.ToLower(match.Question.Name)+" "); ok {
		return rest
	}
	return record
}
