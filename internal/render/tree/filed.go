package tree

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/served"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Filing is what --zone-file read: the file, its zone, and what it held that
// was not asked.
type Filing struct {
	Path, Zone                           string
	Names, Wildcards, Escaped, Unaskable int
}

// FiledQuestion is one question --zone-file walked: what the file says against
// what the servers said, and the walk that asked them.
type FiledQuestion struct {
	Match served.Match
	Walk  *trace.Trace
}

// Filed is what --zone-file prints in place of trees: a line to each question
// saying whether the zone's servers serve what the file holds, and whether the
// walk found the name left pointing at something nobody holds.
func Filed(w io.Writer, filing Filing, questions []FiledQuestion, opts Options) {
	paint := painter(ColorEnabled(w, opts.Color))
	out := bufio.NewWriter(w)
	defer out.Flush()

	head := fmt.Sprintf("%s from %s, against its servers: %s, %s", paint.server(trace.Shown(filing.Zone)), trace.Shown(filing.Path),
		plural(filing.Names, "name", "names"), plural(len(questions), "question", "questions"))
	var unasked []string
	if filing.Wildcards > 0 {
		unasked = append(unasked, plural(filing.Wildcards, "wildcard", "wildcards"))
	}
	if filing.Escaped > 0 {
		unasked = append(unasked, plural(filing.Escaped, "name with an escape", "names with an escape"))
	}
	if filing.Unaskable > 0 {
		unasked = append(unasked, plural(filing.Unaskable, "set of a type this build cannot ask", "sets of a type this build cannot ask"))
	}
	if len(unasked) > 0 {
		head += "; not asked: " + strings.Join(unasked, ", ")
	}
	fmt.Fprintln(out, head)

	width := 0
	for _, question := range questions {
		width = max(width, len(question.Match.Question.Name)+1+len(question.Match.Question.Type))
	}
	same, dangled := 0, 0
	for _, question := range questions {
		match := question.Match
		label := match.Question.Name + " " + match.Question.Type
		pad := strings.Repeat(" ", width-len(label)+2)
		label = paint.server(match.Question.Name) + " " + paint.rrtype(match.Question.Type)

		var said []string
		if match.Same() {
			same++
			said = append(said, paint.dim("same"))
		} else {
			color := yellow
			if match.Tried.Kind == "" {
				color = red
			}
			said = append(said, paint.paint(strings.Join(unfiled(match), "; "), color))
		}
		if left := danglings(question.Walk); len(left) > 0 {
			dangled++
			said = append(said, paint.paint(strings.Join(left, "; "), yellow))
		}
		fmt.Fprintf(out, "  %s%s%s\n", label, pad, strings.Join(said, "; "))
	}

	differ := len(questions) - same
	verb := "differ"
	if differ == 1 {
		verb = "differs"
	}
	foot := fmt.Sprintf("%d the same, %d %s", same, differ, verb)
	if dangled > 0 {
		foot += fmt.Sprintf(", %d dangling", dangled)
	}
	fmt.Fprintln(out, paint.dim(foot+separator(opts.Charset)+"serials are not compared"))
}

// unfiled is how the servers' answer to one question differs from the file.
func unfiled(match served.Match) []string {
	switch tried := match.Tried.Kind; {
	case tried == "":
		return []string{"no answer from the servers"}
	case tried == string(trace.KindNXDomain) || tried == string(trace.KindNoData):
		return []string{tried + " at the servers"}
	}
	var said []string
	if len(match.Missing) > 0 {
		said = append(said, "only in the file: "+records(match, match.Missing))
	}
	if len(match.Extra) > 0 {
		said = append(said, "only at the servers: "+records(match, match.Extra))
	}
	for _, ttl := range match.TTLs {
		set := ""
		if unowned := unowned(match, ttl.Set); !strings.EqualFold(unowned, match.Question.Type) {
			set = unowned + " "
		}
		said = append(said, fmt.Sprintf("%sttl %d in the file, %d at the servers", set, ttl.Current, ttl.Tried))
	}
	return said
}

// danglings is every name the walk recorded as left pointing at something
// nobody holds, once each.
func danglings(tr *trace.Trace) []string {
	var said []string
	seen := map[trace.Dangling]bool{}
	for step := range tr.Shown().Steps() {
		dangling := step.Dangling
		if dangling == nil || seen[*dangling] {
			continue
		}
		seen[*dangling] = true
		switch dangling.Kind {
		case trace.DanglingNameserver, trace.DanglingAlias:
			said = append(said, fmt.Sprintf("dangling %s: %s is missing", dangling.Kind, dangling.Missing))
		case trace.DanglingLame:
			said = append(said, "dangling: every nameserver of "+dangling.Name+" lame")
		}
	}
	return said
}
