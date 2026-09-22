package tree

import (
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// Summary is the line under a finished tree: how the walk went, what a resolver
// made of the same question, and what the walk cost. A walk from the root is
// the slow way round by design, so the resolver's time is what says whether the
// wait was the name's doing or the method's.
func Summary(w io.Writer, tr *trace.Trace, opts Options) {
	if tr == nil {
		return
	}
	queries, servers := spent(tr)
	writeSummary(w, tr, painter(colorEnabled(w, opts.Color)), separator(opts.Charset),
		opts.Charset, tr.Elapsed, counts(queries, servers))
}

// writeSummary is the line itself, which a live drawing and a finished tree
// reach by different roads: one counted the queries as they went out, the other
// reads them off the trace.
func writeSummary(w io.Writer, tr *trace.Trace, paint painter, sep string,
	charset Charset, elapsed time.Duration, counts []string) {

	mark, verdict, color := "✔", "answered", green
	switch {
	case bogus(tr):
		mark, verdict, color = "✘", "bogus", red
	case tr.Result() == nil && tr.Filtered() != nil:
		// Not the same as nothing answering: something did answer, and what it
		// answered was that it would not.
		mark, verdict, color = "✘", "filtered", red
	case tr.Result() == nil:
		mark, verdict, color = "✘", "no answer", yellow
	}
	if charset == ASCII {
		mark = ""
	}

	fields := []string{verdict + " in " + clock(elapsed)}
	if timing := resolverField(tr.Resolvers); timing != "" {
		fields = append(fields, timing)
	}
	fields = append(fields, counts...)

	line := paint.dim(strings.Join(fields, sep))
	if mark != "" {
		line = paint.paint(mark, color) + " " + line
	}
	_, _ = io.WriteString(w, line+"\n")
}

// resolverField is what a recursive server made of the same question, empty
// when none was asked. A server that would not answer still says something
// worth the room: the comparison was tried and there is none.
func resolverField(answers []*trace.Resolver) string {
	switch len(answers) {
	case 0:
		return ""
	case 1:
		return oneResolver(answers[0])
	}

	// Several of them were asked to be held against each other rather than to
	// be timed one by one, so the field says how far apart they were and how
	// many of them disagreed.
	var (
		elapsed        []time.Duration
		differ, silent int
	)
	for _, answer := range answers {
		if answer.Err != "" {
			silent++
			continue
		}
		elapsed = append(elapsed, answer.Elapsed)
		if answer.Match == trace.MatchDiffers {
			differ++
		}
	}
	if len(elapsed) == 0 {
		return plural(len(answers), "resolver", "resolvers") + " did not answer"
	}

	fastest, slowest := slices.Min(elapsed), slices.Max(elapsed)
	field := "resolvers in " + clock(fastest)
	if slowest != fastest {
		field += "-" + clock(slowest)
	}

	var aside []string
	if differ > 0 {
		aside = append(aside, fmt.Sprintf("%d of %d differ", differ, len(answers)))
	}
	if silent > 0 {
		aside = append(aside, fmt.Sprintf("%d did not answer", silent))
	}
	if len(aside) > 0 {
		field += " (" + strings.Join(aside, ", ") + ")"
	}
	return field
}

// oneResolver is the field a single recursive server earns, which is the one
// every run that asks for the comparison at all has had.
func oneResolver(answer *trace.Resolver) string {
	switch {
	case answer == nil:
		return ""
	case answer.Err != "":
		return "resolver did not answer"
	}

	var aside []string
	if answer.Rcode != "" && answer.Rcode != "NOERROR" && answer.Rcode != "NXDOMAIN" {
		aside = append(aside, answer.Rcode)
	}
	// Only a disagreement is worth the room. Agreement is what the reader is
	// expecting, and the tree says what the difference is when there is one.
	if answer.Match == trace.MatchDiffers {
		aside = append(aside, "differs")
	}

	field := "resolver in " + clock(answer.Elapsed)
	if len(aside) > 0 {
		field += " (" + strings.Join(aside, ", ") + ")"
	}
	return field
}

// spent is what a finished walk cost, read off the trace: one query per hop it
// made, and the servers those hops went to. A hop that was only listed was
// never asked, and costs nothing.
func spent(tr *trace.Trace) (queries int, servers int) {
	seen := make(map[netip.Addr]struct{})
	for step := range tr.Steps() {
		if step.Kind == trace.KindZone || step.Kind == trace.KindSkipped {
			continue
		}
		queries++
		if step.Server.IP.IsValid() {
			seen[step.Server.IP] = struct{}{}
		}
	}
	return queries, len(seen)
}

// counts spells out what the walk spent, dropping whatever it did not.
func counts(queries, servers int) []string {
	var fields []string
	if queries > 0 {
		fields = append(fields, plural(queries, "query", "queries"))
	}
	if servers > 0 {
		fields = append(fields, plural(servers, "server", "servers"))
	}
	return fields
}

// separator is what the fields of a summary or a footer are set apart by, kept
// to what the charset can draw.
func separator(charset Charset) string {
	if charset == ASCII {
		return " | "
	}
	return " · "
}
