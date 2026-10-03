// Package recursive holds what a recursive server answered against what the
// walk found for itself. A walk from the root keeps no cache and takes every
// step itself, so what it costs only reads as slow or fast against what the
// ordinary path costs; transport.Ask fetches that other number.
package recursive

import (
	"slices"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Compare sets how the resolver's answer stands against the one the walk found
// for itself, which is the whole reason for keeping both.
//
// They are allowed to differ honestly. A CDN answers for where the question
// seems to come from, and a walk from the root and a resolver are rarely in
// the same place; a short TTL can turn over between the two questions. What a
// difference is worth looking at for is the other reason: a resolver that is
// not resolving, but answering out of a policy, a split horizon or a filter.
// The tool reports the difference and leaves that reading to the reader.
func Compare(tr *trace.Trace) {
	if tr == nil {
		return
	}
	result := tr.Result()
	if result == nil {
		return // nothing of our own to set it against
	}
	for _, answer := range tr.Resolvers {
		compare(tr, result, answer)
	}
}

// compare is one resolver's answer held against the walk's. Each of them is
// judged on its own: several resolvers are several places to have asked from,
// and one of them disagreeing says nothing about the others.
func compare(tr *trace.Trace, result *trace.Step, answer *trace.Resolver) {
	if answer == nil || answer.Err != "" {
		return
	}

	// A resolver that answered REFUSED or SERVFAIL did not resolve anything,
	// so there is no answer of its own to hold against the walk's. The rcode
	// is already on the summary line and says the whole of it; calling that a
	// difference would be reading a broken resolver as a disagreeing one.
	switch answer.Rcode {
	case "NOERROR", "NXDOMAIN":
	default:
		return
	}

	// A different rcode is a difference whatever the records say, and it is the
	// loud one: the name is there for one of them and not for the other. A
	// compact denial is an NXDOMAIN sent as NOERROR (RFC 9824), and a resolver
	// may hand it on either way.
	rcode := result.Rcode
	if result.Compact {
		if answer.Rcode == "NOERROR" && len(trace.Answers(answer.Records, tr.Question.Type)) == 0 {
			return
		}
		rcode = "NXDOMAIN"
	}
	if rcode != "" && rcode != answer.Rcode {
		answer.Match = trace.MatchDiffers
		return
	}

	// Only the records that answer the question are compared, by rdata and not
	// by order: a nameserver is free to rotate an RRset between two questions,
	// and an alias chain reaches the same records by a different name.
	ours := trace.Answers(result.Records, tr.Question.Type)
	theirs := trace.Answers(answer.Records, tr.Question.Type)
	if len(ours) == 0 && len(theirs) == 0 {
		return
	}
	if slices.Equal(ours, theirs) {
		answer.Match = trace.MatchSame
		if trace.TTL(answer.Records, tr.Question.Type) > tr.Allowed() {
			answer.Kept = trace.KeptLonger
		}
		return
	}
	answer.Match = trace.MatchDiffers
	if stale(tr, answer, theirs) {
		answer.Kept = trace.KeptStale
	}
}

// staleTTL is the TTL RFC 8767 suggests a stale answer goes out with. It is a
// suggestion and not a rule, which is why an answer carrying it only looks
// stale, and only when nothing the zone said accounts for it.
const staleTTL = 30

// stale is whether a differing answer looks served past its life: no
// authoritative server the walk asked gave any of it, and it carries what
// serve-stale hands out on a name whose own TTL is longer than that. A CDN
// answering by place differs too, but out of records some server of its zone
// does give.
func stale(tr *trace.Trace, answer *trace.Resolver, theirs []string) bool {
	if len(theirs) == 0 {
		return false
	}
	cached := trace.TTL(answer.Records, tr.Question.Type)
	if cached == 0 || cached > staleTTL || tr.Allowed() <= staleTTL {
		return false
	}

	// Every server --all asked is a place the zone could have given it from.
	// The asides answered other questions, a nameserver's address among them.
	served := make(map[string]bool)
	for step := range tr.Mainline() {
		if step.Minimised || (step.Kind != trace.KindAnswer && step.Kind != trace.KindCNAME) {
			continue
		}
		for _, data := range trace.Answers(step.Records, tr.Question.Type) {
			served[data] = true
		}
	}
	for _, data := range theirs {
		if served[data] {
			return false
		}
	}
	return true
}
