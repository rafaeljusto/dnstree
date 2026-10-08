package recursive

import (
	"slices"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Behave reads what each resolver --check-resolver asked was seen to do. It
// says Unknown wherever the answers could mean two things: a test zone run by
// somebody else can change, and a resolver is not the only thing between here
// and the authoritative servers.
func Behave(tr *trace.Trace) {
	if tr == nil {
		return
	}
	for _, answer := range tr.Resolvers {
		if answer == nil || answer.Behaviour == nil {
			continue
		}
		answer.Behaviour.Validates = validates(answer.Behaviour)
		answer.Behaviour.Rewrites = rewrites(answer.Behaviour)
	}
}

// validates is whether the resolver refused the broken name. One that fails
// it, and answers once told not to check, failed its validation. One that
// answers it outright does not validate, unless the root's SOA came back
// authentic: then the test zone is likelier to have been fixed than the
// resolver to be validating everything but it.
func validates(b *trace.Behaviour) trace.Observed {
	broken, root := b.Broken, b.Root
	switch {
	case broken == nil || broken.Err != "":
		return trace.ObservedUnknown
	case broken.Rcode == "SERVFAIL":
		if again := broken.Unchecked; again != nil && again.Err == "" && again.Rcode == "NOERROR" {
			return trace.ObservedYes
		}
		if slices.ContainsFunc(broken.Extended, trace.ExtendedError.Validation) {
			return trace.ObservedYes
		}
	case broken.Rcode == "NOERROR" && len(trace.Answers(broken.Records, "A")) > 0 && !broken.Authentic &&
		root != nil && root.Err == "" && root.Rcode == "NOERROR" && !root.Authentic:
		return trace.ObservedNo
	}
	return trace.ObservedUnknown
}

// rewrites is whether a name that cannot exist came back with addresses.
func rewrites(b *trace.Behaviour) trace.Observed {
	missing := b.Missing
	switch {
	case missing == nil || missing.Err != "":
		return trace.ObservedUnknown
	case missing.Rcode == "NXDOMAIN":
		return trace.ObservedNo
	case missing.Rcode == "NOERROR" && len(trace.Answers(missing.Records, "A")) > 0:
		return trace.ObservedYes
	}
	return trace.ObservedUnknown
}
