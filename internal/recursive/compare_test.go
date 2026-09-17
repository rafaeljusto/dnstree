package recursive_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/internal/recursive"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// traceOf is a finished walk and a resolver's answer to the same question, with
// nothing in it but what the comparison reads.
func traceOf(rcode string, ours []string, answer *trace.Resolver) *trace.Trace {
	records := make([]trace.RR, 0, len(ours))
	for _, data := range ours {
		records = append(records, trace.RR{Name: "www.test.", Type: "A", Data: data})
	}

	return &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: "test.", Kind: trace.KindAnswer, Rcode: rcode, Records: records,
		}}},
		Resolver: answer,
	}
}

// answerOf is what the resolver said, in the same shape.
func answerOf(rcode string, theirs ...string) *trace.Resolver {
	records := make([]trace.RR, 0, len(theirs))
	for _, data := range theirs {
		records = append(records, trace.RR{Name: "www.test.", Type: "A", Data: data})
	}
	return &trace.Resolver{Rcode: rcode, Records: records}
}

func TestCompare(t *testing.T) {
	for _, tt := range []struct {
		name  string
		tr    *trace.Trace
		match trace.Match
	}{{
		name:  "the same answer",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, answerOf("NOERROR", "192.0.2.10")),
		match: trace.MatchSame,
	}, {
		// A nameserver is free to hand an RRset out in any order it likes, and
		// two of them doing so is not a disagreement about anything.
		name:  "the same addresses, rotated",
		tr:    traceOf("NOERROR", []string{"192.0.2.10", "192.0.2.11"}, answerOf("NOERROR", "192.0.2.11", "192.0.2.10")),
		match: trace.MatchSame,
	}, {
		name:  "a different address",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, answerOf("NOERROR", "10.0.0.1")),
		match: trace.MatchDiffers,
	}, {
		// The loud one: the name is there for one of them and not the other.
		name:  "a different rcode",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, answerOf("NXDOMAIN")),
		match: trace.MatchDiffers,
	}, {
		name:  "one address more",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, answerOf("NOERROR", "192.0.2.10", "192.0.2.11")),
		match: trace.MatchDiffers,
	}, {
		// Both agree the name is not there. There are no records to hold
		// against each other, and the matching rcodes already said it.
		name:  "neither has the name",
		tr:    traceOf("NXDOMAIN", nil, answerOf("NXDOMAIN")),
		match: "",
	}, {
		name:  "the resolver did not answer",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, &trace.Resolver{Err: "i/o timeout"}),
		match: "",
	}, {
		// A resolver that refused did not resolve, so it has no answer of its
		// own to disagree with. The rcode says that on its own, and reading it
		// as a difference would turn a broken resolver into a suspicious one.
		name:  "the resolver refused",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, answerOf("REFUSED")),
		match: "",
	}, {
		name:  "the resolver failed",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, answerOf("SERVFAIL")),
		match: "",
	}, {

		name:  "no comparison was asked for",
		tr:    traceOf("NOERROR", []string{"192.0.2.10"}, nil),
		match: "",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			recursive.Compare(tt.tr)

			got := trace.Match("")
			if tt.tr.Resolver != nil {
				got = tt.tr.Resolver.Match
			}
			if got != tt.match {
				t.Errorf("got %q, want %q", got, tt.match)
			}
		})
	}
}

// TestCompareWithoutResult covers a walk that never got anywhere. There is
// nothing of our own to set the resolver's answer against, and its answer alone
// is not evidence of anything.
func TestCompareWithoutResult(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		Resolver: answerOf("NOERROR", "192.0.2.10"),
	}

	recursive.Compare(tr)
	if tr.Resolver.Match != "" {
		t.Errorf("got %q, want no comparison", tr.Resolver.Match)
	}
}

// TestCompareAcrossAnAlias covers the answer arriving under a different name
// than it was asked about. The walk ends on the target of the alias, and the
// resolver returns the whole chain; comparing by type rather than by owner is
// what makes the two comparable at all.
func TestCompareAcrossAnAlias(t *testing.T) {
	tr := traceOf("NOERROR", []string{"192.0.2.10"}, &trace.Resolver{
		Rcode: "NOERROR",
		Records: []trace.RR{
			{Name: "www.test.", Type: "CNAME", Data: "real.test."},
			{Name: "real.test.", Type: "A", Data: "192.0.2.10"},
		},
	})

	recursive.Compare(tr)
	if tr.Resolver.Match != trace.MatchSame {
		t.Errorf("got %q, want the alias chain to agree", tr.Resolver.Match)
	}
}
