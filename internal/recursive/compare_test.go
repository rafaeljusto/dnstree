package recursive_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/recursive"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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
		Resolvers: resolvers(answer),
	}
}

// answerOf is what the resolver said, in the same shape.
// resolvers is the one answer as a list, and no list at all where there is no
// answer to put in one.
func resolvers(answer *trace.Resolver) []*trace.Resolver {
	if answer == nil {
		return nil
	}
	return []*trace.Resolver{answer}
}

// compacted is a walk that ended on a compact denial (RFC 9824): an NXDOMAIN
// the server answered as NOERROR.
func compacted(answer *trace.Resolver) *trace.Trace {
	tr := traceOf("NOERROR", nil, answer)
	result := tr.Root.Children[0]
	result.Kind, result.Compact = trace.KindNXDomain, true
	return tr
}

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
		// RFC 9824 lets the same denial travel as NOERROR or NXDOMAIN.
		name:  "a compact denial handed on as NXDOMAIN",
		tr:    compacted(answerOf("NXDOMAIN")),
		match: "",
	}, {
		name:  "a compact denial handed on as it came",
		tr:    compacted(answerOf("NOERROR")),
		match: "",
	}, {
		name:  "a compact denial against an address",
		tr:    compacted(answerOf("NOERROR", "192.0.2.10")),
		match: trace.MatchDiffers,
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
			if len(tt.tr.Resolvers) > 0 && tt.tr.Resolvers[0] != nil {
				got = tt.tr.Resolvers[0].Match
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
		Question:  trace.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Root:      &trace.Step{Zone: ".", Kind: trace.KindZone},
		Resolvers: []*trace.Resolver{answerOf("NOERROR", "192.0.2.10")},
	}

	recursive.Compare(tr)
	if tr.Resolvers[0].Match != "" {
		t.Errorf("got %q, want no comparison", tr.Resolvers[0].Match)
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
	if tr.Resolvers[0].Match != trace.MatchSame {
		t.Errorf("got %q, want the alias chain to agree", tr.Resolvers[0].Match)
	}
}

// TestCompareJudgesEachOnItsOwn covers the point of asking several: they are
// several places the question was put from, and one of them disagreeing with
// the walk says nothing at all about the others.
func TestCompareJudgesEachOnItsOwn(t *testing.T) {
	tr := traceOf("NOERROR", []string{"192.0.2.10"}, nil)
	tr.Resolvers = []*trace.Resolver{
		answerOf("NOERROR", "192.0.2.10"),
		answerOf("NOERROR", "10.4.2.9"),
		{Err: "i/o timeout"},
	}

	recursive.Compare(tr)

	for i, want := range []trace.Match{trace.MatchSame, trace.MatchDiffers, ""} {
		if got := tr.Resolvers[i].Match; got != want {
			t.Errorf("got %q for the %d resolver, want %q", got, i, want)
		}
	}
}

// withTTL is the same records, every one of them kept for ttl seconds.
func withTTL(records []trace.RR, ttl uint32) []trace.RR {
	for i := range records {
		records[i].TTL = ttl
	}
	return records
}

func TestCompareKept(t *testing.T) {
	// zoneOf is a walk whose answer the zone gives with a TTL of 300, and
	// asked is the resolver's answer with the TTL it handed out.
	zoneOf := func(asked *trace.Resolver, data ...string) *trace.Trace {
		tr := traceOf("NOERROR", data, asked)
		withTTL(tr.Root.Children[0].Records, 300)
		return tr
	}
	asked := func(ttl uint32, data ...string) *trace.Resolver {
		answer := answerOf("NOERROR", data...)
		withTTL(answer.Records, ttl)
		return answer
	}

	for _, tt := range []struct {
		name string
		tr   *trace.Trace
		kept trace.Kept
	}{{
		name: "the same answer with a TTL above the zone's",
		tr:   zoneOf(asked(3600, "192.0.2.10"), "192.0.2.10"),
		kept: trace.KeptLonger,
	}, {
		name: "the same answer fetched fresh",
		tr:   zoneOf(asked(300, "192.0.2.10"), "192.0.2.10"),
	}, {
		// Less than the zone gives is a copy partway through its life, which is
		// what a cache is for.
		name: "the same answer partway through its life",
		tr:   zoneOf(asked(120, "192.0.2.10"), "192.0.2.10"),
	}, {
		name: "an answer the zone does not give, with serve-stale's 30 seconds",
		tr:   zoneOf(asked(30, "198.51.100.1"), "192.0.2.10"),
		kept: trace.KeptStale,
	}, {
		name: "an answer the zone does not give, with a long TTL",
		tr:   zoneOf(asked(3600, "198.51.100.1"), "192.0.2.10"),
	}, {
		// The walk gets the zone's whole TTL, so a few seconds left is a copy
		// near its end, not a stale one, where the zone itself gives only 30.
		name: "an answer the zone does not give, on a zone that keeps it 30 seconds",
		tr: func() *trace.Trace {
			tr := traceOf("NOERROR", []string{"192.0.2.10"}, asked(20, "198.51.100.1"))
			withTTL(tr.Root.Children[0].Records, 30)
			return tr
		}(),
	}, {
		// With --all each server is a place to have been answered from: a CDN
		// answering by place gives some resolver what one of them gave the walk.
		name: "an answer another server of the zone gave the walk",
		tr: func() *trace.Trace {
			tr := zoneOf(asked(30, "198.51.100.1"), "192.0.2.10")
			tr.Root.Children = append(tr.Root.Children, &trace.Step{
				Zone: "test.", Kind: trace.KindAnswer, Rcode: "NOERROR",
				Records: withTTL([]trace.RR{{Name: "www.test.", Type: "A", Data: "198.51.100.1"}}, 300),
			})
			return tr
		}(),
		kept: "",
	}, {
		// A nameserver's address looked up on the way answered another
		// question, and giving the same address says nothing about this one.
		name: "an answer only an aside gave",
		tr: func() *trace.Trace {
			tr := zoneOf(asked(30, "198.51.100.1"), "192.0.2.10")
			tr.Root.Children = append(tr.Root.Children, &trace.Step{
				Zone: "test.", Kind: trace.KindAnswer, Rcode: "NOERROR", Aside: true,
				Records: withTTL([]trace.RR{{Name: "ns1.test.", Type: "A", Data: "198.51.100.1"}}, 300),
			})
			return tr
		}(),
		kept: trace.KeptStale,
	}, {
		// Two servers of the zone partway through a change of TTL: holding
		// what the slower one gave is holding no longer than it allowed.
		name: "the TTL another server of the zone gave the walk",
		tr: func() *trace.Trace {
			tr := zoneOf(asked(3000, "192.0.2.10"), "192.0.2.10")
			tr.Root.Children = append([]*trace.Step{{
				Zone: "test.", Kind: trace.KindAnswer, Rcode: "NOERROR",
				Records: withTTL([]trace.RR{{Name: "www.test.", Type: "A", Data: "192.0.2.10"}}, 3600),
			}}, tr.Root.Children...)
			return tr
		}(),
	}, {
		name: "the name gone for the resolver",
		tr:   zoneOf(answerOf("NXDOMAIN"), "192.0.2.10"),
	}} {
		t.Run(tt.name, func(t *testing.T) {
			recursive.Compare(tt.tr)
			if got := tt.tr.Resolvers[0].Kept; got != tt.kept {
				t.Errorf("got %q, want %q", got, tt.kept)
			}
		})
	}
}
