package explain_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/explain"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// question is what every walk here set out to answer.
var question = trace.Question{Name: "www.test.", Type: "A", Class: "IN"}

// walk is a trace of that question, with the hops given hanging off the root in
// the order they were made.
func walk(steps ...*trace.Step) *trace.Trace {
	return &trace.Trace{
		Question: question,
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: steps},
	}
}

// hop is one query to a named server of test.
func hop(kind trace.StepKind, server string) *trace.Step {
	return &trace.Step{
		Zone:   "test.",
		Kind:   kind,
		Server: trace.Server{Name: server, IP: netip.MustParseAddr("192.0.2.5"), Port: 53},
	}
}

// said is every finding as one block of text, which is what a reader has in
// front of them.
func said(tr *trace.Trace) string {
	var lines []string
	for _, finding := range explain.Findings(tr) {
		lines = append(lines, finding.Text)
	}
	return strings.Join(lines, "\n")
}

func TestFindings(t *testing.T) {
	answer := func() *trace.Step {
		step := hop(trace.KindAnswer, "ns.test.")
		step.Records = []trace.RR{{Name: "www.test.", Type: "A", Data: "192.0.2.1"}}
		return step
	}

	tests := map[string]struct {
		trace *trace.Trace
		want  []string
		avoid []string
	}{
		"an answer names the records, the server and the zone it serves": {
			trace: walk(answer()),
			want:  []string{"www.test. A is 192.0.2.1", "ns.test.", "test."},
		},
		"a name that is not there names the zone that says so": {
			trace: walk(hop(trace.KindNXDomain, "ns.test.")),
			want:  []string{"www.test. does not exist", "test. is the zone that says so"},
		},
		"a type that is not there is not a name that is not there": {
			trace: walk(hop(trace.KindNoData, "ns.test.")),
			want:  []string{"exists but has no A record"},
			avoid: []string{"does not exist"},
		},
		"an alias the walk never got to the end of": {
			trace: walk(func() *trace.Step {
				step := hop(trace.KindCNAME, "ns.test.")
				step.Records = []trace.RR{{Name: "www.test.", Type: "CNAME", Data: "other.test."}}
				return step
			}()),
			want: []string{"is an alias for other.test.", "ended there without an answer"},
		},
		"an answer reached through aliases says how many": {
			trace: walk(func() *trace.Step {
				alias := hop(trace.KindCNAME, "ns.test.")
				alias.Records = []trace.RR{{Name: "www.test.", Type: "CNAME", Data: "other.test."}}
				alias.Children = []*trace.Step{answer()}
				return alias
			}()),
			want: []string{"www.test. A is 192.0.2.1", "after 1 alias"},
		},
		"an answer withheld is not a walk that found nothing": {
			trace: walk(func() *trace.Step {
				step := hop(trace.KindFiltered, "ns.test.")
				step.Rcode = "REFUSED"
				step.Extended = []trace.ExtendedError{{Code: 18, Reason: "Prohibited", Text: "not from here"}}
				return step
			}()),
			want: []string{"was withheld by ns.test.", "decided rather than served", "prohibited"},
			// The server's own words are its own, and --format ascii promises
			// the output stays under codepoint 127.
			avoid: []string{"nothing answered", "not from here"},
		},
		"a walk that ran into silence says where it stopped and who was silent": {
			trace: walk(hop(trace.KindTimeout, "ns.test.")),
			want:  []string{"nothing answered for www.test. A", "stopped at test.", "1 server did not answer in time: ns.test."},
		},
		"a lame server is named once, not twice": {
			trace: walk(hop(trace.KindLame, "ns.test.")),
			want:  []string{"stopped at test.", "answered without authority", "ns.test."},
			avoid: []string{"authority for it"},
		},
		"more servers than anyone wants read out are counted": {
			trace: walk(
				hop(trace.KindTimeout, "a.test."), hop(trace.KindTimeout, "b.test."),
				hop(trace.KindTimeout, "c.test."), hop(trace.KindTimeout, "d.test."),
				hop(trace.KindTimeout, "e.test."),
			),
			want: []string{"5 servers did not answer in time", "a.test., b.test., c.test. and 2 more"},
		},
		"a budget that ran out is the reason the walk stopped": {
			trace: walk(&trace.Step{Zone: "test.", Kind: trace.KindError, Err: "the query budget of 64 ran out"}),
			want:  []string{"stopped at test.", "the query budget of 64 ran out"},
		},
		"a chain of trust that holds says how far it got": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Secure, Algorithm: "ECDSAP256SHA256"}
				return step
			}()),
			want: []string{"the chain of trust holds from the root to test.", "ECDSAP256SHA256"},
		},
		"a broken chain says so, and what a validating resolver will do about it": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Bogus, Reason: "the answer carries no signature"}
				return step
			}()),
			want: []string{"the chain of trust breaks at test.", "the answer carries no signature", "SERVFAIL"},
		},
		"the zone named as broken is the one the verdict is about, not the one it is drawn on": {
			trace: walk(&trace.Step{
				Zone: "org.", Kind: trace.KindReferral,
				Server:     trace.Server{Name: "a0.org.afilias-nst.info."},
				Delegation: &trace.Delegation{Zone: "dnssec-failed.org."},
				DNSSEC: &trace.DNSSECStatus{
					State: trace.Bogus, Zone: "dnssec-failed.org.",
					Reason: "no DNSKEY of the zone matches the DS its parent published",
				},
			}),
			want:  []string{"the chain of trust breaks at dnssec-failed.org."},
			avoid: []string{"breaks at org."},
		},
		"a chain nothing here could check is unchecked, never broken": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Indeterminate, Reason: "algorithm 253 is not one this build knows"}
				return step
			}()),
			want:  []string{"could not be checked", "not the same as finding it broken"},
			avoid: []string{"breaks at", "SERVFAIL"},
		},
		"a zone nobody signed says that plainly": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Insecure, Reason: "proved that test. has no DS"}
				return step
			}()),
			want: []string{"test. is not signed", "proved that test. has no DS"},
		},
		"a walk that followed no chain says nothing about one": {
			trace: walk(answer()),
			avoid: []string{"chain of trust", "not signed"},
		},
		"a resolver that answered differently is worth a look": {
			trace: func() *trace.Trace {
				tr := walk(answer())
				tr.Resolver = &trace.Resolver{Match: trace.MatchDiffers}
				return tr
			}(),
			want: []string{"a recursive resolver answered this question differently"},
		},
		"a resolver that agreed is worth no room": {
			trace: func() *trace.Trace {
				tr := walk(answer())
				tr.Resolver = &trace.Resolver{Match: trace.MatchSame}
				return tr
			}(),
			avoid: []string{"recursive resolver"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := said(test.trace)
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("got\n%s\nwant it to carry %q", got, want)
				}
			}
			for _, avoid := range test.avoid {
				if strings.Contains(got, avoid) {
					t.Errorf("got\n%s\nwant nothing in it saying %q", got, avoid)
				}
			}
		})
	}
}

// TestFindingsLevels covers the only thing a renderer reads besides the text.
// A chain that could not be checked must not be painted as one that broke.
func TestFindingsLevels(t *testing.T) {
	tests := map[string]struct {
		status *trace.DNSSECStatus
		want   explain.Level
	}{
		"broken is a fault":      {&trace.DNSSECStatus{State: trace.Bogus}, explain.Fault},
		"unchecked is a warning": {&trace.DNSSECStatus{State: trace.Indeterminate}, explain.Warn},
		"unsigned is a note":     {&trace.DNSSECStatus{State: trace.Insecure}, explain.Note},
		"secure is a note":       {&trace.DNSSECStatus{State: trace.Secure}, explain.Note},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			step := hop(trace.KindAnswer, "ns.test.")
			step.DNSSEC = test.status

			var found bool
			for _, finding := range explain.Findings(walk(step)) {
				if finding.Topic != explain.Trust {
					continue
				}
				found = true
				if finding.Level != test.want {
					t.Errorf("got level %d, want %d: %s", finding.Level, test.want, finding.Text)
				}
			}
			if !found {
				t.Error("got no finding about the chain of trust, want one")
			}
		})
	}
}

// TestFindingsOrder covers the reading order: what came of the walk first, and
// the workings under it.
func TestFindingsOrder(t *testing.T) {
	step := hop(trace.KindAnswer, "ns.test.")
	step.DNSSEC = &trace.DNSSECStatus{State: trace.Secure}

	tr := walk(hop(trace.KindTimeout, "dead.test."), step)
	tr.Resolver = &trace.Resolver{Match: trace.MatchDiffers}

	var topics []explain.Topic
	for _, finding := range explain.Findings(tr) {
		topics = append(topics, finding.Topic)
	}

	want := []explain.Topic{explain.Outcome, explain.Trust, explain.Servers, explain.Resolver}
	if len(topics) != len(want) {
		t.Fatalf("got %v, want one finding of each of %v", topics, want)
	}
	for i, topic := range topics {
		if topic != want[i] {
			t.Errorf("got %v, want %v", topics, want)
			break
		}
	}
}

// TestFindingsNothing covers the traces there is nothing to say about, which a
// renderer must be able to ask about without checking first.
func TestFindingsNothing(t *testing.T) {
	for name, tr := range map[string]*trace.Trace{
		"no trace at all":            nil,
		"a trace with no walk in it": {Question: question},
	} {
		t.Run(name, func(t *testing.T) {
			if findings := explain.Findings(tr); len(findings) != 0 {
				t.Errorf("got %v, want nothing said", findings)
			}
		})
	}
}
