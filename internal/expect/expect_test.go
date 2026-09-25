package expect_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/expect"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// walk is a trace of one question that came to the step given.
func walk(qtype string, result *trace.Step) *trace.Trace {
	return &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: qtype, Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{result}},
	}
}

// answered is a hop that answered with those records.
func answered(qtype string, data ...string) *trace.Step {
	step := hop(trace.KindAnswer)
	for _, rdata := range data {
		step.Records = append(step.Records,
			trace.RR{Name: "www.test.", TTL: 300, Type: qtype, Data: rdata})
	}
	return step
}

func hop(kind trace.StepKind) *trace.Step {
	return &trace.Step{
		Zone:   "test.",
		Kind:   kind,
		Server: trace.Server{Name: "ns.test.", IP: netip.MustParseAddr("192.0.2.5"), Port: 53},
	}
}

// signed is a hop the chain of trust reached this state at.
func signed(step *trace.Step, state trace.DNSSECState) *trace.Step {
	step.DNSSEC = &trace.DNSSECStatus{State: state, Zone: "test."}
	return step
}

// parse reads the values the way the command line would.
func parse(tb testing.TB, values ...string) []expect.Expectation {
	tb.Helper()

	want := make([]expect.Expectation, 0, len(values))
	for _, value := range values {
		expectation, err := expect.Parse(value)
		if err != nil {
			tb.Fatalf("Parse(%q): %v", value, err)
		}
		want = append(want, expectation)
	}
	return want
}

func TestUnmet(t *testing.T) {
	tests := map[string]struct {
		expect []string
		trace  *trace.Trace
		want   []string
	}{
		"rdata among the answers is met": {
			expect: []string{"192.0.2.1"},
			trace:  walk("A", answered("A", "192.0.2.1", "192.0.2.2")),
		},
		"rdata that is not among them is not, and the answer is read back": {
			expect: []string{"192.0.2.9"},
			trace:  walk("A", answered("A", "192.0.2.1", "192.0.2.2")),
			want:   []string{"expected 192.0.2.9, got 192.0.2.1 and 192.0.2.2"},
		},
		"an address is held against an address rather than against the text of one": {
			expect: []string{"2001:0db8:0:0:0:0:0:1"},
			trace:  walk("AAAA", answered("AAAA", "2001:db8::1")),
		},
		"a name the server wrote is read back escaped": {
			expect: []string{"ns.test."},
			trace:  walk("NS", answered("NS", "ns\x1b[2K.test.")),
			want:   []string{`expected ns.test., got ns\027[2K.test.`},
		},
		"a name is compared the way DNS compares names": {
			expect: []string{"10 mail.TEST."},
			trace:  walk("MX", answered("MX", "10 MAIL.test.")),
		},
		"every expectation has to hold": {
			expect: []string{"192.0.2.1", "192.0.2.9"},
			trace:  walk("A", answered("A", "192.0.2.1")),
			want:   []string{"expected 192.0.2.9, got 192.0.2.1"},
		},
		"a long answer is counted rather than read out whole": {
			expect: []string{"192.0.2.9"},
			trace:  walk("A", answered("A", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")),
			want:   []string{"expected 192.0.2.9, got 192.0.2.1, 192.0.2.2, 192.0.2.3 and 1 more"},
		},

		// The words are what is nearly always meant, so they win; the escape is
		// there for the zone that serves a record reading like one of them.
		"a word wins over rdata that reads like it": {
			expect: []string{"secure"},
			trace:  walk("TXT", answered("TXT", "secure")),
			want:   []string{"expected secure, got a walk that followed no chain of trust"},
		},
		"a leading = asks for the rdata and nothing else": {
			expect: []string{"=secure"},
			trace:  walk("TXT", answered("TXT", "secure")),
		},

		"the chain of trust is read where one was followed": {
			expect: []string{"secure"},
			trace:  walk("A", signed(answered("A", "192.0.2.1"), trace.Secure)),
		},
		"a chain that came to something else is said plainly": {
			expect: []string{"secure"},
			trace:  walk("A", signed(answered("A", "192.0.2.1"), trace.Bogus)),
			want:   []string{"expected secure, got bogus"},
		},
		// Reading an unchecked chain as secure would turn a run that forgot
		// --dnssec into a run that checked something.
		"a walk that followed no chain has met no expectation about one": {
			expect: []string{"secure"},
			trace:  walk("A", answered("A", "192.0.2.1")),
			want:   []string{"expected secure, got a walk that followed no chain of trust"},
		},

		"what the walk came to is a word too": {
			expect: []string{"nxdomain"},
			trace:  walk("A", hop(trace.KindNXDomain)),
		},
		"a walk that came to something else says which": {
			expect: []string{"nxdomain"},
			trace:  walk("A", answered("A", "192.0.2.1")),
			want:   []string{"expected nxdomain, got answer"},
		},
		"a walk that came to nothing meets nothing": {
			expect: []string{"192.0.2.1", "answer"},
			trace:  walk("A", hop(trace.KindTimeout)),
			want:   []string{"expected 192.0.2.1, got nothing", "expected answer, got nothing"},
		},
		"an answer of another type is not an answer of this one": {
			expect: []string{"192.0.2.1"},
			trace:  walk("A", answered("AAAA", "2001:db8::1")),
			want:   []string{"expected 192.0.2.1, got no A record"},
		},

		"a walk nothing was asked of meets everything": {
			trace: walk("A", hop(trace.KindTimeout)),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := expect.Unmet(test.trace, parse(t, test.expect...))
			if !slices.Equal(got, test.want) {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestParseRejects covers the values that say nothing. They are reported
// against the flag that carried them rather than after a walk has been made.
func TestParseRejects(t *testing.T) {
	for _, value := range []string{"", "="} {
		if _, err := expect.Parse(value); err == nil {
			t.Errorf("Parse(%q): got no error, want one", value)
		}
	}
}

// TestUnmetOfNothing covers the walk that could not be made at all, which is
// somebody else's verdict to give.
func TestUnmetOfNothing(t *testing.T) {
	if got := expect.Unmet(nil, parse(t, "192.0.2.1")); got != nil {
		t.Errorf("got %q, want nothing", got)
	}
}

// TestFresh holds the lifetime of a chain of trust against what was asked of
// it. The walk is made at noon, and the signatures under the answer run out a
// fixed time after that.
func TestFresh(t *testing.T) {
	noon := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	// Signed for a month, the way an offline signer signs.
	lasting := func(state trace.DNSSECState, left time.Duration) *trace.Trace {
		step := signed(answered("A", "192.0.2.1"), state)
		if left > 0 {
			expiration := noon.Add(left)
			step.DNSSEC.Signatures = []trace.Lifetime{{Inception: expiration.Add(-30 * 24 * time.Hour), Expiration: expiration}}
		}
		tr := walk("A", step)
		tr.Started = noon
		return tr
	}

	tests := map[string]struct {
		tr    *trace.Trace
		want  string
		unmet string
	}{
		"a fortnight left of a month is fresh": {
			tr: lasting(trace.Secure, 14*24*time.Hour), want: "fresh",
		},
		"two days left of a month is late in its life": {
			tr: lasting(trace.Secure, 50*time.Hour), want: "fresh",
			unmet: "expected fresh, got a signature over test. late in its life, running out in 2 days 2 hours",
		},
		"a fortnight left is not three weeks": {
			tr: lasting(trace.Secure, 14*24*time.Hour), want: "fresh:21d",
			unmet: "expected fresh:21d, got signatures over test. that run out in 14 days",
		},
		"two days left is more than a day": {
			tr: lasting(trace.Secure, 50*time.Hour), want: "fresh:1d",
		},
		"a length of time in hours": {
			tr: lasting(trace.Secure, 50*time.Hour), want: "fresh:72h",
			unmet: "expected fresh:72h, got signatures over test. that run out in 2 days 2 hours",
		},
		"an unsigned zone has nothing fresh about it": {
			tr: lasting(trace.Insecure, 0), want: "fresh",
			unmet: "expected fresh, got insecure",
		},
		"a walk that checked nothing": {
			tr: walk("A", answered("A", "192.0.2.1")), want: "fresh",
			unmet: "expected fresh, got a walk that followed no chain of trust",
		},
		"a trace that does not say when it was made": {
			tr: func() *trace.Trace {
				tr := lasting(trace.Secure, 14*24*time.Hour)
				tr.Started = time.Time{}
				return tr
			}(),
			want:  "fresh",
			unmet: "expected fresh, got signatures whose lifetime the trace does not record",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			unmet := expect.Unmet(test.tr, parse(t, test.want))
			switch {
			case test.unmet == "" && len(unmet) > 0:
				t.Errorf("got %q, want it met", unmet)
			case test.unmet != "" && (len(unmet) != 1 || unmet[0] != test.unmet):
				t.Errorf("got %q, want %q", unmet, test.unmet)
			}
		})
	}
}

func TestParseFresh(t *testing.T) {
	for name, value := range map[string]string{
		"no time at all":      "fresh:0d",
		"days that are not":   "fresh:xd",
		"a length that isn't": "fresh:soon",
		"a negative length":   "fresh:-1h",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := expect.Parse(value); err == nil {
				t.Errorf("Parse(%q) took it, want it refused", value)
			}
		})
	}
}
