package history_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/history"
)

// remembered is a walk that answered, as the walk before this one left it. Each
// test changes the one thing it is about.
func remembered(change func(*history.Walk)) *history.Walk {
	walk := &history.Walk{
		Version:  history.Version,
		Question: history.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Seen:     seen,
		Kind:     "answer",
		Answer:   []string{"192.0.2.1"},
		TTL:      3600,
		Zones: []history.Zone{
			{Name: ".", DNSSEC: "secure"},
			{Name: "test.", NS: []string{"a.ns.test.", "b.ns.test."}, DNSSEC: "secure"},
		},
	}
	if change != nil {
		change(walk)
	}
	return walk
}

// later is the same walk made a day on, which is what the comparison is always
// between: two walks of one question at two times.
func later(change func(*history.Walk)) *history.Walk {
	walk := remembered(change)
	walk.Seen = seen.Add(24 * time.Hour)
	return walk
}

// said is every change as one block of text, and the level of the loudest of
// them, which together are all a reader gets.
func said(findings []explain.Finding) (string, explain.Level) {
	var (
		lines []string
		worst explain.Level
	)
	for _, finding := range findings {
		if finding.Topic != explain.Change {
			panic("a change that is not about change")
		}
		lines = append(lines, finding.Text)
		worst = max(worst, finding.Level)
	}
	return strings.Join(lines, "\n"), worst
}

func TestChanges(t *testing.T) {
	tests := map[string]struct {
		before, now *history.Walk
		want        []string
		avoid       []string
		level       explain.Level
	}{
		"nothing remembered is not nothing changed": {
			before: nil,
			now:    later(nil),
			want:   []string{"nothing to compare", "first walk of www.test. A that was remembered"},
			avoid:  []string{"nothing has changed"},
		},
		"a walk that came out the same says so, rather than nothing": {
			before: remembered(nil),
			now:    later(nil),
			want:   []string{"nothing has changed since the walk of www.test. A 1 day ago"},
		},
		"an answer that changed is the first thing said": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Answer = []string{"198.51.100.1"} }),
			want: []string{
				"the walk of www.test. A before this one was 1 day ago",
				"the answer changed: 192.0.2.1 became 198.51.100.1",
			},
		},
		"a name that stopped answering at all": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Kind, w.Answer, w.TTL = "", nil, 0 }),
			want:   []string{"www.test. answered then and nothing answers now"},
			level:  explain.Warn,
		},
		"a name that started answering again": {
			before: remembered(func(w *history.Walk) { w.Kind, w.Answer, w.TTL = "", nil, 0 }),
			now:    later(nil),
			want:   []string{"nothing answered for www.test. then and something does now"},
			level:  explain.Note,
		},
		"a name that stopped existing": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Kind, w.Answer, w.TTL = "nxdomain", nil, 0 }),
			want:   []string{"had an answer then and does not exist now"},
			level:  explain.Warn,
		},
		"a type that went away under a name that did not": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Kind, w.Answer, w.TTL = "nodata", nil, 0 }),
			want:   []string{"had A records then and has none now"},
			level:  explain.Warn,
		},
		"a TTL cut short before a move is worth a line of its own": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.TTL = 60 }),
			want:   []string{"the answer is unchanged, and its TTL went from 3600 to 60"},
			level:  explain.Note,
		},
		"a nameserver that came in": {
			before: remembered(nil),
			now: later(func(w *history.Walk) {
				w.Zones[1].NS = []string{"a.ns.test.", "b.ns.test.", "c.ns.test."}
			}),
			want:  []string{"c.ns.test. was added to the nameservers of test."},
			avoid: []string{"went", "changed:"},
		},
		"a nameserver that went": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Zones[1].NS = []string{"a.ns.test."} }),
			want:   []string{"b.ns.test. was dropped from the nameservers of test."},
		},
		"a set of nameservers that was replaced": {
			before: remembered(nil),
			now: later(func(w *history.Walk) {
				w.Zones[1].NS = []string{"c.ns.test.", "d.ns.test."}
			}),
			want: []string{
				"the nameservers of test. changed:",
				"c.ns.test. and d.ns.test. came in",
				"a.ns.test. and b.ns.test. went",
			},
		},
		"the same nameservers spelled differently are the same nameservers": {
			before: remembered(nil),
			now: later(func(w *history.Walk) {
				w.Zones[1].NS = []string{"A.NS.TEST.", "B.ns.Test."}
			}),
			want: []string{"nothing has changed"},
		},
		"a zone cut that was not there before": {
			before: remembered(nil),
			now: later(func(w *history.Walk) {
				w.Zones = append(w.Zones, history.Zone{
					Name: "sub.test.", NS: []string{"c.ns.test."}, DNSSEC: "secure",
				})
			}),
			want: []string{"there is a zone cut at sub.test. now, and there was none then"},
		},
		"a zone cut that is gone": {
			before: remembered(func(w *history.Walk) {
				w.Zones = append(w.Zones, history.Zone{Name: "sub.test.", NS: []string{"c.ns.test."}})
			}),
			now:  later(nil),
			want: []string{"the zone cut at sub.test. is gone"},
		},
		"a chain of trust that broke is a fault": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Zones[1].DNSSEC = "bogus" }),
			want:   []string{"the chain of trust over test. read secure then and reads bogus now"},
			level:  explain.Fault,
		},
		"a zone that stopped being signed is a warning": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Zones[1].DNSSEC = "insecure" }),
			want:   []string{"read secure then and reads insecure now"},
			level:  explain.Warn,
		},
		"a zone that started being signed is good news": {
			before: remembered(func(w *history.Walk) { w.Zones[1].DNSSEC = "insecure" }),
			now:    later(nil),
			want:   []string{"read insecure then and reads secure now"},
			level:  explain.Note,
		},
		// A run without --dnssec follows no chain and remembers no state, which
		// is not a zone that stopped being signed.
		"a chain nobody followed this time is not a chain that changed": {
			before: remembered(nil),
			now:    later(func(w *history.Walk) { w.Zones[0].DNSSEC, w.Zones[1].DNSSEC = "", "" }),
			want:   []string{"nothing has changed"},
			avoid:  []string{"chain of trust"},
		},
		"a chain nobody followed last time is not one that changed either": {
			before: remembered(func(w *history.Walk) { w.Zones[0].DNSSEC, w.Zones[1].DNSSEC = "", "" }),
			now:    later(nil),
			want:   []string{"nothing has changed"},
			avoid:  []string{"chain of trust"},
		},
		"more than one thing can change at once": {
			before: remembered(nil),
			now: later(func(w *history.Walk) {
				w.Answer = []string{"198.51.100.1"}
				w.Zones[1].NS = []string{"a.ns.test."}
				w.Zones[1].DNSSEC = "bogus"
			}),
			want: []string{
				"the answer changed",
				"was dropped from the nameservers of test.",
				"reads bogus now",
			},
			level: explain.Fault,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, level := said(history.Changes(test.before, test.now))
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
			if test.level != 0 && level != test.level {
				t.Errorf("got level %d, want %d:\n%s", level, test.level, got)
			}
		})
	}
}

// TestChangesAge covers the one number every comparison carries.
func TestChangesAge(t *testing.T) {
	tests := map[string]struct {
		since time.Duration
		want  string
	}{
		"a walk just made":            {30 * time.Second, "moments ago"},
		"one minute":                  {time.Minute, "1 minute ago"},
		"minutes":                     {40 * time.Minute, "40 minutes ago"},
		"one hour":                    {time.Hour, "1 hour ago"},
		"hours":                       {5 * time.Hour, "5 hours ago"},
		"one day":                     {25 * time.Hour, "1 day ago"},
		"days":                        {90 * time.Hour, "3 days ago"},
		"a memory from a later clock": {-time.Hour, "remembered from later than this one"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			before := remembered(nil)
			now := remembered(nil)
			now.Seen = before.Seen.Add(test.since)

			got, _ := said(history.Changes(before, now))
			if !strings.Contains(got, test.want) {
				t.Errorf("got %q, want it to say %q", got, test.want)
			}
		})
	}
}
