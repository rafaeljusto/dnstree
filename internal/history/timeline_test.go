package history_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/history"
)

// signed is a walk of www.test. made at an offset into the history, with
// test.'s keys and its parent's DS as given.
func signed(at time.Duration, keys, ds []uint16, keysTTL, dsTTL uint32) *history.Walk {
	records := func(tags []uint16) []history.Record {
		var out []history.Record
		for _, tag := range tags {
			out = append(out, history.Record{Tag: tag, Algorithm: "ECDSAP256SHA256", Since: seen.Add(at)})
		}
		return out
	}
	return remembered(func(w *history.Walk) {
		w.Seen = seen.Add(at)
		w.Zones[1].Keys, w.Zones[1].DS = records(keys), records(ds)
		w.Zones[1].KeysTTL, w.Zones[1].DSTTL = keysTTL, dsTTL
	})
}

func TestTimeline(t *testing.T) {
	const day, hour = 86400, 3600
	tests := map[string]struct {
		walks []*history.Walk
		want  []string
		not   []string
		worst explain.Level
	}{
		"three walks that agree say how many there were and nothing else": {
			walks: []*history.Walk{remembered(nil), at(5*time.Minute, nil), at(10*time.Minute, nil)},
			want:  []string{"3 walks of www.test. A in hist from 2026-09-21 09:00:00 UTC to 2026-09-21 09:10:00 UTC, 0 changes"},
			not:   []string{"between"},
		},
		"a change is placed between the two walks that saw it, never at a moment": {
			walks: []*history.Walk{
				remembered(nil),
				at(5*time.Minute, func(w *history.Walk) { w.Answer = []string{"192.0.2.2"} }),
			},
			want: []string{
				"1 change",
				"between 2026-09-21 09:00:00 and 09:05:00 UTC, the answer changed: 192.0.2.1 became 192.0.2.2",
			},
		},
		"a silence much longer than the usual interval is said": {
			walks: []*history.Walk{
				remembered(nil), at(5*time.Minute, nil), at(10*time.Minute, nil), at(70*time.Minute, nil),
			},
			want: []string{"nothing was saved between 2026-09-21 09:10:00 and 10:10:00 UTC, 1 hour where the walks are usually 5 minutes apart"},
		},
		"a key removed while caches may still hold the DS that named only it": {
			walks: []*history.Walk{
				signed(0, []uint16{1, 2}, []uint16{1}, hour, day),
				signed(5*time.Minute, []uint16{1, 2}, []uint16{2}, hour, day),
				signed(2*time.Hour, []uint16{2}, []uint16{2}, hour, day),
			},
			want: []string{
				"the parent withdrew the DS for key 1 (ECDSAP256SHA256) of test.",
				"key 1 (ECDSAP256SHA256) was removed from test.",
				"the keys became 2 of test., at most 2 hours after the DS set changed between 2026-09-21 09:00:00 and 09:05:00 UTC, but that DS set had a TTL of 1 day",
				"a resolver that still held the old DS set could not validate test. for up to 1 day (RFC 7583)",
			},
			worst: explain.Warn,
		},
		"a key removed once the old DS has run out of every cache is fine": {
			walks: []*history.Walk{
				signed(0, []uint16{1, 2}, []uint16{1}, hour, day),
				signed(5*time.Minute, []uint16{1, 2}, []uint16{2}, hour, day),
				signed(25*time.Hour, []uint16{2}, []uint16{2}, hour, day),
			},
			want: []string{"key 1 (ECDSAP256SHA256) was removed from test."},
			not:  []string{"RFC 7583"},
		},
		"a key removed under a DS set that still names a key left is fine": {
			walks: []*history.Walk{
				signed(0, []uint16{1, 2}, []uint16{1, 2}, hour, day),
				signed(5*time.Minute, []uint16{1, 2}, []uint16{2}, hour, day),
				signed(10*time.Minute, []uint16{2}, []uint16{2}, hour, day),
			},
			not: []string{"RFC 7583"},
		},
		"a DS moved to a key published moments before strands the old key set": {
			walks: []*history.Walk{
				signed(0, []uint16{1}, []uint16{1}, hour, day),
				signed(5*time.Minute, []uint16{1, 2}, []uint16{1}, hour, day),
				signed(10*time.Minute, []uint16{1, 2}, []uint16{2}, hour, day),
			},
			want: []string{
				"the DS set moved to 2 of test., at most 10 minutes after the key set changed",
				"that key set had a TTL of 1 hour",
				"a resolver that still held the old key set could not validate test. for up to 1 hour (RFC 7583)",
			},
			worst: explain.Warn,
		},
		"a DS moved once the old key set has run out of every cache is fine": {
			walks: []*history.Walk{
				signed(0, []uint16{1}, []uint16{1}, hour, day),
				signed(5*time.Minute, []uint16{1, 2}, []uint16{1}, hour, day),
				signed(2*time.Hour, []uint16{1, 2}, []uint16{2}, hour, day),
			},
			not: []string{"RFC 7583"},
		},
		"a TTL the walks did not keep turns the timing off rather than reading as zero": {
			walks: []*history.Walk{
				signed(0, []uint16{1, 2}, []uint16{1}, 0, 0),
				signed(5*time.Minute, []uint16{1, 2}, []uint16{2}, 0, 0),
				signed(10*time.Minute, []uint16{2}, []uint16{2}, 0, 0),
			},
			not: []string{"RFC 7583"},
		},
		"a zone the chain did not reach securely is no evidence its keys changed": {
			walks: []*history.Walk{
				signed(0, []uint16{1}, []uint16{1}, hour, day),
				at(5*time.Minute, func(w *history.Walk) { w.Zones[1].DNSSEC = "bogus" }),
			},
			want:  []string{"the chain of trust over test. read secure then and reads bogus now"},
			not:   []string{"was removed", "withdrew"},
			worst: explain.Fault,
		},
		"walks given out of order are read in the order they were made": {
			walks: []*history.Walk{
				at(5*time.Minute, func(w *history.Walk) { w.Answer = []string{"192.0.2.2"} }),
				remembered(nil),
			},
			want: []string{"the answer changed: 192.0.2.1 became 192.0.2.2"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			text, worst := said(history.Timeline(tt.walks, "hist"))
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Errorf("missing %q in:\n%s", want, text)
				}
			}
			for _, not := range tt.not {
				if strings.Contains(text, not) {
					t.Errorf("unexpected %q in:\n%s", not, text)
				}
			}
			if worst != tt.worst {
				t.Errorf("worst level %v, want %v:\n%s", worst, tt.worst, text)
			}
		})
	}
}

func TestTimelineReadsOutAtMostSoManyChanges(t *testing.T) {
	walks := []*history.Walk{remembered(nil)}
	for i := 1; i <= 60; i++ {
		walks = append(walks, at(time.Duration(i)*time.Minute, func(w *history.Walk) {
			w.Answer = []string{"192.0.2." + string(rune('0'+i%2))}
		}))
	}
	text, _ := said(history.Timeline(walks, "hist"))
	if !strings.Contains(text, "lines more not read out") {
		t.Errorf("a long history was read out whole:\n%s", text)
	}
	if lines := strings.Count(text, "\n") + 1; lines > 45 {
		t.Errorf("%d lines, want the changes cut at 40", lines)
	}
}

// at is the walk remembered made an offset later.
func at(offset time.Duration, change func(*history.Walk)) *history.Walk {
	walk := remembered(change)
	walk.Seen = seen.Add(offset)
	return walk
}
