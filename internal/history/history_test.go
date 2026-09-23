package history_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/history"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

var seen = time.Date(2026, time.September, 21, 9, 0, 0, 0, time.UTC)

func question() trace.Question {
	return trace.Question{Name: "www.test.", Type: "A", Class: "IN"}
}

// resolution is a walk of two zone cuts that answered at the second, with a
// verdict on each cut and an aside on the way down.
func resolution() *trace.Trace {
	return &trace.Trace{
		Question: question(),
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, DNSSEC: &trace.DNSSECStatus{
			State: trace.Secure, Zone: ".",
		}, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindReferral,
			Delegation: &trace.Delegation{Zone: "test.", NS: []string{"b.ns.test.", "a.ns.test."}},
			// A cut is judged from above, so the verdict on a referral is the
			// verdict of the zone it points at.
			DNSSEC: &trace.DNSSECStatus{State: trace.Insecure, Zone: "test."},
			Children: []*trace.Step{
				{Zone: "test.", Kind: trace.KindAnswer, Aside: true,
					Delegation: &trace.Delegation{Zone: "aside.test.", NS: []string{"c.ns.test."}}},
				{Zone: "test.", Kind: trace.KindAnswer, Records: []trace.RR{
					{Name: "www.test.", TTL: 300, Type: "A", Data: "192.0.2.2"},
					{Name: "www.test.", TTL: 60, Type: "A", Data: "192.0.2.1"},
					{Name: "www.test.", TTL: 900, Type: "AAAA", Data: "2001:db8::1"},
				}},
			},
		}}},
	}
}

func TestOf(t *testing.T) {
	got := history.Of(resolution(), seen)

	want := &history.Walk{
		Version:  history.Version,
		Question: history.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Seen:     seen,
		Kind:     "answer",
		// Sorted and deduplicated, because a nameserver is free to rotate an
		// RRset between one walk and the next.
		Answer: []string{"192.0.2.1", "192.0.2.2"},
		// The shortest of the records that answered, and nothing from a record
		// of another type.
		TTL: 60,
		Zones: []history.Zone{
			{Name: ".", DNSSEC: "secure"},
			{Name: "test.", NS: []string{"a.ns.test.", "b.ns.test."}, DNSSEC: "insecure"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// TestOfNothing covers a walk with nothing to remember of its answer. The zones
// it crossed are still worth keeping: that is what says the delegation changed
// while the name was down.
func TestOfNothing(t *testing.T) {
	tr := &trace.Trace{Question: question(), Root: &trace.Step{
		Zone: ".", Kind: trace.KindZone,
		Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindReferral,
			Delegation: &trace.Delegation{Zone: "test.", NS: []string{"a.ns.test."}},
			Children:   []*trace.Step{{Zone: "test.", Kind: trace.KindTimeout}},
		}},
	}}

	got := history.Of(tr, seen)
	if got.Kind != "" || len(got.Answer) != 0 {
		t.Errorf("got kind %q and answer %v, want neither", got.Kind, got.Answer)
	}
	if len(got.Zones) != 2 {
		t.Errorf("got %v, want the root and test. kept", got.Zones)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "made", "on", "demand")
	want := history.Of(resolution(), seen)

	if err := history.Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got := history.Load(dir, question())
	if got == nil {
		t.Fatal("got nothing back, want the walk that was saved")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// TestSaveReplacesALink covers a link planted where the walk is kept, in a
// cache directory somebody else can write to. The walk replaces the link and
// the file it pointed at is left alone: nothing reaches the disk outside the
// cache. No half-written file is left behind either.
func TestSaveReplacesALink(t *testing.T) {
	dir, outside := t.TempDir(), filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	walk := history.Of(resolution(), seen)
	if err := history.Save(dir, walk); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	var kept string
	for _, entry := range entries {
		if entry.Name() != "probe" {
			kept = filepath.Join(dir, entry.Name())
		}
	}
	if err := os.Remove(kept); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, kept); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}

	if err := history.Save(dir, walk); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if data, _ := os.ReadFile(outside); string(data) != "untouched" {
		t.Errorf("got %q in the file the link pointed at, want it untouched", data)
	}
	if info, err := os.Lstat(kept); err != nil || !info.Mode().IsRegular() {
		t.Errorf("got %v, %v, want the link replaced by the walk", info, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("got %d entries, want the walk and nothing half-written", len(entries))
	}
}

// TestLoadIgnores covers every way a cache can be no use. None of them is an
// error: a walk with nothing to compare against is a walk that says so.
func TestLoadIgnores(t *testing.T) {
	tests := map[string]func(testing.TB, string){
		"a directory with nothing in it": func(testing.TB, string) {},

		"a file that is not JSON": func(tb testing.TB, dir string) {
			write(tb, dir, question(), "not json at all")
		},
		"a file from another version": func(tb testing.TB, dir string) {
			walk := history.Of(resolution(), seen)
			walk.Version = history.Version + 1
			if err := history.Save(dir, walk); err != nil {
				tb.Fatal(err)
			}
		},
		// Two questions can come down to the same file name, so the question is
		// written inside and read back before the file is believed.
		"a file holding another question": func(tb testing.TB, dir string) {
			walk := history.Of(resolution(), seen)
			walk.Question.Name = "elsewhere.test."
			write(tb, dir, question(), marshal(tb, walk))
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, dir)

			if got := history.Load(dir, question()); got != nil {
				t.Errorf("got %+v, want nothing to compare against", got)
			}
		})
	}
}

// TestLoadReadsBackWhatTheQuestionAsks covers the case the file name cannot
// tell apart on its own: a name whose characters a file name will not carry.
func TestLoadReadsBackWhatTheQuestionAsks(t *testing.T) {
	dir := t.TempDir()

	first := trace.Question{Name: "a/b.test.", Type: "A", Class: "IN"}
	second := trace.Question{Name: `a\b.test.`, Type: "A", Class: "IN"}

	walk := history.Of(&trace.Trace{Question: first}, seen)
	if err := history.Save(dir, walk); err != nil {
		t.Fatal(err)
	}

	if got := history.Load(dir, first); got == nil {
		t.Error("got nothing for the question that was saved, want it back")
	}
	if got := history.Load(dir, second); got != nil {
		t.Errorf("got %+v for another question, want nothing", got.Question)
	}
}

func TestDir(t *testing.T) {
	t.Run("the environment names it outright", func(t *testing.T) {
		t.Setenv(history.DirEnv, "/somewhere/of/its/own")

		if got, err := history.Dir(); err != nil || got != "/somewhere/of/its/own" {
			t.Errorf("got %q and %v, want the directory the environment named", got, err)
		}
	})

	t.Run("the XDG location comes next", func(t *testing.T) {
		t.Setenv(history.DirEnv, "")
		t.Setenv("XDG_CACHE_HOME", "/tmp/cache")

		if got, err := history.Dir(); err != nil || got != filepath.Join("/tmp/cache", "dnstree") {
			t.Errorf("got %q and %v, want it under the XDG cache", got, err)
		}
	})
}

func write(tb testing.TB, dir string, question trace.Question, data string) {
	tb.Helper()

	// Saving first is what puts the file where Load will look for it, whatever
	// the question comes down to as a name.
	if err := history.Save(dir, history.Of(&trace.Trace{Question: question}, seen)); err != nil {
		tb.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		tb.Fatalf("got %v and %v, want the one file Save wrote", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte(data), 0o600); err != nil {
		tb.Fatal(err)
	}
}

func marshal(tb testing.TB, walk *history.Walk) string {
	tb.Helper()

	dir := tb.TempDir()
	if err := history.Save(dir, walk); err != nil {
		tb.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		tb.Fatalf("got %v and %v, want one file", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		tb.Fatal(err)
	}
	return string(data)
}
