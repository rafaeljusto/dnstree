package markdown_test

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/render/markdown"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// resolution is the walk --format json writes as its golden, asked of three
// resolvers that each came to something different.
func resolution(tb testing.TB) *trace.Trace {
	tb.Helper()

	file, err := os.Open(filepath.Join("..", "jsonout", "testdata", "resolution.golden"))
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()
	tr, err := jsonout.Read(file)
	if err != nil {
		tb.Fatal(err)
	}

	tr.Resolvers = []*trace.Resolver{
		{
			Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53}, Elapsed: 23 * time.Millisecond,
			Rcode: "NOERROR", Match: trace.MatchSame,
		},
		{
			Server: trace.Server{IP: netip.MustParseAddr("198.51.100.53"), Port: 5353}, Elapsed: 9 * time.Millisecond,
			Rcode: "NOERROR", Match: trace.MatchDiffers,
			Records: []trace.RR{
				{Name: "www.example.com.", TTL: 60, Type: "A", Data: "198.51.100.1"},
				{Name: "www.example.com.", TTL: 60, Type: "A", Data: "198.51.100.2"},
				{Name: "www.example.com.", TTL: 60, Type: "A", Data: "198.51.100.3"},
				{Name: "www.example.com.", TTL: 60, Type: "A", Data: "198.51.100.4"},
			},
		},
		{Server: trace.Server{IP: netip.MustParseAddr("203.0.113.53"), Port: 53}, Err: "i/o timeout"},
	}
	return tr
}

func TestRender(t *testing.T) {
	tr := resolution(t)
	var got bytes.Buffer
	if err := markdown.Render(&got, tr, explain.Findings(tr)); err != nil {
		t.Fatalf("Render: %v", err)
	}
	compare(t, "resolution", got.String())
}

// TestRenderEscapes covers text the servers wrote: it may not open a link, a
// tag, a heading or a cell of its own, and a backtick may not close the fence
// or the span it sits in.
func TestRenderEscapes(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "a`b.example.", Type: "TXT"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindAnswer, Rcode: "NOERROR", Server: trace.Server{IP: netip.MustParseAddr("192.0.2.1")},
			Records: []trace.RR{{Name: "a`b.example.", Type: "TXT", Data: "\"```\""}},
		}}},
		Resolvers: []*trace.Resolver{{
			Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53")}, Rcode: "NOERROR", Match: trace.MatchDiffers,
			Records: []trace.RR{{Name: "a`b.example.", Type: "TXT", Data: `"x|y [a](http://b) <img> www.evil.example @octocat #1"`}},
		}},
	}
	findings := []explain.Finding{
		{Level: explain.Warn, Text: "# not a heading"},
		{Text: "1. not a list"},
		{Text: "*not* _emphasis_ & [no](link) <b>"},
	}

	var got bytes.Buffer
	if err := markdown.Render(&got, tr, findings); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := got.String()
	for _, want := range []string{
		"### ``a`b.example. TXT``: answered",
		"\n````\n",
		`- ⚠ \# not a heading`,
		`- 1\. not a list`,
		`- \*not\* \_emphasis\_ \& \[no\](link) \<b\>`,
		// A code span is the one place GitHub neither links nor mentions.
		"| 192.0.2.53 | differs: `\"x\\124y [a](http://b) <img> www.evil.example @octocat #1\"` |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got\n%s\nwant %q in it", out, want)
		}
	}
}

func compare(tb testing.TB, name, got string) {
	tb.Helper()

	golden := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			tb.Fatalf("writing %s: %v", golden, err)
		}
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		tb.Fatalf("%v (run go test -update to create it)", err)
	}
	if got != string(want) {
		tb.Errorf("output does not match %s, run go test -update to see the change\n--- got ---\n%s", golden, got)
	}
}

// TestRenderEmptyRecord covers a record with no data, which as a code span
// would print as two bare backticks.
func TestRenderEmptyRecord(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "example.", Type: "NULL"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindAnswer, Rcode: "NOERROR", Server: trace.Server{IP: netip.MustParseAddr("192.0.2.1")},
			Records: []trace.RR{{Name: "example.", Type: "NULL", Data: "x"}},
		}}},
		Resolvers: []*trace.Resolver{{
			Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53")}, Rcode: "NOERROR", Match: trace.MatchDiffers,
			Records: []trace.RR{{Name: "example.", Type: "NULL", Data: ""}},
		}},
	}

	var got bytes.Buffer
	if err := markdown.Render(&got, tr, nil); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := "| 192.0.2.53 | differs: - |"; !strings.Contains(got.String(), want) {
		t.Errorf("got\n%s\nwant %q in it", got.String(), want)
	}
}

// TestRenderFailure covers a resolver that answered SERVFAIL where the walk
// did not: the cell says what it most likely came of.
func TestRenderFailure(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "example.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindAnswer, Rcode: "NOERROR", Server: trace.Server{IP: netip.MustParseAddr("192.0.2.1")},
			Records: []trace.RR{{Name: "example.", Type: "A", Data: "192.0.2.10"}},
		}}},
		Resolvers: []*trace.Resolver{{
			Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53")}, Rcode: "SERVFAIL",
			Unchecked: &trace.Resolver{Rcode: "NOERROR"}, Failed: trace.FailedValidation,
		}},
	}

	var got bytes.Buffer
	if err := markdown.Render(&got, tr, nil); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := "| 192.0.2.53 | answered SERVFAIL: fails validation |"; !strings.Contains(got.String(), want) {
		t.Errorf("got\n%s\nwant %q in it", got.String(), want)
	}
}
