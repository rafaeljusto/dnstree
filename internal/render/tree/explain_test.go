package tree_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// explained is what --explain writes under a walk that ran into a lame server,
// which is enough to carry a finding of every level.
func explained(t *testing.T, opts tree.Options) string {
	t.Helper()

	tr := oneHop(&trace.Step{Kind: trace.KindLame, Rcode: "NOERROR"})
	var out bytes.Buffer
	tree.Explain(&out, explain.Findings(tr), opts)
	return out.String()
}

func TestExplain(t *testing.T) {
	out := explained(t, tree.Options{Color: tree.ColorNever})

	if !strings.HasPrefix(out, "\n") {
		t.Errorf("got %q, want it set apart from the summary above it", out)
	}
	for _, want := range []string{"· ", "nothing answered for www.test. A", "ns.test."} {
		if !strings.Contains(out, want) {
			t.Errorf("got %q, want it to carry %q", out, want)
		}
	}
	// One sentence to a line, and nothing drawn around them.
	for line := range strings.Lines(strings.TrimSpace(out)) {
		if !strings.HasPrefix(line, "· ") {
			t.Errorf("got the line %q, want every one of them a finding", line)
		}
	}
}

// TestExplainASCII covers the promise --format ascii makes: the findings are
// prose, and prose is the easiest place to break it.
func TestExplainASCII(t *testing.T) {
	out := explained(t, tree.Options{Charset: tree.ASCII, Color: tree.ColorNever})

	if !strings.Contains(out, "- ") {
		t.Errorf("got %q, want the findings marked in ASCII", out)
	}
	for _, r := range out {
		if r > 127 {
			t.Fatalf("got %q in ascii output, want none", r)
		}
	}
}

func TestExplainColor(t *testing.T) {
	if out := explained(t, tree.Options{Color: tree.ColorNever}); strings.Contains(out, "\x1b") {
		t.Errorf("got %q, want no escapes in it", out)
	}
	if out := explained(t, tree.Options{Color: tree.ColorAlways}); !strings.Contains(out, "\x1b") {
		t.Errorf("got %q, want the findings painted", out)
	}
}

// TestExplainNothing covers a trace there is nothing to say about: the blank
// line that sets the findings apart must not be written on its own.
func TestExplainNothing(t *testing.T) {
	var out bytes.Buffer
	tree.Explain(&out, nil, tree.Options{Color: tree.ColorNever})
	if out.Len() != 0 {
		t.Errorf("got %q, want nothing written", out.String())
	}
}
