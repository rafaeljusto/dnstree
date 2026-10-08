package jsonout_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/render/dot"
	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/render/markdown"
	"github.com/rafaeljusto/dnstree/v2/internal/render/mermaid"
	"github.com/rafaeljusto/dnstree/v2/internal/render/openmetrics"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
)

// FuzzRead reads a saved walk whoever wrote it, the way --from does. A file
// that is refused is refused; one that is read draws in every format without
// a panic, keeps --format ascii in printable ASCII, and saves back to the
// same bytes it would be read from again. A format may still refuse a walk,
// as a timeline does one saved without the times its queries started.
func FuzzRead(f *testing.F) {
	golden, err := os.ReadFile("testdata/resolution.golden")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(golden)
	var saved bytes.Buffer
	if err := jsonout.Render(&saved, resolution()); err != nil {
		f.Fatal(err)
	}
	f.Add(saved.Bytes())
	f.Add([]byte(`{"schema_version":4,"question":{"name":"x\u001b[2K.","type":"A","class":"IN"},"root":{"zone":".","kind":"zone"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tr, err := jsonout.Read(bytes.NewReader(data))
		if err != nil {
			return
		}
		findings := explain.Findings(tr)
		tr.Check = explain.Check(tr)

		var once bytes.Buffer
		if err := jsonout.Render(&once, tr); err != nil {
			t.Fatalf("Render: %v", err)
		}
		again, err := jsonout.Read(bytes.NewReader(once.Bytes()))
		if err != nil {
			t.Fatalf("what it saved is refused: %v\n%s", err, once.String())
		}
		var twice bytes.Buffer
		if err := jsonout.Render(&twice, again); err != nil {
			t.Fatalf("Render again: %v", err)
		}
		if !bytes.Equal(once.Bytes(), twice.Bytes()) {
			t.Errorf("saved twice, it differs:\n%s\n%s", once.String(), twice.String())
		}

		var out bytes.Buffer
		for _, render := range []func() error{
			func() error { return dot.Render(&out, tr) },
			func() error { return mermaid.Render(&out, tr) },
			func() error { return mermaid.Gantt(&out, tr) },
			func() error { return markdown.Render(&out, tr, findings) },
			func() error { return openmetrics.Render(&out, tr) },
			func() error {
				_, _, err := web.Payload(tr, findings, web.Options{})
				return err
			},
			func() error {
				return tree.Render(&out, tr, tree.Options{Charset: tree.Unicode, Color: tree.ColorAlways})
			},
			func() error {
				return tree.Waterfall(&out, tr, tree.Options{Charset: tree.Unicode, Width: 80})
			},
		} {
			out.Reset()
			_ = render()
		}

		out.Reset()
		ascii := tree.Options{Charset: tree.ASCII, Color: tree.ColorNever, Width: 80}
		if err := tree.Render(&out, tr, ascii); err != nil {
			t.Fatalf("ascii: %v", err)
		}
		tree.Summary(&out, tr, ascii)
		tree.Explain(&out, findings, ascii)
		_ = tree.Waterfall(&out, tr, ascii)
		if i := strings.IndexFunc(out.String(), func(r rune) bool { return r > '~' || r < ' ' && r != '\n' }); i >= 0 {
			t.Errorf("ascii holds %q at %d: %q", out.String()[i:min(i+8, len(out.String()))], i, out.String())
		}
	})
}
