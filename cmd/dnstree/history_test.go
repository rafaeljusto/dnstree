package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/history"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
)

// TestRunHistory reads a directory of walks saved one after another, the way
// a loop around --format json keeps them, across a change to the answer. It
// asks no server and writes nothing.
func TestRunHistory(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: watchZone("192.0.2.1")})
	hints := rootHintsFile(t)
	port := strconv.Itoa(int(server.Addr.Port()))
	cache := t.TempDir()
	t.Setenv(history.DirEnv, cache)

	dir := t.TempDir()
	save := func(name string, compress bool) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		args := []string{"--root-hints", hints, "--port", port, "--no-asn", "--no-compare", "--format", "json", "www.test."}
		if code := run(t.Context(), args, &stdout, &stderr); code != exitAnswer {
			t.Fatalf("got exit %d, want %d: %s", code, exitAnswer, stderr.String())
		}
		data := stdout.Bytes()
		if compress {
			var buf bytes.Buffer
			z := gzip.NewWriter(&buf)
			_, _ = z.Write(data)
			_ = z.Close()
			data = buf.Bytes()
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	save("1.json.gz", true)
	save("2.json", false)
	server.Replace(t, watchZone("192.0.2.2"))
	save("3.json", false)
	if err := os.WriteFile(filepath.Join(dir, "notes.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	asked := len(server.Queries())

	tests := map[string]struct {
		args []string
		code int
		want []string
	}{
		"the walks of the question, with the change between the two that saw it": {
			args: []string{"--history", dir, "www.test."},
			code: exitAnswer,
			want: []string{
				"3 walks of www.test. A in " + dir,
				"1 change",
				"the answer changed: 192.0.2.1 became 192.0.2.2",
				"192.0.2.2", // the newest walk is the one drawn
				"--history skipped what holds no walk it can read: notes.json",
			},
		},
		"a question the directory holds no walk of": {
			args: []string{"--history", dir, "www.test.", "AAAA"},
			code: exitUsage,
			want: []string{"--history " + dir + " holds no walk of www.test. AAAA"},
		},
		"the walks as a report": {
			args: []string{"--history", dir, "--format", "markdown", "www.test."},
			code: exitAnswer,
			want: []string{"the answer changed: 192.0.2.1 became 192.0.2.2"},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), append([]string{"--color", "never"}, test.args...), &stdout, &stderr)
			if code != test.code {
				t.Fatalf("got exit %d, want %d: %s%s", code, test.code, stdout.String(), stderr.String())
			}
			out := stdout.String() + stderr.String()
			for _, want := range test.want {
				if !strings.Contains(out, want) {
					t.Errorf("got\n%s\nwant it to carry %q", out, want)
				}
			}
		})
	}

	if got := len(server.Queries()); got != asked {
		t.Errorf("got %d more queries, want a history to ask nothing", got-asked)
	}
	if entries, err := os.ReadDir(cache); err != nil || len(entries) != 0 {
		t.Errorf("got %v and %v, want nothing remembered", entries, err)
	}
}
