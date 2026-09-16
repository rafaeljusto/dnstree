package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
)

// rootZone is a whole synthetic internet in one zone, so that the command can
// be run end to end against a single server on a single port.
const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    127.0.0.1
`

func TestRun(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	hints := rootHintsFile(t)
	port := strconv.Itoa(int(server.Addr.Port()))

	tests := map[string]struct {
		format string
		check  func(testing.TB, string)
	}{
		"tree": {format: "tree", check: func(tb testing.TB, out string) {
			if !strings.Contains(out, "└── ") || !strings.Contains(out, ". (root)") {
				tb.Errorf("got %q, want a tree", out)
			}
		}},
		"ascii": {format: "ascii", check: func(tb testing.TB, out string) {
			if !strings.Contains(out, "`-- ") {
				tb.Errorf("got %q, want ASCII branches", out)
			}
			for _, r := range out {
				if r > 127 {
					tb.Fatalf("got %q in ascii output, want none", r)
				}
			}
		}},
		"json": {format: "json", check: func(tb testing.TB, out string) {
			var document map[string]any
			if err := json.Unmarshal([]byte(out), &document); err != nil {
				tb.Fatalf("the output is not JSON: %v\n%s", err, out)
			}
			if _, ok := document["schema_version"]; !ok {
				tb.Errorf("got %v, want a versioned document", document)
			}
		}},
		"dot": {format: "dot", check: func(tb testing.TB, out string) {
			if !strings.HasPrefix(out, "digraph dnstree {") {
				tb.Errorf("got %q, want a graph", out)
			}
		}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), []string{
				"--root-hints", hints, "--port", port, "--no-asn", "--format", test.format,
				".", "NS",
			}, &stdout, &stderr)

			if code != exitAnswer {
				t.Fatalf("got exit %d, want %d: %s%s", code, exitAnswer, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "a.root-servers.net.") {
				t.Errorf("got %q, want the answer in it", stdout.String())
			}
			test.check(t, stdout.String())
		})
	}
}

func TestRunExitCodes(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	hints := rootHintsFile(t)

	tests := map[string]struct {
		args []string
		want int
	}{
		"an answer": {
			args: []string{"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())), "--no-asn", ".", "NS"},
			want: exitAnswer,
		},
		"nothing to resolve": {args: nil, want: exitUsage},
		"a type nobody has": {
			args: []string{"--root-hints", hints, "--no-asn", "example.com", "NONSENSE"},
			want: exitUsage,
		},
		"root hints that are not there": {
			args: []string{"--root-hints", filepath.Join(t.TempDir(), "missing"), ".", "NS"},
			want: exitUsage,
		},
		"nobody home": {
			// Port 1 is reserved and nothing answers there.
			args: []string{"--root-hints", hints, "--port", "1", "--no-asn", "--timeout", "200ms", "--retries", "0", ".", "NS"},
			want: exitNoAnswer,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(t.Context(), test.args, &stdout, &stderr); got != test.want {
				t.Errorf("got exit %d, want %d: %s%s", got, test.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunDebug(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})

	var stdout, stderr bytes.Buffer
	run(t.Context(), []string{
		"--root-hints", rootHintsFile(t), "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--debug", ".", "NS",
	}, &stdout, &stderr)

	if !strings.Contains(stderr.String(), "asked a nameserver") {
		t.Errorf("got %q on stderr, want the hops reported", stderr.String())
	}
}

// rootHintsFile points the walk at loopback, where the fake root is.
func rootHintsFile(tb testing.TB) string {
	tb.Helper()

	path := filepath.Join(tb.TempDir(), "named.root")
	hints := ".                   3600000 NS a.root-servers.net.\n" +
		"a.root-servers.net. 3600000 A  127.0.0.1\n"
	if err := os.WriteFile(path, []byte(hints), 0o600); err != nil {
		tb.Fatalf("writing the hints: %v", err)
	}
	return path
}
