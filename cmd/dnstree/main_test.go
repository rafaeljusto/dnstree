package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/cli"
	"github.com/rafaeljusto/dnstree/v2/internal/history"
	"github.com/rafaeljusto/dnstree/v2/internal/rdap"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakemx"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/output"
)

// rootZone is a whole synthetic internet in one zone, so that the command can
// be run end to end against a single server on a single port.
const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    127.0.0.1
`

// TestMain puts the tests in a home of their own, so that a file of defaults on
// the machine running them cannot change what the command does.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "dnstree-home")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	os.Unsetenv(cli.ConfigEnv)

	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

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
		"emoji": {format: "emoji", check: func(tb testing.TB, out string) {
			if !strings.Contains(out, "🎯") || !strings.Contains(out, "🌍") {
				tb.Errorf("got %q, want the walk told in emoji", out)
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
		"mermaid": {format: "mermaid", check: func(tb testing.TB, out string) {
			if !strings.Contains(out, "flowchart LR") || strings.Contains(out, "answered in") {
				tb.Errorf("got %q, want a chart and no summary under it", out)
			}
		}},
		"waterfall": {format: "waterfall", check: func(tb testing.TB, out string) {
			if !strings.Contains(out, "█") || !strings.Contains(out, "answered in") {
				tb.Errorf("got %q, want a bar per query and the summary under them", out)
			}
		}},
		"waterfall-ascii": {format: "waterfall-ascii", check: func(tb testing.TB, out string) {
			if !strings.Contains(out, "#") {
				tb.Errorf("got %q, want ASCII bars", out)
			}
			for _, r := range out {
				if r > 127 {
					tb.Fatalf("got %q in waterfall-ascii output, want none", r)
				}
			}
		}},
		"waterfall-mermaid": {format: "waterfall-mermaid", check: func(tb testing.TB, out string) {
			if !strings.Contains(out, "\ngantt\n") || strings.Contains(out, "answered in") {
				tb.Errorf("got %q, want a gantt chart and no summary under it", out)
			}
		}},
		"markdown": {format: "markdown", check: func(tb testing.TB, out string) {
			if !strings.HasPrefix(out, "### `. NS`: answered\n") || strings.Count(out, "answered in") != 1 ||
				!strings.Contains(out, "**what happened**") {
				tb.Errorf("got %q, want a report, explained, with the summary in it once", out)
			}
		}},
		"openmetrics": {format: "openmetrics", check: func(tb testing.TB, out string) {
			if !strings.HasSuffix(out, "\n# EOF\n") || strings.Contains(out, "answered in") {
				tb.Errorf("got %q, want metrics and no summary under them", out)
			}
		}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), []string{
				"--root-hints", hints, "--port", port, "--no-asn", "--no-compare", "--format", test.format,
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

// TestRunWeb covers the formats that draw nothing: the walk is served instead,
// the address is printed where somebody can open it, and interrupting the run
// is what takes it down. The two pages read the same walk.
func TestRunWeb(t *testing.T) {
	tests := map[string]struct {
		format string
		page   string
	}{
		"the flat page": {format: "web", page: "app.js"},
		"the scene":     {format: "web-3d", page: "scene.js"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
			hints := rootHintsFile(t)

			ctx, stop := context.WithCancel(t.Context())
			defer stop()

			out := new(output.Buffer)
			done := make(chan int, 1)
			go func() {
				done <- run(ctx, []string{
					"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
					"--no-asn", "--no-compare", "--format", test.format,
					"--web-addr", "127.0.0.1:0", "--no-browser", "--explain", ".", "NS",
				}, out, io.Discard)
			}()

			base := out.Await(t, output.Address)
			index, err := http.Get(base)
			if err != nil {
				t.Fatalf("reading the page: %v", err)
			}
			html, _ := io.ReadAll(index.Body)
			index.Body.Close()
			if !strings.Contains(string(html), test.page) {
				t.Errorf("got a page without %s, want the one --format %s serves", test.page, test.format)
			}

			answer, err := http.Get(base + "page.json")
			if err != nil {
				t.Fatalf("reading the walk: %v", err)
			}
			defer answer.Body.Close()

			var page struct {
				Trace struct {
					Question struct {
						Name string `json:"name"`
					} `json:"question"`
				} `json:"trace"`
				Findings []struct {
					Text string `json:"text"`
				} `json:"findings"`
			}
			if err := json.NewDecoder(answer.Body).Decode(&page); err != nil {
				t.Fatalf("the page is not JSON: %v", err)
			}
			if page.Trace.Question.Name != "." {
				t.Errorf("got %q, want the walk that was made", page.Trace.Question.Name)
			}
			if len(page.Findings) == 0 {
				t.Error("got no findings, want --explain carried to the page")
			}

			stop()
			select {
			case code := <-done:
				if code != exitAnswer {
					t.Errorf("got exit %d, want %d", code, exitAnswer)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the command is still running after it was interrupted")
			}
		})
	}
}

// TestRunLiveNowhere covers --live where there is no one to watch: a pipe, a
// file, a test. Nothing is drawn twice and no escape is written.
func TestRunLiveNowhere(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	hints := rootHintsFile(t)
	port := strconv.Itoa(int(server.Addr.Port()))

	resolve := func(tb testing.TB, args ...string) string {
		tb.Helper()

		var stdout, stderr bytes.Buffer
		code := run(t.Context(), append(args,
			"--root-hints", hints, "--port", port, "--no-asn", "--no-compare", ".", "NS"), &stdout, &stderr)
		if code != exitAnswer {
			tb.Fatalf("got exit %d, want %d: %s%s", code, exitAnswer, stdout.String(), stderr.String())
		}
		return stdout.String()
	}

	live := resolve(t, "--live")
	if strings.Contains(live, "\x1b") {
		t.Errorf("got %q, want nothing drawn at something that is not a terminal", live)
	}
	// Only the round trip times, which no two runs share, are allowed to differ.
	timing := regexp.MustCompile(`[0-9.]+(µs|ms|s)`)
	if want := resolve(t); timing.ReplaceAllString(live, "") != timing.ReplaceAllString(want, "") {
		t.Errorf("got\n%s\nwant the same as without --live\n%s", live, want)
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
			args: []string{"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())), "--no-asn", "--no-compare", ".", "NS"},
			want: exitAnswer,
		},
		"nothing to resolve": {args: nil, want: exitUsage},
		"a type nobody has": {
			args: []string{"--root-hints", hints, "--no-asn", "--no-compare", "example.com", "NONSENSE"},
			want: exitUsage,
		},
		"root hints that are not there": {
			args: []string{"--root-hints", filepath.Join(t.TempDir(), "missing"), "--no-compare", ".", "NS"},
			want: exitUsage,
		},
		"nobody home": {
			// Port 1 is reserved and nothing answers there.
			args: []string{"--root-hints", hints, "--port", "1", "--no-asn", "--no-compare", "--timeout", "200ms", "--retries", "0", ".", "NS"},
			want: exitNoAnswer,
		},
		"an expectation that holds": {
			args: []string{"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())), "--no-asn", "--no-compare",
				"--expect", "a.root-servers.net.", ".", "NS"},
			want: exitAnswer,
		},
		"an expectation that does not": {
			args: []string{"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())), "--no-asn", "--no-compare",
				"--expect", "b.root-servers.net.", ".", "NS"},
			want: exitExpect,
		},
		// The walk's own verdict is the bigger fact, and a script reading 4 for
		// a walk that answered nothing would go looking in the wrong place.
		"a walk that answered nothing keeps its own verdict": {
			args: []string{"--root-hints", hints, "--port", "1", "--no-asn", "--no-compare", "--timeout", "200ms", "--retries", "0",
				"--expect", "a.root-servers.net.", ".", "NS"},
			want: exitNoAnswer,
		},
		"an expectation nothing can be made of": {
			args: []string{"--root-hints", hints, "--no-asn", "--no-compare", "--expect", "", ".", "NS"},
			want: exitUsage,
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

// TestRunNamesTheFlagOfAMissingFile covers the files a run is pointed at.
// Several flags take one, and "no such file or directory" alone leaves the user
// to work out which of them it was.
func TestRunNamesTheFlagOfAMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	tests := map[string][]string{
		"--names":         {"--names", missing},
		"--root-hints":    {"--root-hints", missing, "example.com"},
		"--from":          {"--from", missing},
		"--against":       {"--against", missing, "example.com"},
		"--trust-anchors": {"--trust-anchors", missing, "--dnssec", "example.com"},
		"--tls-ca":        {"--tls-ca", missing, "--dot", "--root", "192.0.2.1", "example.com"},
		"--config":        {"--config", missing, "example.com"},
	}
	for flag, args := range tests {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(t.Context(), args, &stdout, &stderr); got != exitUsage {
				t.Errorf("got exit %d, want %d: %s", got, exitUsage, stderr.String())
			}
			if want := flag + " " + missing + ": "; !strings.Contains(stderr.String(), want) {
				t.Errorf("got %q, want it to say %q", stderr.String(), want)
			}
		})
	}
}

// TestRunRefusesAQuestionLikeAnyCommandLine covers a name or type nothing can
// ask, which is the user's typing and said like the rest of it, with the list it
// came from where it came from one. The line is the mistake alone: the error
// that marks it as the command line's is for the code, not the user.
func TestRunRefusesAQuestionLikeAnyCommandLine(t *testing.T) {
	list := filepath.Join(t.TempDir(), "names")
	if err := os.WriteFile(list, []byte("bad..name\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		args []string
		want string
	}{
		"a flag":            {args: []string{"--bogus", "example.com"}, want: "--bogus is not a flag; --help lists them"},
		"a name":            {args: []string{"bad..name"}, want: `"bad..name" is not a domain name`},
		"a type":            {args: []string{"example.com", "nonsense"}, want: `"NONSENSE" is not a query type`},
		"a name in --names": {args: []string{"--names", list}, want: "--names " + list + `: "bad..name" is not a domain name`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(t.Context(), append([]string{"--no-config"}, test.args...), &stdout, &stderr); got != exitUsage {
				t.Errorf("got exit %d, want %d: %s", got, exitUsage, stderr.String())
			}
			if got := stderr.String(); got != test.want+"\n" {
				t.Errorf("got %q, want %q", got, test.want+"\n")
			}
		})
	}
}

func TestRunDebug(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})

	var stdout, stderr bytes.Buffer
	run(t.Context(), []string{
		"--root-hints", rootHintsFile(t), "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--no-compare", "--debug", ".", "NS",
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

// The two zones of a walk that has to change port halfway down: the root is
// reached where --root says, the delegation below it where --port does.
const (
	splitRootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    127.0.0.1
test.               IN NS   ns.test.
ns.test.            IN A    127.0.0.1
`

	splitChildZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    127.0.0.1
www   IN A    192.0.2.10
`
)

// TestRunRoot walks a hierarchy the command line put together itself. The two
// servers share loopback and differ only by port, which is the shape a test
// hierarchy has: --root carries the port of the one it names, and --port says
// where everything reached by glue is asked, glue having no port to carry.
func TestRunRoot(t *testing.T) {
	root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: splitRootZone})
	child := fakens.New(t, fakens.Config{Name: "ns.test.", Origin: "test.", Zone: splitChildZone})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", "a.root-servers.net@" + root.Addr.String(),
		"--port", strconv.Itoa(int(child.Addr.Port())),
		"--no-asn", "--no-compare", "--color", "never", "www.test", "A",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"a.root-servers.net.", "referral → test.", "www.test.", "192.0.2.10"} {
		if !strings.Contains(out, want) {
			t.Errorf("got no %q in the walk:\n%s", want, out)
		}
	}
}

// TestRunWithout leaves a nameserver out. The zone's only one leaves nothing
// to answer, whatever transport is there to fall back on; one the walk never
// needed is said to have changed nothing, which is what a misspelled name looks
// like.
func TestRunWithout(t *testing.T) {
	tests := map[string]struct {
		without string
		code    int
		want    []string
	}{
		"the zone's only nameserver": {
			without: "ns.test",
			code:    exitNoAnswer,
			want:    []string{"left out by --without ns.test.", "no answer in", "without ns.test."},
		},
		"a nameserver the walk never needed": {
			without: "ns.example.com",
			code:    exitAnswer,
			want: []string{"answered in", "without ns.example.com.",
				"--without ns.example.com. left nothing out: the walk came to no server by that name or address"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: splitRootZone})
			child := fakens.New(t, fakens.Config{Name: "ns.test.", Origin: "test.", Zone: splitChildZone})

			var stdout, stderr bytes.Buffer
			code := run(t.Context(), []string{
				"--root", "a.root-servers.net@" + root.Addr.String(),
				"--port", strconv.Itoa(int(child.Addr.Port())),
				"--tcp", "--fallback", "--without", test.without,
				"--no-asn", "--no-compare", "--color", "never", "www.test", "A",
			}, &stdout, &stderr)

			if code != test.code {
				t.Fatalf("got exit %d, want %d\n%s%s", code, test.code, stdout.String(), stderr.String())
			}
			out := stdout.String() + stderr.String()
			for _, want := range test.want {
				if !strings.Contains(out, want) {
					t.Errorf("got no %q:\n%s", want, out)
				}
			}
			if test.code == exitNoAnswer && len(child.Queries()) > 0 {
				t.Errorf("got %d queries at ns.test., which was left out", len(child.Queries()))
			}
		})
	}
}

// TestRunExposure asks the zone's nameserver for the whole zone and for a
// lookup it should not do. The transfer is open, and the tree and the
// explanation both say so; the zone itself is never drawn.
func TestRunExposure(t *testing.T) {
	root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: splitRootZone})
	child := fakens.New(t, fakens.Config{Name: "ns.test.", Origin: "test.", Zone: splitChildZone,
		Behaviour: fakens.Behaviour{OpenTransfer: true}})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", "a.root-servers.net@" + root.Addr.String(),
		"--port", strconv.Itoa(int(child.Addr.Port())),
		"--check-axfr", "--check-recursion", "--explain",
		"--no-asn", "--no-compare", "--color", "never", "--format", "ascii", "www.test", "A",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"axfr open", "recursion closed",
		"zone transfers of test. are open to anyone at ns.test.",
		"no nameserver of test. looked up another name for a stranger",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hostmaster") {
		t.Errorf("got the transferred zone drawn:\n%s", out)
	}
}

// TestRunEDNS puts the RFC 8906 tests to a nameserver that copies an unknown
// flag back. The tree and the explanation say so, and the walk still answers.
func TestRunEDNS(t *testing.T) {
	root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: splitRootZone})
	child := fakens.New(t, fakens.Config{Name: "ns.test.", Origin: "test.", Zone: splitChildZone,
		Behaviour: fakens.Behaviour{EchoEDNSFlags: true}})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", "a.root-servers.net@" + root.Addr.String(),
		"--port", strconv.Itoa(int(child.Addr.Port())),
		"--check-edns", "--explain",
		"--no-asn", "--no-compare", "--color", "never", "--format", "ascii", "www.test", "A",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"edns0 ok", "edns version 1 ok", "edns option 100 ok", "edns flag 0x40 broken: copied back",
		"did not ignore an EDNS flag nobody has defined",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got no %q:\n%s", want, out)
		}
	}
}

// TestRunRootWithoutName leaves the name off, which is all a walk needs when
// nothing has to verify a certificate.
func TestRunRootWithoutName(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", server.Addr.String(), "--no-asn", "--no-compare", "--color", "never", ".", "NS",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "a.root-servers.net.") {
		t.Errorf("got no answer in the walk:\n%s", out)
	}
}

// TestRunRootIgnoresThePort makes sure the port a root carries wins over
// --port, which is what lets the rest of the hierarchy sit somewhere else.
func TestRunRootIgnoresThePort(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", server.Addr.String(), "--port", "1", // nothing answers on port 1
		"--no-asn", "--no-compare", "--timeout", "500ms", "--retries", "0", "--color", "never", ".", "NS",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d: the root was asked on --port\n%s%s",
			code, exitAnswer, stdout.String(), stderr.String())
	}
}

// TestRunRootOverTLS reaches the same split hierarchy over DoT. The fake
// servers hold the library's self-signed certificate, so the walk only gets
// through when --tls-insecure says not to verify it.
func TestRunRootOverTLS(t *testing.T) {
	root := fakens.New(t, fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: splitRootZone, TLS: true,
	})
	child := fakens.New(t, fakens.Config{
		Name: "ns.test.", Origin: "test.", Zone: splitChildZone, TLS: true,
	})

	args := []string{
		"--root", "a.root-servers.net@" + root.TLSAddr.String(),
		"--port", strconv.Itoa(int(child.TLSAddr.Port())),
		"--dot", "--no-asn", "--no-compare", "--timeout", "2s", "--color", "never", "www.test", "A",
	}

	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), append([]string{"--tls-insecure"}, args...), &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "192.0.2.10") {
		t.Errorf("got no answer over dot:\n%s", out)
	}

	// The same walk verifying the certificate reaches nothing at all.
	stdout.Reset()
	stderr.Reset()
	if code := run(t.Context(), args, &stdout, &stderr); code != exitNoAnswer {
		t.Errorf("got exit %d without --tls-insecure, want %d: the certificate refused\n%s%s",
			code, exitNoAnswer, stdout.String(), stderr.String())
	}
}

// TestRunCompare puts the same question to a recursive server beside the walk.
// A walk from the root is the slow way round by design, so that timing is what
// says whether the wait was the name's doing or the method's.
func TestRunCompare(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", server.Addr.String(), "--resolver", server.Addr.String(),
		"--no-asn", "--color", "never", ".", "NS",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "resolver in ") {
		t.Errorf("got no resolver to read the walk against:\n%s", out)
	}
	if !strings.Contains(out, "answered in ") {
		t.Errorf("got no summary under the tree:\n%s", out)
	}
}

// TestRunServFail covers a resolver that fails validation where the walk does
// not: asked again with checking disabled, it answers, and the line under the
// tree says so.
func TestRunServFail(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	resolver := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone,
		Behaviour: fakens.Behaviour{ServFailUnlessCD: true}})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", server.Addr.String(), "--resolver", resolver.Addr.String(),
		"--no-asn", "--color", "never", "--format", "ascii", ".", "NS",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d: a resolver failing is not the walk failing\n%s%s",
			code, exitAnswer, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if want := "servfail: 127.0.0.1 answers SERVFAIL where the walk found"; !strings.Contains(out, want) {
		t.Errorf("got no %q:\n%s", want, out)
	}
	if want := "with checking disabled it answers, so it fails validation"; !strings.Contains(out, want) {
		t.Errorf("got no %q:\n%s", want, out)
	}
	queries := resolver.Queries()
	if len(queries) != 2 || queries[0].CD || !queries[1].CD {
		t.Errorf("got %+v, want the resolver asked once plainly and once with checking disabled", queries)
	}
}

// TestRunDDR asks the resolver the walk is timed against which encrypted
// resolvers stand for it, and draws what it offers under the tree.
func TestRunDDR(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone + `
_dns.resolver.arpa. IN SVCB 1 dns.test. alpn=dot
`})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", server.Addr.String(), "--resolver", server.Addr.String(),
		"--ddr", "--explain", "--no-asn", "--color", "never", "--format", "ascii", ".", "NS",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if want := "ddr: 127.0.0.1 offers dot at dns.test (not verified)"; !strings.Contains(out, want) {
		t.Errorf("got no %q:\n%s", want, out)
	}
	if want := "which --ddr does not check"; !strings.Contains(out, want) {
		t.Errorf("got no %q in the explanation:\n%s", want, out)
	}
}

// cymruZone answers for loopback the way Team Cymru answers for a real address.
const cymruZone = `
@         IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@         IN NS   ns
ns        IN A    127.0.0.1
1.0.0.127 IN TXT  "64512 | 127.0.0.0/8 | ZZ | test | 1970-01-01"
`

// TestRunASNResolver sends the origin AS lookups somewhere the host knows
// nothing about, which is the only way to see them annotated offline.
func TestRunASNResolver(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	cymru := fakens.New(t, fakens.Config{Origin: "origin.asn.cymru.com.", Zone: cymruZone})

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", server.Addr.String(),
		"--resolver", cymru.Addr.String(),
		"--no-compare", "--color", "never", ".", "NS",
	}, &stdout, &stderr)

	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "AS64512") {
		t.Errorf("got no origin AS from the resolver that was named:\n%s", out)
	}
}

// TestRunExplain covers --explain end to end. The sentences are read off the
// trace the walk recorded, so a real walk is the only thing worth reading them
// against: one that answered, and one that ran into a server with no business
// answering for the zone.
func TestRunExplain(t *testing.T) {
	t.Run("a walk that answered", func(t *testing.T) {
		server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})

		var stdout, stderr bytes.Buffer
		code := run(t.Context(), []string{
			"--root-hints", rootHintsFile(t), "--port", strconv.Itoa(int(server.Addr.Port())),
			"--no-asn", "--no-compare", "--color", "never", "--explain", ".", "NS",
		}, &stdout, &stderr)

		if code != exitAnswer {
			t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"· ", ". NS is a.root-servers.net.", "answered by"} {
			if !strings.Contains(out, want) {
				t.Errorf("got no %q in the run:\n%s", want, out)
			}
		}
	})

	t.Run("a walk that met a lame server", func(t *testing.T) {
		root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: splitRootZone})
		child := fakens.New(t, fakens.Config{
			Name: "ns.test.", Origin: "test.", Zone: splitChildZone,
			Behaviour: fakens.Behaviour{Lame: true},
		})

		var stdout, stderr bytes.Buffer
		code := run(t.Context(), []string{
			"--root", "a.root-servers.net@" + root.Addr.String(),
			"--port", strconv.Itoa(int(child.Addr.Port())),
			"--no-asn", "--no-compare", "--format", "ascii", "--explain", "www.test", "A",
		}, &stdout, &stderr)

		if code != exitNoAnswer {
			t.Fatalf("got exit %d, want %d\n%s%s", code, exitNoAnswer, stdout.String(), stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"nothing answered for www.test. A", "answered without authority", "ns.test."} {
			if !strings.Contains(out, want) {
				t.Errorf("got no %q in the run:\n%s", want, out)
			}
		}
		// The findings are prose, which is the easiest place to break what
		// --format ascii promises about the whole run.
		for _, r := range out {
			if r > 127 {
				t.Fatalf("got %q in ascii output, want none", r)
			}
		}
	})

	// Nothing is said unless it is asked for.
	t.Run("a walk that was not asked to explain itself", func(t *testing.T) {
		server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})

		var stdout, stderr bytes.Buffer
		run(t.Context(), []string{
			"--root-hints", rootHintsFile(t), "--port", strconv.Itoa(int(server.Addr.Port())),
			"--no-asn", "--no-compare", "--color", "never", ".", "NS",
		}, &stdout, &stderr)

		if out := stdout.String(); strings.Contains(out, "answered by") {
			t.Errorf("got an explanation nobody asked for:\n%s", out)
		}
	})
}

// TestRunSchema covers --schema. It answers a question about the command
// rather than resolving a name, so it needs neither a name nor anything to
// resolve it against.
func TestRunSchema(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"--schema"}, &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d: %s", code, exitAnswer, stderr.String())
	}

	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("the schema is not JSON: %v\n%s", err, stdout.String())
	}
	if _, ok := document["$schema"]; !ok {
		t.Errorf("got %v, want it to name the draft it is written in", document)
	}

	properties, _ := document["properties"].(map[string]any)
	if properties["schema_version"] == nil {
		t.Errorf("got %v, want it to describe the document --format json writes", document)
	}
}

// TestRunDiff covers --diff end to end: the first walk has nothing to compare
// against and remembers itself, and the second is held against it. The cache
// goes in a directory of the test's own, because a run that wrote to the one on
// the machine would change what the next run of the real command says.
func TestRunDiff(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	hints := rootHintsFile(t)
	port := strconv.Itoa(int(server.Addr.Port()))
	cache := t.TempDir()
	t.Setenv(history.DirEnv, cache)

	walk := func(tb testing.TB) string {
		tb.Helper()

		var stdout, stderr bytes.Buffer
		code := run(t.Context(), []string{
			"--root-hints", hints, "--port", port,
			"--no-asn", "--no-compare", "--color", "never", "--diff", ".", "NS",
		}, &stdout, &stderr)

		if code != exitAnswer {
			tb.Fatalf("got exit %d, want %d: %s%s", code, exitAnswer, stdout.String(), stderr.String())
		}
		if stderr.Len() > 0 {
			tb.Errorf("got %q on stderr, want the comparison to have gone through", stderr.String())
		}
		return stdout.String()
	}

	if first := walk(t); !strings.Contains(first, "nothing to compare") {
		t.Errorf("got %q, want the first walk to have nothing to compare against", first)
	}

	// Remembered under a name that can be read and thrown away by hand.
	if entries, err := os.ReadDir(cache); err != nil || len(entries) != 1 {
		t.Fatalf("got %v and %v, want the one walk remembered", entries, err)
	}

	if second := walk(t); !strings.Contains(second, "nothing has changed since the walk of . NS") {
		t.Errorf("got %q, want the second walk held against the first", second)
	}
}

// watchZone is the root, serving one address for www.test. so that a test can
// change it under a walk that is watching.
func watchZone(address string) string {
	return `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    127.0.0.1
www.test.           IN A    ` + address + "\n"
}

// watching starts a run in the background and hands back the buffers it writes
// to and the code it ends with.
func watching(ctx context.Context, tb testing.TB, args ...string) (code <-chan int, out, errs *output.Buffer) {
	tb.Helper()

	stdout, stderr := new(output.Buffer), new(output.Buffer)
	done := make(chan int, 1)
	go func() { done <- run(ctx, args, stdout, stderr) }()
	return done, stdout, stderr
}

// ended waits for a run to finish, and says so rather than hanging the suite
// where it does not.
func ended(tb testing.TB, code <-chan int) int {
	tb.Helper()

	select {
	case got := <-code:
		return got
	case <-time.After(20 * time.Second):
		tb.Fatal("the run did not end")
		return 0
	}
}

// TestRunWatch covers what is left on the screen by a watch: the tree once, a
// line for the round that found the answer had moved, and nothing at all for
// the rounds that found it had not.
func TestRunWatch(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: watchZone("192.0.2.1")})
	hints := rootHintsFile(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	code, stdout, stderr := watching(ctx, t,
		"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--no-compare", "--color", "never", "--watch", "1s", "www.test", "A")

	stdout.Await(t, `\(root\)`)
	server.Replace(t, watchZone("192.0.2.2"))
	time.Sleep(2500 * time.Millisecond)
	cancel()

	if got := ended(t, code); got != exitAnswer {
		t.Errorf("got exit %d, want %d: %s", got, exitAnswer, stderr.String())
	}

	out := stdout.String()
	if got := strings.Count(out, "(root)"); got != 1 {
		t.Errorf("got %d trees, want the one drawn at the start: %s", got, out)
	}

	// Said once, by the round that found it: the rounds after that one found
	// the same answer as the round before them and have nothing to say.
	const moved = "the answer changed: 192.0.2.1 became 192.0.2.2"
	if got := strings.Count(out, moved); got != 1 {
		t.Errorf("got the change said %d times, want once: %s", got, out)
	}
	if !regexp.MustCompile(`(?m)^\d\d:\d\d:\d\d ` + regexp.QuoteMeta(moved)).MatchString(out) {
		t.Errorf("got %q, want the change under the time it was found", out)
	}
}

// TestRunWatchWaitsForWhatIsExpected covers the reason to leave one running:
// it ends of its own accord as soon as everything expected of the walk holds.
func TestRunWatchWaitsForWhatIsExpected(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: watchZone("192.0.2.1")})
	hints := rootHintsFile(t)

	code, stdout, stderr := watching(t.Context(), t,
		"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--no-compare", "--color", "never", "--watch", "1s",
		"--expect", "192.0.2.2", "www.test", "A")

	stdout.Await(t, `\(root\)`)
	server.Replace(t, watchZone("192.0.2.2"))

	if got := ended(t, code); got != exitAnswer {
		t.Errorf("got exit %d, want %d once the answer arrived: %s", got, exitAnswer, stderr.String())
	}
}

// TestRunWatchInterrupted covers the other way it ends: the answer never came,
// and what it exits with says so rather than saying the wait went well.
func TestRunWatchInterrupted(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: watchZone("192.0.2.1")})
	hints := rootHintsFile(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	code, stdout, stderr := watching(ctx, t,
		"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--no-compare", "--color", "never", "--watch", "1s",
		"--expect", "192.0.2.2", "www.test", "A")

	stdout.Await(t, `\(root\)`)
	cancel()

	if got := ended(t, code); got != exitExpect {
		t.Errorf("got exit %d, want %d: what was expected never arrived", got, exitExpect)
	}
	if !strings.Contains(stderr.String(), "expected 192.0.2.2, got 192.0.2.1") {
		t.Errorf("got %q, want it to say what it was still waiting for", stderr.String())
	}
}

// TestRunFrom saves a walk as JSON and draws it again, which asks nothing of
// any server: the second run is pointed at none and still answers the way the
// first one did.
func TestRunFrom(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	hints := rootHintsFile(t)
	port := strconv.Itoa(int(server.Addr.Port()))

	var saved, stderr bytes.Buffer
	if code := run(t.Context(), []string{
		"--root-hints", hints, "--port", port, "--no-asn", "--no-compare", "--format", "json", ".", "NS",
	}, &saved, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d: %s", code, exitAnswer, stderr.String())
	}
	path := filepath.Join(t.TempDir(), "walk.json")
	if err := os.WriteFile(path, saved.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	asked := len(server.Queries())

	// The same walk as a build that kept no start times would have saved it.
	untimed := filepath.Join(t.TempDir(), "untimed.json")
	stripped := regexp.MustCompile(`\s*"start_ms": [0-9.]+,`).ReplaceAll(saved.Bytes(), nil)
	if bytes.Equal(stripped, saved.Bytes()) {
		t.Fatal("got a saved walk with no start_ms to take out")
	}
	if err := os.WriteFile(untimed, stripped, 0o644); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		args []string
		code int
		want string
	}{
		"drawn as a tree, and explained": {
			args: []string{"--from", path, "--explain", "--color", "never"},
			code: exitAnswer, want: ". NS is a.root-servers.net.",
		},
		"written back out as it was saved": {
			args: []string{"--from", path, "--format", "json"},
			code: exitAnswer, want: saved.String(),
		},
		"drawn as a chart": {
			args: []string{"--from", path, "--format", "mermaid"},
			code: exitAnswer, want: "flowchart LR",
		},
		"drawn as a waterfall": {
			args: []string{"--from", path, "--format", "waterfall-ascii"},
			code: exitAnswer, want: "a.root-servers.net.",
		},
		"written up as a report": {
			args: []string{"--from", path, "--format", "markdown"},
			code: exitAnswer, want: "- . NS is a.root-servers.net.",
		},
		"drawn as a gantt chart": {
			args: []string{"--from", path, "--format", "waterfall-mermaid"},
			code: exitAnswer, want: "\ngantt\n",
		},
		"a walk saved before start times, refused a waterfall": {
			args: []string{"--from", untimed, "--format", "waterfall"},
			code: exitUsage, want: "walk the name again",
		},
		"a walk saved before start times, refused a gantt chart": {
			args: []string{"--from", untimed, "--format", "waterfall-mermaid"},
			code: exitUsage, want: "walk the name again",
		},
		"a walk saved before start times, still drawn as a tree": {
			args: []string{"--from", untimed, "--color", "never"},
			code: exitAnswer, want: "a.root-servers.net.",
		},
		"held to what was expected of it": {
			args: []string{"--from", path, "--expect", "nxdomain"},
			code: exitExpect, want: "expected nxdomain, got answer",
		},
		"how long a change takes, worked out again": {
			args: []string{"--from", path, "--propagation", "--color", "never"},
			code: exitAnswer, want: "propagation:   change the answer",
		},
		"how long a change takes, written for a program": {
			args: []string{"--from", path, "--propagation", "--format", "json"},
			code: exitAnswer, want: `"change": "answer"`,
		},
		"a file that is not a walk": {
			args: []string{"--from", hints},
			code: exitUsage, want: "not a trace",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), test.args, &stdout, &stderr)
			if code != test.code {
				t.Fatalf("got exit %d, want %d: %s%s", code, test.code, stdout.String(), stderr.String())
			}
			if out := stdout.String() + stderr.String(); !strings.Contains(out, test.want) {
				t.Errorf("got\n%s\nwant it to carry %q", out, test.want)
			}
		})
	}

	if got := len(server.Queries()); got != asked {
		t.Errorf("got %d more queries, want a saved walk to ask nothing", got-asked)
	}
}

// TestRunAgainst holds walks against one saved to a file: another saved walk,
// and one made now. Nothing is remembered, so the cache is left empty.
func TestRunAgainst(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: watchZone("192.0.2.1")})
	hints := rootHintsFile(t)
	port := strconv.Itoa(int(server.Addr.Port()))
	cache := t.TempDir()
	t.Setenv(history.DirEnv, cache)

	walking := []string{"--root-hints", hints, "--port", port, "--no-asn", "--no-compare"}
	save := func(tb testing.TB, name string) string {
		tb.Helper()

		var stdout, stderr bytes.Buffer
		args := append(slices.Clone(walking), "--format", "json", "www.test.")
		if code := run(t.Context(), args, &stdout, &stderr); code != exitAnswer {
			tb.Fatalf("got exit %d, want %d: %s", code, exitAnswer, stderr.String())
		}
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, stdout.Bytes(), 0o644); err != nil {
			tb.Fatal(err)
		}
		return path
	}

	before := save(t, "before.json")
	server.Replace(t, watchZone("192.0.2.2"))
	after := save(t, "after.json")

	// A question whose type carries an escape, which only its escaped copy may
	// be compared by or drawn as.
	hostile := filepath.Join(t.TempDir(), "hostile.json")
	if err := os.WriteFile(hostile, []byte(`{"schema_version": 4,
		"question": {"name": "www.test.", "type": "A\u001b[41m", "class": "IN"}, "elapsed_ms": 1,
		"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "nxdomain", "rcode": "NXDOMAIN",
		"server": {"name": "a.root-servers.net.", "ip": "192.0.2.1", "port": 53}}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		args []string
		code int
		want string
	}{
		"two saved walks that differ": {
			args: []string{"--from", after, "--against", before},
			code: exitAnswer, want: "the answer changed: 192.0.2.1 became 192.0.2.2",
		},
		"a saved walk held against itself": {
			args: []string{"--from", after, "--against", after},
			code: exitAnswer, want: "nothing differs from the walk of www.test. A in " + after,
		},
		"a walk made now, held against a saved one": {
			args: append(slices.Clone(walking), "--against", before, "www.test."),
			code: exitAnswer, want: "the answer changed: 192.0.2.1 became 192.0.2.2",
		},
		"a walk made now, of another question": {
			args: append(slices.Clone(walking), "--against", before, "www.test.", "AAAA"),
			code: exitUsage, want: before + " is a walk of www.test. A, and this one is of www.test. AAAA",
		},
		"a file that is not a walk": {
			args: []string{"--from", after, "--against", hints},
			code: exitUsage, want: "not a trace",
		},
		"a hostile question, held against itself": {
			args: []string{"--from", hostile, "--against", hostile},
			code: exitAnswer, want: "nothing differs",
		},
		"a hostile question, held against another": {
			args: []string{"--from", hostile, "--against", before},
			code: exitUsage, want: "and this one is of www.test. A",
		},
		"the first round of a watch": {
			args: append(slices.Clone(walking),
				"--watch", "1s", "--expect", "192.0.2.2", "--against", before, "www.test."),
			code: exitAnswer, want: "the answer changed: 192.0.2.1 became 192.0.2.2",
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
			if !strings.Contains(out, test.want) {
				t.Errorf("got\n%s\nwant it to carry %q", out, test.want)
			}
			if strings.Contains(out, "\x1b") {
				t.Errorf("got an escape through:\n%q", out)
			}
		})
	}

	if entries, err := os.ReadDir(cache); err != nil || len(entries) != 0 {
		t.Errorf("got %v and %v, want nothing remembered", entries, err)
	}
}

// TestRunFromHostile reads a file written to forge output, with escapes in the
// fields a walk fills with this build's own words. Whoever hands over a saved
// walk chooses every byte of it, so no format may draw one raw.
func TestRunFromHostile(t *testing.T) {
	const hostile = `{"schema_version": 4,
		"question": {"name": "x.", "type": "A\n---\nflowchart LR\n\u001b]0;pwned\u0007", "class": "IN\u001b[8m"},
		"started": "2026-09-24T12:00:00Z", "elapsed_ms": 1,
		"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "answer",
			"rcode": "NOERROR\u001b[2K\u001b[1A\r", "proto": "udp\u001b[41m",
			"asked": {"name": "x.", "type": "A\u001b[7m", "class": "IN"},
			"start_ms": 0, "rtt_ms": 1,
			"server": {"name": "a.root-servers.net.", "ip": "192.0.2.1", "port": 53},
			"records": [{"name": "x.", "ttl": 60, "type": "A\u001b[8m", "data": "192.0.2.1"}],
			"extended": [{"code": 15, "reason": "Blocked\u001b[5m\u00e9"}],
			"dnssec": {"state": "secure", "zone": ".", "algorithm": "ED25519\u001b[41m", "digest": "ab\u001b[0m",
				"signal": {"state": "pending", "reason": "x\u001b[7m"},
				"keys": [{"tag": 1, "algorithm": "RSASHA1\u001b[41m", "sep": true, "bits": 1024}],
				"ds": [{"tag": 2, "algorithm": "ED25519\u001b[41m", "digest": "SHA1\u001b[0m", "match": "unmatched"},
					{"tag": 3, "algorithm": "ED25519", "digest": "SHA1", "match": "matched"},
					{"tag": 3, "algorithm": "ED25519", "digest": "SHA256\u001b[41m", "match": "matched"}]}}]}}`

	for _, args := range [][]string{
		{"--color", "never", "--explain"},
		{"--color", "always"},
		{"--format", "ascii", "--explain"},
		{"--format", "json"},
		{"--format", "dot"},
		{"--format", "mermaid"},
		{"--format", "openmetrics"},
		{"--format", "waterfall", "--color", "always"},
		{"--format", "waterfall-ascii", "--explain"},
		{"--format", "waterfall-mermaid"},
		{"--format", "markdown"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			previous := stdin
			t.Cleanup(func() { stdin = previous })
			stdin = strings.NewReader(hostile)

			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), append([]string{"--from", "-"}, args...), &stdout, &stderr); code != exitAnswer {
				t.Fatalf("got exit %d, want %d: %s", code, exitAnswer, stderr.String())
			}
			out := stdout.String()
			if slices.Contains(args, "always") {
				// Only the palette's own colours may stay; the file's are not in it.
				out = regexp.MustCompile("\x1b\\[(0|1|3[1-5]|90)m").ReplaceAllString(out, "")
			}
			if strings.ContainsAny(out, "\x1b\x07\r") || strings.Contains(out, `\u001b`) {
				t.Errorf("got an escape through:\n%q", out)
			}
			if strings.HasSuffix(args[1], "ascii") && strings.ContainsFunc(out, func(r rune) bool { return r > 127 }) {
				t.Errorf("got a rune above 127 in --format ascii:\n%q", out)
			}
			if args[1] == "mermaid" && strings.Count(out, "\nflowchart LR\n") != 1 {
				t.Errorf("got the front matter broken out of:\n%s", out)
			}
			if args[1] == "waterfall-mermaid" && strings.Count(out, "\ngantt\n") != 1 {
				t.Errorf("got the front matter broken out of:\n%s", out)
			}
		})
	}
}

// TestRunFromStdin reads the saved walk from the standard input.
func TestRunFromStdin(t *testing.T) {
	previous := stdin
	t.Cleanup(func() { stdin = previous })
	stdin = strings.NewReader(`{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
		"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "nxdomain", "rcode": "NXDOMAIN",
		"server": {"name": "a.root-servers.net.", "ip": "192.0.2.1", "port": 53}}]}}`)

	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"--from", "-", "--color", "never"}, &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d: %s", code, exitAnswer, stderr.String())
	}
	if !strings.Contains(stdout.String(), "a.root-servers.net. 192.0.2.1") {
		t.Errorf("got\n%s\nwant the saved hop drawn", stdout.String())
	}
}

func TestRunSeveral(t *testing.T) {
	// lame. is delegated back to the root's own server, which only ever
	// refers the walk to itself again.
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone + `
lame.               IN NS   a.root-servers.net.
`})
	hints := rootHintsFile(t)
	common := []string{"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--no-compare", "--color", "never"}

	tests := map[string]struct {
		args  []string
		names string
		want  int
		trees int
		heads []string
	}{
		"several types of one name, all answered": {
			args: []string{".", "NS", "SOA"}, want: exitAnswer, trees: 2, heads: []string{". NS\n", ". SOA\n"},
		},
		"a lame delegation among names that answer": {
			args: []string{"--names", "-"}, names: "# the root, then a lame delegation\n. NS\nlame.\n",
			want: exitNoAnswer, trees: 2, heads: []string{". NS\n", "lame. A\n"},
		},
		"a type nobody has, refused before anything is walked": {
			args: []string{".", "NS", "NONSENSE"}, want: exitUsage,
		},
		"a name that is not one, refused before anything is walked": {
			args: []string{"--names", "-"}, names: ". NS\nexample..com\n", want: exitUsage,
		},
		"a file with a line that cannot be read": {
			args: []string{"--names", "-"}, names: ". NS\n. AXFR\n", want: exitUsage,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			previous := stdin
			t.Cleanup(func() { stdin = previous })
			stdin = strings.NewReader(test.names)

			var stdout, stderr bytes.Buffer
			code := run(t.Context(), append(slices.Clone(common), test.args...), &stdout, &stderr)
			if code != test.want {
				t.Fatalf("got exit %d, want %d: %s%s", code, test.want, stdout.String(), stderr.String())
			}
			if got := strings.Count(stdout.String(), ". (root)\n"); got != test.trees {
				t.Errorf("got %d trees, want %d:\n%s", got, test.trees, stdout.String())
			}
			for _, head := range test.heads {
				if !strings.Contains(stdout.String(), head) {
					t.Errorf("got\n%s\nwant a tree headed %q", stdout.String(), head)
				}
			}
		})
	}
}

// TestReportWithNoAgent covers a broken zone that names nobody to tell. Nothing
// is sent, and the run that asked for a report says so rather than nothing.
func TestReportWithNoAgent(t *testing.T) {
	root := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone, DNSSEC: true,
		Behaviour: fakens.Behaviour{BadSignature: true}})

	anchors := filepath.Join(t.TempDir(), "anchors")
	if err := os.WriteFile(anchors, []byte(root.Anchors(t)[0].String()+"\n"), 0o600); err != nil {
		t.Fatalf("writing the anchors: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"--root-hints", rootHintsFile(t), "--port", strconv.Itoa(int(root.Addr.Port())),
		"--trust-anchors", anchors, "--dnssec", "--no-asn", "--no-compare", "--report", "nothing.", "A"}, &stdout, &stderr)
	if code != exitBogus {
		t.Fatalf("got exit %d, want %d: %s%s", code, exitBogus, stdout.String(), stderr.String())
	}
	if want := "report: not sent: . names no agent to report to"; !strings.Contains(stderr.String(), want) {
		t.Errorf("got %q on stderr, want %q", stderr.String(), want)
	}
}

// TestReport covers --report end to end: a root whose signatures do not hold
// names an agent, and the report reaches the recursive server --resolver names
// as the lookup RFC 9567 builds, once, and is drawn under the tree.
func TestReport(t *testing.T) {
	root := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone, DNSSEC: true,
		Behaviour: fakens.Behaviour{BadSignature: true, ReportAgent: "agent.example."}})
	resolver := fakens.New(t, fakens.Config{Origin: "example.", Zone: "@ IN SOA ns hostmaster 1 7200 3600 1209600 3600\n"})

	anchors := filepath.Join(t.TempDir(), "anchors")
	if err := os.WriteFile(anchors, []byte(root.Anchors(t)[0].String()+"\n"), 0o600); err != nil {
		t.Fatalf("writing the anchors: %v", err)
	}

	for name, test := range map[string]struct {
		report bool
		sent   int
	}{
		"sent when asked for": {report: true, sent: 1},
		"never unasked":       {},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(resolver.Queries())
			args := []string{"--root-hints", rootHintsFile(t), "--port", strconv.Itoa(int(root.Addr.Port())),
				"--trust-anchors", anchors, "--dnssec", "--no-asn", "--no-compare"}
			if test.report {
				args = append(args, "--report", "--resolver", resolver.Addr.String())
			}
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), append(args, "nothing.", "A"), &stdout, &stderr); code != exitBogus {
				t.Fatalf("got exit %d, want %d: %s%s", code, exitBogus, stdout.String(), stderr.String())
			}

			var sent []string
			for _, query := range resolver.Queries()[before:] {
				sent = append(sent, query.Name)
			}
			if len(sent) != test.sent || (test.sent > 0 && sent[0] != "_er.1.nothing.6._er.agent.example.") {
				t.Errorf("got %q sent to the resolver, want %d report", sent, test.sent)
			}
			out := stdout.String()
			if !strings.Contains(out, "report → agent.example.") {
				t.Errorf("got %q, want the agent drawn on the hop", out)
			}
			if told := strings.Contains(out, "report: told agent.example."); told != test.report {
				t.Errorf("got %q, want the report drawn only where one was sent", out)
			}
		})
	}
}

// TestRunPcap captures two walks into one file, with the nameserver of the
// zone truncating every answer over UDP: each query it was sent appears in the
// capture, over whichever protocol carried it, and nothing else does.
func TestRunPcap(t *testing.T) {
	root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: splitRootZone})
	child := fakens.New(t, fakens.Config{Name: "ns.test.", Origin: "test.", Zone: splitChildZone,
		Behaviour: fakens.Behaviour{TruncateUDP: true}})
	path := filepath.Join(t.TempDir(), "walk.pcap")

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{
		"--root", "a.root-servers.net@" + root.Addr.String(),
		"--port", strconv.Itoa(int(child.Addr.Port())),
		"--pcap", path,
		"--no-asn", "--no-compare", "--color", "never", "www.test", "A", "AAAA",
	}, &stdout, &stderr)
	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the capture: %v", err)
	}
	if len(data) < 24 || !bytes.Equal(data[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) {
		t.Fatalf("got no pcap header: % x", data[:min(len(data), 24)])
	}

	// A query is a packet from dnstree's side with something in it: a
	// datagram, or a segment past the handshake.
	asked := map[string]int{}
	for rest := data[24:]; len(rest) >= 16; {
		size := int(rest[8]) | int(rest[9])<<8 | int(rest[10])<<16 | int(rest[11])<<24
		pkt := rest[16 : 16+size]
		rest = rest[16+size:]
		if !bytes.Equal(pkt[12:16], []byte{192, 0, 2, 1}) {
			continue
		}
		switch body := pkt[20:]; pkt[9] {
		case 17:
			asked["udp"]++
		case 6:
			if len(body) > int(body[12]>>4)*4 {
				asked["tcp"]++
			}
		}
	}

	want := map[string]int{}
	for _, server := range []*fakens.Server{root, child} {
		for _, query := range server.Queries() {
			want[query.Proto]++
		}
	}
	if want["tcp"] == 0 {
		t.Fatalf("got no query retried over tcp, which the test is about: %v", want)
	}
	if !maps.Equal(asked, want) {
		t.Errorf("got %v queries in the capture, want the %v the servers saw", asked, want)
	}
}

// TestRunRDAP asks a registry of its own about the domain of the walk, and
// holds the registration to what --expect asked of it.
func TestRunRDAP(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone + "www.example.test. IN A 192.0.2.1\n"})
	expires := time.Now().Add(10*24*time.Hour + time.Hour).UTC().Format(time.RFC3339)

	var registry *httptest.Server
	registry = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dns.json":
			fmt.Fprintf(w, `{"services":[[["test"],["%s/"]]]}`, registry.URL)
		case "/domain/example.test":
			fmt.Fprintf(w, `{"status":["active"],"events":[{"eventAction":"expiration","eventDate":%q}]}`, expires)
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	rdapBootstrap, rdapHTTP = registry.URL+"/dns.json", registry.Client()
	defer func() { rdapBootstrap, rdapHTTP = rdap.Bootstrap, nil }()

	tests := map[string]struct {
		args []string
		code int
		err  string
	}{
		"a registration with the time asked for left": {
			args: []string{"--expect", "registered:7d"},
			code: exitAnswer,
		},
		"a registration that runs out sooner than asked": {
			args: []string{"--expect", "registered:30d"},
			code: exitExpect,
			err:  "expected registered:30d, got example.test. running out in 10 days",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--root", server.Addr.String(), "--no-asn", "--no-compare", "--color", "never", "--rdap"},
				append(tt.args, "www.example.test", "A")...)
			if code := run(t.Context(), args, &stdout, &stderr); code != tt.code {
				t.Fatalf("got exit %d, want %d\n%s%s", code, tt.code, stdout.String(), stderr.String())
			}
			if want := "rdap: example.test. runs out in 10 days, on "; !strings.Contains(stdout.String(), want) {
				t.Errorf("got\n%s\nwant a line saying %q", stdout.String(), want)
			}
			if !strings.Contains(stderr.String(), tt.err) {
				t.Errorf("got stderr %q, want %q", stderr.String(), tt.err)
			}
		})
	}
}

// TestRunMail checks the mail path of a name, and draws it again from the walk
// --format json saved.
func TestRunMail(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone + `
example.test.             IN MX   10 mx.example.test.
mx.example.test.          IN A    192.0.2.25
_25._tcp.mx.example.test. IN TLSA 3 1 1 e41cc7633029afdba53744d7e5fc31ef507e592de9dfb33557bf3b9a79239446
_dmarc.example.test.      IN TXT  "v=DMARC1; p=reject"
`})
	base := []string{"--root", server.Addr.String(), "--no-asn", "--no-compare", "--color", "never"}
	want := []string{
		"mail: 1 MX host for example.test.",
		"mail:   10 mx.example.test. unchecked (1 TLSA record): nothing was checked without --dnssec",
		"mail: no mta-sts; no tls-rpt; dmarc p=reject",
		"mail: dane not checked: add --dnssec",
	}
	drawn := func(out string) []string {
		var lines []string
		for line := range strings.Lines(out) {
			if strings.HasPrefix(line, "mail: ") {
				lines = append(lines, strings.TrimSuffix(line, "\n"))
			}
		}
		return lines
	}

	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), append(base, "--mail", "example.test", "A"), &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if got := drawn(stdout.String()); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	stdout.Reset()
	if code := run(t.Context(), append(base, "--mail", "--format", "json", "example.test", "A"), &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s", code, exitAnswer, stderr.String())
	}
	path := filepath.Join(t.TempDir(), "walk.json")
	if err := os.WriteFile(path, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := run(t.Context(), []string{"--from", path, "--color", "never"}, &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s", code, exitAnswer, stderr.String())
	}
	if got := drawn(stdout.String()); !slices.Equal(got, want) {
		t.Errorf("got %q drawn again, want %q", got, want)
	}
}

// TestRunTLSA connects to the mail servers of a signed mail path, one that
// presents the key its TLSA record names and one renewed without its record,
// and draws what each presented again from the walk --format json saved.
func TestRunTLSA(t *testing.T) {
	now := time.Now()
	current := fakemx.Issue(t, nil, false, now.AddDate(0, 0, -7), now.AddDate(0, 3, 0), "mx1.example.test")
	renewed := fakemx.Issue(t, nil, false, now.AddDate(0, 0, -1), now.AddDate(0, 3, 0), "mx2.example.test")
	retired := fakemx.Issue(t, nil, false, now.AddDate(0, -3, 0), now, "mx2.example.test")
	root := fakens.New(t, fakens.Config{Origin: ".", DNSSEC: true, Zone: rootZone + `
example.test.              IN MX   10 mx1.example.test.
example.test.              IN MX   20 mx2.example.test.
mx1.example.test.          IN A    192.0.2.25
mx2.example.test.          IN A    192.0.2.26
_25._tcp.mx1.example.test. IN TLSA 3 1 1 ` + fakemx.Digest(current.Cert, 1, 1) + `
_25._tcp.mx2.example.test. IN TLSA 3 1 1 ` + fakemx.Digest(retired.Cert, 1, 1) + `
`})
	servers := map[netip.AddrPort]netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.25:25"): fakemx.Serve(t, fakemx.Honest, current.Key, current.Cert),
		netip.MustParseAddrPort("192.0.2.26:25"): fakemx.Serve(t, fakemx.Honest, renewed.Key, renewed.Cert),
	}
	tlsaDial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", servers[addr].String())
	}
	defer func() { tlsaDial = nil }()

	anchors := filepath.Join(t.TempDir(), "anchors")
	if err := os.WriteFile(anchors, []byte(root.Anchors(t)[0].String()+"\n"), 0o600); err != nil {
		t.Fatalf("writing the anchors: %v", err)
	}
	base := []string{"--root", root.Addr.String(), "--trust-anchors", anchors, "--dnssec", "--mail", "--tlsa",
		"--no-asn", "--no-compare", "--color", "never"}
	issued := func(cert fakemx.Issued) string { return cert.Cert.NotBefore.UTC().Format(time.DateOnly) }
	want := []string{
		"mail:     192.0.2.25 match: 3 1 1 " + fakemx.Digest(current.Cert, 1, 1)[:8] + "... matches CN=mx1.example.test, issued " + issued(current),
		"mail:     192.0.2.26 mismatch: no TLSA record matches the certificate or key it presents; CN=mx2.example.test, issued " + issued(renewed),
		"mail: dane covers 2 of 2 MX hosts, but mx2.example.test. presents what a sender that checks it refuses",
	}
	drawn := func(out string) []string {
		var lines []string
		for line := range strings.Lines(out) {
			if strings.HasPrefix(line, "mail:     ") || strings.HasPrefix(line, "mail: dane") {
				lines = append(lines, strings.TrimSuffix(line, "\n"))
			}
		}
		return lines
	}

	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), append(base, "example.test", "A"), &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if got := drawn(stdout.String()); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if warning := "mx2.example.test. at 192.0.2.26 presents a certificate issued " + issued(renewed) + " that no TLSA record of its matches"; !strings.Contains(stdout.String(), warning) {
		t.Errorf("got\n%s\nwant a warning saying %q", stdout.String(), warning)
	}

	stdout.Reset()
	if code := run(t.Context(), append(base, "--format", "json", "example.test", "A"), &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s", code, exitAnswer, stderr.String())
	}
	path := filepath.Join(t.TempDir(), "walk.json")
	if err := os.WriteFile(path, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	tlsaDial = func(context.Context, netip.AddrPort) (net.Conn, error) {
		t.Error("a walk drawn again connected to a mail server")
		return nil, errors.New("no")
	}
	stdout.Reset()
	if code := run(t.Context(), []string{"--from", path, "--color", "never"}, &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s", code, exitAnswer, stderr.String())
	}
	if got := drawn(stdout.String()); !slices.Equal(got, want) {
		t.Errorf("got %q drawn again, want %q", got, want)
	}
}

// TestRunSVCB follows a name's HTTPS records to the server they name, and
// draws the path again from the walk --format json saved.
func TestRunSVCB(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone + `
example.test.      IN HTTPS 0 cdn.example.test.
cdn.example.test.  IN HTTPS 1 edge.example.test. alpn="h3" ipv4hint="192.0.2.1"
edge.example.test. IN A     192.0.2.7
`})
	base := []string{"--root", server.Addr.String(), "--no-asn", "--no-compare", "--color", "never", "-4"}
	want := []string{
		"svcb: example.test. HTTPS 0 cdn.example.test.",
		`svcb: cdn.example.test. HTTPS 1 edge.example.test. alpn="h3" ipv4hint="192.0.2.1"`,
		"svcb:   edge.example.test. 192.0.2.7; hint 192.0.2.1 is not among them",
	}
	drawn := func(out string) []string {
		var lines []string
		for line := range strings.Lines(out) {
			if strings.HasPrefix(line, "svcb: ") {
				lines = append(lines, strings.TrimSuffix(line, "\n"))
			}
		}
		return lines
	}

	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), append(base, "--svcb", "example.test"), &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if got := drawn(stdout.String()); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if !strings.Contains(stdout.String(), "hint at 192.0.2.1, which is not among its addresses") {
		t.Errorf("got\n%s\nwant the stray hint warned about", stdout.String())
	}

	stdout.Reset()
	if code := run(t.Context(), append(base, "--svcb", "--format", "json", "example.test", "HTTPS"), &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s", code, exitAnswer, stderr.String())
	}
	path := filepath.Join(t.TempDir(), "walk.json")
	if err := os.WriteFile(path, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := run(t.Context(), []string{"--from", path, "--color", "never"}, &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s", code, exitAnswer, stderr.String())
	}
	if got := drawn(stdout.String()); !slices.Equal(got, want) {
		t.Errorf("got %q drawn again, want %q", got, want)
	}
}

// TestRunCheck grades a zone whose servers echo an EDNS flag back and whose NS
// set lists a server the delegation does not, and holds it to --expect: both
// are worth a look, and neither is broken.
func TestRunCheck(t *testing.T) {
	root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: `
@                     IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                     IN NS   a.root-servers.net.
a.root-servers.net.   IN A    127.0.0.1
example.test.         IN NS   ns.example.test.
ns.example.test.      IN A    127.0.0.1
`})
	child := fakens.New(t, fakens.Config{Name: "ns.example.test.", Origin: "example.test.", Zone: `
@     IN SOA  ns hostmaster 7 7200 3600 1209600 3600
@     IN NS   ns
@     IN NS   ns2
@     IN TXT  "v=spf1 -all"
ns    IN A    127.0.0.1
ns2   IN A    127.0.0.1
www   IN A    192.0.2.10
`, Behaviour: fakens.Behaviour{EchoEDNSFlags: true}})

	var registry *httptest.Server
	registry = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dns.json":
			fmt.Fprintf(w, `{"services":[[["test"],["%s/"]]]}`, registry.URL)
		case "/domain/example.test":
			fmt.Fprintf(w, `{"status":["active"],"nameservers":[{"ldhName":"ns.example.test"}],"events":[{"eventAction":"expiration","eventDate":%q}]}`,
				time.Now().Add(400*24*time.Hour).UTC().Format(time.RFC3339))
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	rdapBootstrap, rdapHTTP = registry.URL+"/dns.json", registry.Client()
	defer func() { rdapBootstrap, rdapHTTP = rdap.Bootstrap, nil }()

	base := []string{
		"--root", "a.root-servers.net@" + root.Addr.String(),
		"--port", strconv.Itoa(int(child.Addr.Port())), "--resolver", child.Addr.String(),
		"--no-asn", "--no-compare", "--color", "never", "--format", "ascii", "--check",
	}
	tests := map[string]struct {
		args []string
		code int
		err  string
	}{
		"nothing broken, which check:ok asks": {
			args: []string{"--expect", "check:ok"},
			code: exitAnswer,
		},
		"something to look at, which check:clean refuses": {
			args: []string{"--expect", "check:clean"},
			code: exitExpect,
			err:  "expected check:clean, got delegation look, dnssec look, servers look and 1 more",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(slices.Clone(base), append(tt.args, "www.example.test", "A")...)
			if code := run(t.Context(), args, &stdout, &stderr); code != tt.code {
				t.Fatalf("got exit %d, want %d\n%s%s", code, tt.code, stdout.String(), stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"check example.test.",
				"  ok answer        www.example.test. A is 192.0.2.10",
				"  !! delegation    example.test. lists ns2.example.test., which the delegation does not carry",
				"  ok consistency   every nameserver asked serves one copy of example.test., serial 7 (1 nameserver, 1 address)",
				"  !! dnssec        the chain of trust at . could not be checked",
				"  !! servers       example.test. is delegated to one nameserver",
				"  !! edns          ns.example.test. (127.0.0.1) did not ignore an EDNS flag nobody has defined",
				"  -- strangers     not asked; --check-axfr and --check-recursion",
				"  ok registration  ",
				"4 to look at | 5 passed | 1 skipped",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("got no %q:\n%s", want, out)
				}
			}
			if !strings.Contains(stderr.String(), tt.err) {
				t.Errorf("got stderr %q, want %q", stderr.String(), tt.err)
			}
		})
	}
}

// TestRunSPFOutOfTime covers --spf asking a resolver that never answers: the
// tree is drawn once the walk and a short grace are over, rather than after
// every lookup has spent its whole timeout.
func TestRunSPFOutOfTime(t *testing.T) {
	root := fakens.New(t, fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: `
@                     IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                     IN NS   a.root-servers.net.
a.root-servers.net.   IN A    127.0.0.1
example.test.         IN NS   ns.example.test.
ns.example.test.      IN A    127.0.0.1
`})
	child := fakens.New(t, fakens.Config{Name: "ns.example.test.", Origin: "example.test.", Zone: `
@     IN SOA  ns hostmaster 7 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    127.0.0.1
www   IN A    192.0.2.10
`})
	silent := fakens.New(t, fakens.Config{Name: "resolver.", Origin: ".", Zone: `
@     IN SOA  resolver. hostmaster 1 7200 3600 1209600 3600
`, Behaviour: fakens.Behaviour{Drop: true}})

	spfGrace = 100 * time.Millisecond
	defer func() { spfGrace = defaultSPFGrace }()

	var stdout, stderr bytes.Buffer
	args := []string{
		"--root", "a.root-servers.net@" + root.Addr.String(),
		"--port", strconv.Itoa(int(child.Addr.Port())), "--resolver", silent.Addr.String(),
		"--no-asn", "--no-compare", "--color", "never", "--format", "ascii",
		"--timeout", "10s", "--spf", "www.example.test", "A",
	}
	start := time.Now()
	if code := run(t.Context(), args, &stdout, &stderr); code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("took %v, want the tree drawn soon after the walk", took)
	}
	if !strings.Contains(stdout.String(), "ran out of time") {
		t.Errorf("got no word of the time running out:\n%s", stdout.String())
	}
}
