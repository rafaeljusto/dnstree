package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/cli"
	"github.com/rafaeljusto/dnstree/internal/history"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
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

// TestRunWeb covers the format that draws nothing: the walk is served instead,
// the address is printed where somebody can open it, and interrupting the run
// is what takes it down.
func TestRunWeb(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: ".", Zone: rootZone})
	hints := rootHintsFile(t)

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	out := new(served)
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{
			"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
			"--no-asn", "--no-compare", "--format", "web",
			"--web-addr", "127.0.0.1:0", "--no-browser", "--explain", ".", "NS",
		}, out, io.Discard)
	}()

	base := out.address(t)
	answer, err := http.Get(base + "page.json")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
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
}

// served is what the command writes while it is still running, which is where
// the address of the page appears.
type served struct {
	mutex sync.Mutex
	buf   bytes.Buffer
}

func (s *served) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.buf.Write(p)
}

func (s *served) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.buf.String()
}

func (s *served) address(tb testing.TB) string {
	tb.Helper()

	found := regexp.MustCompile(`http://[^\s]+/`)
	for range 400 {
		if at := found.FindString(s.String()); at != "" {
			return at
		}
		time.Sleep(10 * time.Millisecond)
	}
	tb.Fatalf("got %q, want the address of the page in it", s.String())
	return ""
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
// to and the code it ends with. Nothing reads the buffers until the code has
// arrived, which is what makes reading them safe.
func watching(ctx context.Context, tb testing.TB, args ...string) (code <-chan int, out, errs *bytes.Buffer) {
	tb.Helper()

	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
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

	time.Sleep(400 * time.Millisecond)
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

	code, _, stderr := watching(t.Context(), t,
		"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--no-compare", "--color", "never", "--watch", "1s",
		"--expect", "192.0.2.2", "www.test", "A")

	time.Sleep(1500 * time.Millisecond)
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

	code, _, stderr := watching(ctx, t,
		"--root-hints", hints, "--port", strconv.Itoa(int(server.Addr.Port())),
		"--no-asn", "--no-compare", "--color", "never", "--watch", "1s",
		"--expect", "192.0.2.2", "www.test", "A")

	time.Sleep(1500 * time.Millisecond)
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
		"held to what was expected of it": {
			args: []string{"--from", path, "--expect", "nxdomain"},
			code: exitExpect, want: "expected nxdomain, got answer",
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
			"server": {"name": "a.root-servers.net.", "ip": "192.0.2.1", "port": 53},
			"records": [{"name": "x.", "ttl": 60, "type": "A\u001b[8m", "data": "192.0.2.1"}],
			"extended": [{"code": 15, "reason": "Blocked\u001b[5m\u00e9"}],
			"dnssec": {"state": "secure", "algorithm": "ED25519\u001b[41m", "digest": "ab\u001b[0m",
				"signal": {"state": "pending", "reason": "x\u001b[7m"}}}]}}`

	for _, args := range [][]string{
		{"--color", "never", "--explain"},
		{"--color", "always"},
		{"--format", "ascii", "--explain"},
		{"--format", "json"},
		{"--format", "dot"},
		{"--format", "mermaid"},
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
			if args[0] == "--color" && args[1] == "always" {
				// Only the palette's own colours may stay; the file's are not in it.
				out = regexp.MustCompile("\x1b\\[(0|1|3[1-5]|90)m").ReplaceAllString(out, "")
			}
			if strings.ContainsAny(out, "\x1b\x07\r") || strings.Contains(out, `\u001b`) {
				t.Errorf("got an escape through:\n%q", out)
			}
			if args[1] == "ascii" && strings.ContainsFunc(out, func(r rune) bool { return r > 127 }) {
				t.Errorf("got a rune above 127 in --format ascii:\n%q", out)
			}
			if args[1] == "mermaid" && strings.Count(out, "\nflowchart LR\n") != 1 {
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
