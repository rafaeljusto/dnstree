package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/cli"
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
