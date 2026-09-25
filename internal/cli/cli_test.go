package cli_test

import (
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/cli"
	"github.com/rafaeljusto/dnstree/internal/expect"
	"github.com/rafaeljusto/dnstree/internal/render/tree"
)

func TestParse(t *testing.T) {
	tests := map[string]struct {
		args []string
		want cli.Config
	}{
		"a name is enough": {
			args: []string{"example.com"},
			want: cli.Config{Name: "example.com", Type: "A"},
		},
		"a type as well": {
			args: []string{"example.com", "mx"},
			want: cli.Config{Name: "example.com", Type: "MX"},
		},
		"a walk to watch": {
			args: []string{"--format", "emoji", "--live", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "emoji", Live: true},
		},
		"a walk in a browser": {
			args: []string{"--format", "web", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "web", WebAddr: "127.0.0.1:0"},
		},
		"a walk served somewhere else": {
			args: []string{"--format", "web", "--web-addr", "0.0.0.0:8080", "--no-browser", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "web", WebAddr: "0.0.0.0:8080"},
		},
		"a walk explained": {
			args: []string{"--explain", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Explain: true},
		},
		"a walk held against the last one": {
			args: []string{"--diff", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Diff: true},
		},
		"the whole surface": {
			args: []string{
				"-6", "--dot", "--fallback", "--all", "--dnssec", "--check-ns", "--no-asn", "--no-compare",
				"--format", "json", "--color", "never", "--timeout", "5s", "--retries", "3",
				"--max-depth", "8", "--max-queries", "32", "--max-cname", "4", "--port", "5353",
				"--root-hints", "hints", "--trust-anchors", "anchors",
				"--tls-ca", "ca.pem", "--debug",
				"example.com", "ns",
			},
			want: cli.Config{
				Name: "example.com", Type: "NS", Family: 6, Proto: "dot",
				Fallback: true, All: true, DNSSEC: true, CheckNS: true,
				Format: "json", Color: tree.ColorNever, Timeout: 5 * time.Second,
				Retries: 3, MaxDepth: 8, MaxQueries: 32, MaxCNAME: 4, Port: 5353,
				RootHints: "hints", TrustAnchors: "anchors", TLSCA: "ca.pem", Debug: true,
			},
		},
		"a root named outright": {
			args: []string{"--root", "127.0.0.1", "example.com"},
			want: cli.Config{
				Name: "example.com", Type: "A",
				Roots: []cli.Root{{Addr: netip.MustParseAddrPort("127.0.0.1:0")}},
			},
		},
		"roots with names and ports": {
			args: []string{
				"--root", "a.root-servers.net@198.41.0.4:5353",
				"--root", "[::1]:5354",
				"example.com",
			},
			want: cli.Config{
				Name: "example.com", Type: "A",
				Roots: []cli.Root{
					{Name: "a.root-servers.net.", Addr: netip.MustParseAddrPort("198.41.0.4:5353")},
					{Addr: netip.MustParseAddrPort("[::1]:5354")},
				},
			},
		},
		"a recursive server of its own": {
			args: []string{"--resolver", "192.0.2.1", "example.com"},
			want: cli.Config{
				Name: "example.com", Type: "A",
				Resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")},
			},
		},
		"several of them, in the order they were named": {
			args: []string{"--resolver", "192.0.2.1", "--resolver", "192.0.2.2:5353", "example.com"},
			want: cli.Config{
				Name: "example.com", Type: "A",
				Resolvers: []netip.AddrPort{
					netip.MustParseAddrPort("192.0.2.1:53"),
					netip.MustParseAddrPort("192.0.2.2:5353"),
				},
			},
		},
		"the older name for it": {
			args: []string{"--asn-resolver", "192.0.2.1", "example.com"},
			want: cli.Config{
				Name: "example.com", Type: "A",
				Resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")},
			},
		},
		"no question put to a resolver": {
			args: []string{"--no-compare", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A"},
		},
		"a walk that minimises its questions": {
			args: []string{"--qmin", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Minimise: true},
		},
		"a chart for a wiki": {
			args: []string{"--format", "mermaid", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "mermaid"},
		},
		"a walk already made needs no name": {
			args: []string{"--from", "walk.json"},
			want: cli.Config{From: "walk.json"},
		},
		"a walk already made, explained and held to a lifetime": {
			args: []string{"--from", "-", "--explain", "--expect", "fresh:3d", "--format", "emoji"},
			want: cli.Config{From: "-", Explain: true, Format: "emoji", Expect: expectations(t, "fresh:3d")},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// The defaults nothing in the table sets.
			want := test.want
			if want.Proto == "" {
				want.Proto, want.Color, want.Timeout, want.Retries = "udp", tree.ColorAuto, 2*time.Second, 1
			}
			if want.Format == "" {
				want.Format = "tree"
			}
			given := strings.Join(test.args, " ")
			if !strings.Contains(given, "--no-asn") {
				want.ASN = true
			}
			if !strings.Contains(given, "--no-compare") {
				want.Compare = true
			}
			if !strings.Contains(given, "--no-browser") {
				want.Browser = true
			}

			got, err := cli.Parse(test.args, io.Discard)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(*got, want) {
				t.Errorf("got  %+v\nwant %+v", *got, want)
			}
		})
	}
}

// expectations reads --expect values the way the command line does.
func expectations(tb testing.TB, values ...string) []expect.Expectation {
	tb.Helper()

	var want []expect.Expectation
	for _, value := range values {
		expectation, err := expect.Parse(value)
		if err != nil {
			tb.Fatalf("expect.Parse(%q): %v", value, err)
		}
		want = append(want, expectation)
	}
	return want
}

func TestParseRejects(t *testing.T) {
	tests := map[string][]string{
		"nothing to resolve":              {},
		"too many arguments":              {"example.com", "A", "please"},
		"two address families":            {"-4", "-6", "example.com"},
		"two transports":                  {"--udp", "--doh", "example.com"},
		"an unknown format":               {"--format", "runes", "example.com"},
		"live json":                       {"--format", "json", "--live", "example.com"},
		"live dot":                        {"--format", "dot", "--live", "example.com"},
		"live web":                        {"--format", "web", "--live", "example.com"},
		"watched json":                    {"--format", "json", "--watch", "30s", "example.com"},
		"watched dot":                     {"--format", "dot", "--watch", "30s", "example.com"},
		"watched web":                     {"--format", "web", "--watch", "30s", "example.com"},
		"a watch tighter than a second":   {"--watch", "100ms", "example.com"},
		"a watch of no time at all":       {"--watch", "-1s", "example.com"},
		"a page nobody serves":            {"--web-addr", "127.0.0.1:8080", "example.com"},
		"a browser for a tree":            {"--no-browser", "example.com"},
		"explained json":                  {"--format", "json", "--explain", "example.com"},
		"explained dot":                   {"--format", "dot", "--explain", "example.com"},
		"compared json":                   {"--format", "json", "--diff", "example.com"},
		"compared dot":                    {"--format", "dot", "--diff", "example.com"},
		"live mermaid":                    {"--format", "mermaid", "--live", "example.com"},
		"watched mermaid":                 {"--format", "mermaid", "--watch", "30s", "example.com"},
		"explained mermaid":               {"--format", "mermaid", "--explain", "example.com"},
		"compared mermaid":                {"--format", "mermaid", "--diff", "example.com"},
		"a walk already made, and a name": {"--from", "walk.json", "example.com"},
		"a walk already made, drawn live": {"--from", "walk.json", "--live"},
		"a walk already made, watched":    {"--from", "walk.json", "--watch", "30s"},
		"a walk already made, remembered": {"--from", "walk.json", "--diff"},
		"a walk already made, re-checked": {"--dnssec", "--from", "walk.json"},
		"a walk already made, re-asked":   {"--from", "walk.json", "--qmin", "--timeout", "3s"},
		"a lifetime that is not one":      {"--expect", "fresh:soon", "example.com"},
		"an unknown colour":               {"--color", "sometimes", "example.com"},
		"a timeout of nothing":            {"--timeout", "0", "example.com"},
		"a negative retry count":          {"--retries", "-1", "example.com"},
		"a port beyond the range":         {"--port", "70000", "example.com"},
		"a flag nobody has":               {"--recursive", "example.com"},
		"help":                            {"--help"},

		"two ways to start a walk":      {"--root", "127.0.0.1", "--root-hints", "hints", "example.com"},
		"a root that is no address":     {"--root", "localhost", "example.com"},
		"a root with no address":        {"--root", "ns.example.com@", "example.com"},
		"a root with a bad port":        {"--root", "127.0.0.1:70000", "example.com"},
		"a resolver that is no address": {"--resolver", "cymru.com", "example.com"},
		"a resolver with nothing to answer": {
			"--no-asn", "--no-compare", "--resolver", "192.0.2.1", "example.com",
		},
		"TLS settings with no TLS":  {"--tls-insecure", "example.com"},
		"a CA with nothing to sign": {"--dot", "--tls-ca", "ca.pem", "--tls-insecure", "example.com"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := cli.Parse(args, io.Discard); !errors.Is(err, cli.ErrUsage) {
				t.Errorf("got error %v, want it to read as a usage problem", err)
			}
		})
	}
}

// TestParseSchema covers a flag that answers a question about the command
// rather than resolving a name: it needs no name, and the rest of the command
// line is never reached.
func TestParseSchema(t *testing.T) {
	cfg, err := cli.Parse([]string{"--schema"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Schema || cfg.Name != "" {
		t.Errorf("got %+v, want the schema asked for and no name to resolve", *cfg)
	}
}

// TestParseUsage covers the help itself, which is the only documentation a
// reader has in front of them at the time.
func TestParseUsage(t *testing.T) {
	var out strings.Builder
	if _, err := cli.Parse(nil, &out); !errors.Is(err, cli.ErrUsage) {
		t.Fatalf("got error %v, want a usage problem", err)
	}

	for _, want := range []string{
		"usage: dnstree", "--dnssec", "--format", "--web-addr", "--no-browser",
		"--explain", "--diff", "--expect", "--schema", "Exit codes",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("got usage without %q:\n%s", want, out.String())
		}
	}
}
