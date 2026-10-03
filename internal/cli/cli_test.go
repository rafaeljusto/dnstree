package cli_test

import (
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/cli"
	"github.com/rafaeljusto/dnstree/v2/internal/expect"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
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
		"a name in another script, asked in punycode": {
			args: []string{"münchen.de", "mx"},
			want: cli.Config{Name: "xn--mnchen-3ya.de", Type: "MX"},
		},
		"a walk to watch": {
			args: []string{"--format", "emoji", "--live", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "emoji", Live: true},
		},
		"a walk in a browser": {
			args: []string{"--format", "web", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "web", WebAddr: "127.0.0.1:0"},
		},
		"a walk in a scene": {
			args: []string{"--format", "web-3d", "--no-browser", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "web-3d", WebAddr: "127.0.0.1:0"},
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
		"the PTR of an IPv4 address": {
			args: []string{"-x", "192.0.2.1"},
			want: cli.Config{Name: "1.2.0.192.in-addr.arpa.", Type: "PTR"},
		},
		"the PTR of an IPv6 address, nibble by nibble": {
			args: []string{"-x", "2001:db8::1"},
			want: cli.Config{Name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", Type: "PTR"},
		},
		"an IPv4 address written the IPv6 way is asked under in-addr.arpa.": {
			args: []string{"-x", "::ffff:192.0.2.1"},
			want: cli.Config{Name: "1.2.0.192.in-addr.arpa.", Type: "PTR"},
		},
		"a signed zone's request of its parent": {
			args: []string{"--dnssec", "--check-ds", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", DNSSEC: true, CheckDS: true},
		},
		"a walk that minimises its questions": {
			args: []string{"--qmin", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Minimise: true},
		},
		"a walk that asks the resolvers what encrypted resolvers they designate": {
			args: []string{"--ddr", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", DDR: true},
		},
		"a zone's nameservers asked for what they should keep": {
			args: []string{"--check-axfr", "--check-recursion", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", CheckAXFR: true, CheckRecursion: true},
		},
		"a walk that sends each server a cookie": {
			args: []string{"--cookie", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Cookie: true},
		},
		"a chart for a wiki": {
			args: []string{"--format", "mermaid", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "mermaid"},
		},
		"a timeline of the walk": {
			args: []string{"--format", "waterfall", "--explain", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "waterfall", Explain: true},
		},
		"a timeline for a document": {
			args: []string{"--format", "waterfall-ascii", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "waterfall-ascii"},
		},
		"a timeline for a wiki": {
			args: []string{"--format", "waterfall-mermaid", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "waterfall-mermaid"},
		},
		"a report for an incident, with what changed": {
			args: []string{"--format", "markdown", "--diff", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "markdown", Diff: true},
		},
		"numbers for a monitoring system": {
			args: []string{"--format", "openmetrics", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "openmetrics"},
		},
		"a walk already made needs no name": {
			args: []string{"--from", "walk.json"},
			want: cli.Config{From: "walk.json"},
		},
		"a walk already made, explained and held to a lifetime": {
			args: []string{"--from", "-", "--explain", "--expect", "fresh:3d", "--format", "emoji"},
			want: cli.Config{From: "-", Explain: true, Format: "emoji", Expect: expectations(t, "fresh:3d")},
		},
		"two walks already made, held against each other": {
			args: []string{"--from", "after.json", "--against", "before.json"},
			want: cli.Config{From: "after.json", Against: "before.json"},
		},
		"several types of one name": {
			args: []string{"example.com", "a", "aaaa", "mx"},
			want: cli.Config{Name: "example.com", Type: "A", More: []cli.Question{
				{Name: "example.com", Type: "AAAA"}, {Name: "example.com", Type: "MX"},
			}},
		},
		"several types, each remembered against its own last walk": {
			args: []string{"--diff", "--live", "münchen.de", "A", "AAAA"},
			want: cli.Config{Name: "xn--mnchen-3ya.de", Type: "A", Diff: true, Live: true,
				More: []cli.Question{{Name: "xn--mnchen-3ya.de", Type: "AAAA"}}},
		},
		"names from a file": {
			args: []string{"--names", "names.txt", "--format", "markdown"},
			want: cli.Config{Names: "names.txt", Format: "markdown"},
		},
		"a walk made now, held against one saved": {
			args: []string{"--against", "-", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Against: "-"},
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
		"nothing to resolve":                       {},
		"a lookup that is not one among several":   {"example.com", "A", "ANY"},
		"names from a file and a name as well":     {"--names", "names.txt", "example.com"},
		"names from a file and an address":         {"--names", "names.txt", "-x", "192.0.2.1"},
		"names from a file and a saved walk":       {"--names", "names.txt", "--from", "walk.json"},
		"several types written as one json":        {"--format", "json", "example.com", "A", "AAAA"},
		"several types served as one page":         {"--format", "web", "example.com", "A", "AAAA"},
		"several types measured as one":            {"--format", "openmetrics", "example.com", "A", "AAAA"},
		"several types held to one expectation":    {"--expect", "answer", "example.com", "A", "AAAA"},
		"several types held against one walk":      {"--against", "walk.json", "example.com", "A", "AAAA"},
		"several types watched":                    {"--watch", "30s", "example.com", "A", "AAAA"},
		"names from a file written as one json":    {"--format", "json", "--names", "names.txt"},
		"names from a file held to an expectation": {"--names", "-", "--expect", "answer"},
		"two address families":                     {"-4", "-6", "example.com"},
		"a name no punycode can spell":             {"\u202eexample.com"},
		"two transports":                           {"--udp", "--doh", "example.com"},
		"an unknown format":                        {"--format", "runes", "example.com"},
		"live json":                                {"--format", "json", "--live", "example.com"},
		"live dot":                                 {"--format", "dot", "--live", "example.com"},
		"live web":                                 {"--format", "web", "--live", "example.com"},
		"watched json":                             {"--format", "json", "--watch", "30s", "example.com"},
		"watched dot":                              {"--format", "dot", "--watch", "30s", "example.com"},
		"watched web":                              {"--format", "web", "--watch", "30s", "example.com"},
		"live web-3d":                              {"--format", "web-3d", "--live", "example.com"},
		"watched web-3d":                           {"--format", "web-3d", "--watch", "30s", "example.com"},
		"a watch tighter than a second":            {"--watch", "100ms", "example.com"},
		"a watch of no time at all":                {"--watch", "-1s", "example.com"},
		"a page nobody serves":                     {"--web-addr", "127.0.0.1:8080", "example.com"},
		"a browser for a tree":                     {"--no-browser", "example.com"},
		"explained json":                           {"--format", "json", "--explain", "example.com"},
		"explained dot":                            {"--format", "dot", "--explain", "example.com"},
		"compared json":                            {"--format", "json", "--diff", "example.com"},
		"compared dot":                             {"--format", "dot", "--diff", "example.com"},
		"live mermaid":                             {"--format", "mermaid", "--live", "example.com"},
		"watched mermaid":                          {"--format", "mermaid", "--watch", "30s", "example.com"},
		"explained mermaid":                        {"--format", "mermaid", "--explain", "example.com"},
		"compared mermaid":                         {"--format", "mermaid", "--diff", "example.com"},
		"live waterfall":                           {"--format", "waterfall", "--live", "example.com"},
		"watched waterfall":                        {"--format", "waterfall-ascii", "--watch", "30s", "example.com"},
		"explained gantt chart":                    {"--format", "waterfall-mermaid", "--explain", "example.com"},
		"a page for a waterfall":                   {"--format", "waterfall", "--no-browser", "example.com"},
		"live markdown":                            {"--format", "markdown", "--live", "example.com"},
		"watched markdown":                         {"--format", "markdown", "--watch", "30s", "example.com"},
		"live openmetrics":                         {"--format", "openmetrics", "--live", "example.com"},
		"watched openmetrics":                      {"--format", "openmetrics", "--watch", "30s", "example.com"},
		"explained openmetrics":                    {"--format", "openmetrics", "--explain", "example.com"},
		"compared openmetrics":                     {"--format", "openmetrics", "--diff", "example.com"},
		"a walk already made, and a name":          {"--from", "walk.json", "example.com"},
		"a walk already made, drawn live":          {"--from", "walk.json", "--live"},
		"a walk already made, watched":             {"--from", "walk.json", "--watch", "30s"},
		"a walk already made, remembered":          {"--from", "walk.json", "--diff"},
		"held against a file and the cache":        {"--against", "walk.json", "--diff", "example.com"},
		"both walks from the standard input":       {"--from", "-", "--against", "-"},
		"held against a walk, as json":             {"--format", "json", "--against", "walk.json", "example.com"},
		"a walk already made, re-checked":          {"--dnssec", "--from", "walk.json"},
		"a walk already made, re-asked":            {"--from", "walk.json", "--qmin", "--timeout", "3s"},
		"a walk already made, sent cookies":        {"--from", "walk.json", "--cookie"},
		"a walk already made, probed":              {"--from", "walk.json", "--check-axfr"},
		"a lifetime that is not one":               {"--expect", "fresh:soon", "example.com"},
		"a reverse lookup of no address":           {"-x", "example.com"},
		"a reverse lookup and a name":              {"-x", "192.0.2.1", "example.com"},
		"a reverse lookup and a type":              {"-x", "192.0.2.1", "A"},
		"a reverse lookup of a saved walk":         {"--from", "walk.json", "-x", "192.0.2.1"},
		"a request weighed unsigned":               {"--check-ds", "example.com"},
		"designations asked of no resolver":        {"--ddr", "--no-compare", "example.com"},
		"a walk already made, asked for ddr":       {"--from", "walk.json", "--ddr"},
		"an unknown colour":                        {"--color", "sometimes", "example.com"},
		"a timeout of nothing":                     {"--timeout", "0", "example.com"},
		"a negative retry count":                   {"--retries", "-1", "example.com"},
		"no zone cuts to follow":                   {"--max-depth", "0", "example.com"},
		"no queries to make":                       {"--max-queries", "0", "example.com"},
		"no aliases to chase":                      {"--max-cname", "0", "example.com"},
		"a negative budget":                        {"--max-queries", "-5", "example.com"},
		"a port beyond the range":                  {"--port", "70000", "example.com"},
		"a flag nobody has":                        {"--recursive", "example.com"},
		"help":                                     {"--help"},

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

		"ANY, which servers answer with a sample": {"example.com", "ANY"},
		"ANY in lowercase":                        {"example.com", "any"},
		"a zone transfer":                         {"example.com", "AXFR"},
		"an incremental zone transfer":            {"example.com", "IXFR"},
		"the EDNS0 pseudo-record":                 {"example.com", "OPT"},
		"a transaction signature":                 {"example.com", "TSIG"},
		"a key exchange":                          {"example.com", "TKEY"},
		"the compact denial marker":               {"example.com", "NXNAME"},
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

func TestReadQuestions(t *testing.T) {
	tests := map[string]struct {
		text string
		want []cli.Question
	}{
		"a name alone is asked for its address": {
			text: "example.com\n",
			want: []cli.Question{{Name: "example.com", Type: "A"}},
		},
		"a line per name, each with its own types": {
			text: "example.com mx txt\nwww.example.com\taaaa\n",
			want: []cli.Question{
				{Name: "example.com", Type: "MX"}, {Name: "example.com", Type: "TXT"},
				{Name: "www.example.com", Type: "AAAA"},
			},
		},
		"blank lines and comments are skipped": {
			text: "# the zone before the move\n\n   \nexample.com\n  # mail next\nexample.com MX",
			want: []cli.Question{{Name: "example.com", Type: "A"}, {Name: "example.com", Type: "MX"}},
		},
		"a name in another script is asked in punycode": {
			text: "münchen.de\n",
			want: []cli.Question{{Name: "xn--mnchen-3ya.de", Type: "A"}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := cli.ReadQuestions(strings.NewReader(test.text))
			if err != nil {
				t.Fatalf("ReadQuestions: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("got  %+v\nwant %+v", got, test.want)
			}
		})
	}
}

func TestReadQuestionsRejects(t *testing.T) {
	tests := map[string]struct {
		text string
		line string
	}{
		"nothing but comments":         {text: "# nothing yet\n\n"},
		"a type that is not a lookup":  {text: "example.com\nexample.com AXFR\n", line: "line 2"},
		"a name no punycode can spell": {text: "\u202eexample.com\n", line: "line 1"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := cli.ReadQuestions(strings.NewReader(test.text))
			if !errors.Is(err, cli.ErrUsage) {
				t.Fatalf("got error %v, want it to read as a usage problem", err)
			}
			if !strings.Contains(err.Error(), test.line) {
				t.Errorf("got %q, want it to name %q", err, test.line)
			}
		})
	}
}
