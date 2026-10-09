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
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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
		"how long a change takes, written for a program": {
			args: []string{"--propagation", "--format", "json", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Format: "json", Propagation: true},
		},
		"a zone checked whole, on a budget of its own": {
			args: []string{"--check", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Check: true, DNSSEC: true, All: true, CheckNS: true,
				CheckDS: true, Serial: true, CheckEDNS: true, Cookie: true, CAA: true, SPF: true, Mail: true, RDAP: true,
				MaxQueries: cli.CheckMaxQueries},
		},
		"a zone checked whole, on the budget asked for": {
			args: []string{"--check", "--max-queries", "100", "--check-axfr", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Check: true, DNSSEC: true, All: true, CheckNS: true,
				CheckDS: true, Serial: true, CheckEDNS: true, Cookie: true, CAA: true, SPF: true, Mail: true, RDAP: true,
				CheckAXFR: true, MaxQueries: 100},
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
		"every zone the name depends on, with the budget that takes": {
			args: []string{"--deps", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Deps: true, MaxQueries: cli.DepsMaxQueries},
		},
		"every zone the name depends on, on the budget asked for": {
			args: []string{"--deps", "--all", "--max-queries", "100", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Deps: true, All: true, MaxQueries: 100},
		},
		"every nameserver asked, with the budget that takes": {
			args: []string{"--all", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", All: true, MaxQueries: cli.AllMaxQueries},
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
		"a mail check that connects to the hosts it proves": {
			args: []string{"--mail", "--dnssec", "--tlsa", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Mail: true, DNSSEC: true, TLSA: true},
		},
		"a mail check of two DKIM keys, one named twice": {
			args: []string{"--mail", "--dkim", "Google", "--dkim", "s1.2024", "--dkim", "google", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Mail: true, DKIM: []string{"google", "s1.2024"}},
		},
		"a walk that minimises its questions": {
			args: []string{"--qmin", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Minimise: true},
		},
		"a walk that asks the resolvers what encrypted resolvers they designate": {
			args: []string{"--ddr", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", DDR: true},
		},
		"a walk that checks how the resolvers behave": {
			args: []string{"--check-resolver", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Behave: true},
		},
		"a report sent through a resolver nothing else asks": {
			args: []string{"--report", "--dnssec", "--no-asn", "--no-compare", "--resolver", "192.0.2.53", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", DNSSEC: true, Report: true,
				Resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}},
		},
		"a zone tried on new nameservers, by name and by address": {
			args: []string{"--try-ns", "Example.com=ns1.new.net", "--try-ns", "example.com.=ns2.new.net@192.0.2.9", "--try-ns", "example.com=2001:db8::9", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Try: &trace.Trial{
				Zone: "example.com.",
				NS:   []string{"ns1.new.net.", "ns2.new.net.", "2001:db8::9"},
				Addrs: map[string][]netip.Addr{
					"ns2.new.net.": {netip.MustParseAddr("192.0.2.9")},
					"2001:db8::9":  {netip.MustParseAddr("2001:db8::9")},
				},
			}},
		},
		"a walk saved as a packet capture": {
			args: []string{"--pcap", "walk.pcap", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Pcap: "walk.pcap"},
		},
		"a walk answered from a capture, which asks nothing beside it": {
			args: []string{"--replay", "walk.pcap", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Replay: "walk.pcap"},
		},
		"a replayed check, which grades what the capture holds": {
			args: []string{"--replay", "walk.pcap", "--check", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Replay: "walk.pcap", Check: true,
				DNSSEC: true, All: true, CheckNS: true, CheckDS: true, Serial: true, CheckEDNS: true, Cookie: true,
				CAA: true, Mail: true, MaxQueries: 512},
		},
		"a broken chain reported to the agent its zone names": {
			args: []string{"--report", "--dnssec", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", DNSSEC: true, Report: true},
		},
		"a zone's nameservers asked for what they should keep": {
			args: []string{"--check-axfr", "--check-recursion", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", CheckAXFR: true, CheckRecursion: true},
		},
		"a zone's nameservers asked how they handle edns": {
			args: []string{"--check-edns", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", CheckEDNS: true},
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
			if !strings.Contains(given, "--no-asn") && !strings.Contains(given, "--replay") {
				want.ASN = true
			}
			if !strings.Contains(given, "--no-compare") && !strings.Contains(given, "--replay") {
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
		"nothing to resolve":                        {},
		"a lookup that is not one among several":    {"example.com", "A", "ANY"},
		"names from a file and a name as well":      {"--names", "names.txt", "example.com"},
		"names from a file and an address":          {"--names", "names.txt", "-x", "192.0.2.1"},
		"names from a file and a saved walk":        {"--names", "names.txt", "--from", "walk.json"},
		"several types written as one json":         {"--format", "json", "example.com", "A", "AAAA"},
		"several types served as one page":          {"--format", "web", "example.com", "A", "AAAA"},
		"several types measured as one":             {"--format", "openmetrics", "example.com", "A", "AAAA"},
		"several types held to one expectation":     {"--expect", "answer", "example.com", "A", "AAAA"},
		"several types held against one walk":       {"--against", "walk.json", "example.com", "A", "AAAA"},
		"several types watched":                     {"--watch", "30s", "example.com", "A", "AAAA"},
		"names from a file written as one json":     {"--format", "json", "--names", "names.txt"},
		"names from a file held to an expectation":  {"--names", "-", "--expect", "answer"},
		"two address families":                      {"-4", "-6", "example.com"},
		"a name no punycode can spell":              {"\u202eexample.com"},
		"two transports":                            {"--udp", "--doh", "example.com"},
		"an unknown format":                         {"--format", "runes", "example.com"},
		"live json":                                 {"--format", "json", "--live", "example.com"},
		"live dot":                                  {"--format", "dot", "--live", "example.com"},
		"live web":                                  {"--format", "web", "--live", "example.com"},
		"watched json":                              {"--format", "json", "--watch", "30s", "example.com"},
		"watched dot":                               {"--format", "dot", "--watch", "30s", "example.com"},
		"watched web":                               {"--format", "web", "--watch", "30s", "example.com"},
		"live web-3d":                               {"--format", "web-3d", "--live", "example.com"},
		"watched web-3d":                            {"--format", "web-3d", "--watch", "30s", "example.com"},
		"a watch tighter than a second":             {"--watch", "100ms", "example.com"},
		"a watch of no time at all":                 {"--watch", "-1s", "example.com"},
		"a page nobody serves":                      {"--web-addr", "127.0.0.1:8080", "example.com"},
		"a browser for a tree":                      {"--no-browser", "example.com"},
		"a page served at no port":                  {"--format", "web", "--web-addr", "localhost", "example.com"},
		"a page served at a port nothing has":       {"--format", "web", "--web-addr", "127.0.0.1:99999", "example.com"},
		"explained json":                            {"--format", "json", "--explain", "example.com"},
		"how long a change takes, drawn as dot":     {"--format", "dot", "--propagation", "example.com"},
		"how long a change takes, as a waterfall":   {"--format", "waterfall", "--propagation", "example.com"},
		"explained dot":                             {"--format", "dot", "--explain", "example.com"},
		"a zone graded on no budget at all":         {"--check", "--max-queries", "0", "example.com"},
		"a zone graded, drawn as dot":               {"--format", "dot", "--check", "example.com"},
		"a zone graded, measured":                   {"--format", "openmetrics", "--check", "example.com"},
		"a zone graded again from a saved walk":     {"--from", "walk.json", "--check"},
		"compared json":                             {"--format", "json", "--diff", "example.com"},
		"compared dot":                              {"--format", "dot", "--diff", "example.com"},
		"live mermaid":                              {"--format", "mermaid", "--live", "example.com"},
		"watched mermaid":                           {"--format", "mermaid", "--watch", "30s", "example.com"},
		"explained mermaid":                         {"--format", "mermaid", "--explain", "example.com"},
		"compared mermaid":                          {"--format", "mermaid", "--diff", "example.com"},
		"live waterfall":                            {"--format", "waterfall", "--live", "example.com"},
		"watched waterfall":                         {"--format", "waterfall-ascii", "--watch", "30s", "example.com"},
		"explained gantt chart":                     {"--format", "waterfall-mermaid", "--explain", "example.com"},
		"a page for a waterfall":                    {"--format", "waterfall", "--no-browser", "example.com"},
		"live markdown":                             {"--format", "markdown", "--live", "example.com"},
		"watched markdown":                          {"--format", "markdown", "--watch", "30s", "example.com"},
		"live openmetrics":                          {"--format", "openmetrics", "--live", "example.com"},
		"watched openmetrics":                       {"--format", "openmetrics", "--watch", "30s", "example.com"},
		"explained openmetrics":                     {"--format", "openmetrics", "--explain", "example.com"},
		"compared openmetrics":                      {"--format", "openmetrics", "--diff", "example.com"},
		"a walk already made, and a name":           {"--from", "walk.json", "example.com"},
		"a walk already made, drawn live":           {"--from", "walk.json", "--live"},
		"a walk already made, watched":              {"--from", "walk.json", "--watch", "30s"},
		"a walk already made, remembered":           {"--from", "walk.json", "--diff"},
		"held against a file and the cache":         {"--against", "walk.json", "--diff", "example.com"},
		"both walks from the standard input":        {"--from", "-", "--against", "-"},
		"held against a walk, as json":              {"--format", "json", "--against", "walk.json", "example.com"},
		"a walk already made, re-checked":           {"--dnssec", "--from", "walk.json"},
		"a walk already made, re-asked":             {"--from", "walk.json", "--qmin", "--timeout", "3s"},
		"a walk already made, sent cookies":         {"--from", "walk.json", "--cookie"},
		"a walk already made, probed":               {"--from", "walk.json", "--check-axfr"},
		"a lifetime that is not one":                {"--expect", "fresh:soon", "example.com"},
		"a reverse lookup of no address":            {"-x", "example.com"},
		"a reverse lookup and a name":               {"-x", "192.0.2.1", "example.com"},
		"a reverse lookup and a type":               {"-x", "192.0.2.1", "A"},
		"a reverse lookup of a saved walk":          {"--from", "walk.json", "-x", "192.0.2.1"},
		"a request weighed unsigned":                {"--check-ds", "example.com"},
		"certificates matched with no mail check":   {"--dnssec", "--tlsa", "example.com"},
		"certificates matched, nothing proved":      {"--mail", "--tlsa", "example.com"},
		"a DKIM key with no mail check":             {"--dkim", "google", "example.com"},
		"a DKIM selector of an empty label":         {"--mail", "--dkim", "s1..x", "example.com"},
		"a DKIM selector that is not a name":        {"--mail", "--dkim", "s1_key", "example.com"},
		"a DKIM selector that begins with a hyphen": {"--mail", "--dkim", "-s1", "example.com"},
		"a walk already made, asked for DKIM keys":  {"--from", "walk.json", "--mail", "--dkim", "s1"},
		"designations asked of no resolver":         {"--ddr", "--no-compare", "example.com"},
		"a walk already made, asked for ddr":        {"--from", "walk.json", "--ddr"},
		"resolvers checked that nothing asks":       {"--check-resolver", "--no-compare", "example.com"},
		"a walk made, asked to check resolvers":     {"--from", "walk.json", "--check-resolver"},
		"a report with no chain of trust to break":  {"--report", "example.com"},
		"a trial with no zone":                      {"--try-ns", "ns1.new.net", "example.com"},
		"a trial of two zones at once":              {"--try-ns", "example.com=ns1.new.net", "--try-ns", "example.org=ns1.new.net", "example.com"},
		"a trial of the root":                       {"--try-ns", ".=ns1.new.net", "example.com"},
		"a trial remembered as the DNS as it is":    {"--try-ns", "example.com=ns1.new.net", "--diff", "example.com"},
		"a trial on a server that is not one":       {"--try-ns", "example.com=ns1/new", "example.com"},
		"a trial on a server inside it, unglued":    {"--try-ns", "example.com=ns1.example.com", "example.com"},
		"a report every time a walk is watched":     {"--report", "--dnssec", "--watch", "30s", "example.com"},
		"a walk already made, asked for a report":   {"--from", "walk.json", "--report", "--dnssec"},
		"a capture of queries carried in tls":       {"--dot", "--pcap", "walk.pcap", "example.com"},
		"a capture of queries carried in https":     {"--doh", "--pcap", "walk.pcap", "example.com"},
		"a capture of a walk already made":          {"--from", "walk.json", "--pcap", "walk.pcap"},
		"a capture of every walk watched":           {"--watch", "30s", "--pcap", "walk.pcap", "example.com"},
		"a capture written into the drawing":        {"--pcap", "-", "example.com"},
		"a replay of a walk already made":           {"--from", "walk.json", "--replay", "walk.pcap"},
		"a replay read where the names may be":      {"--replay", "-", "example.com"},
		"a replay of queries carried in tls":        {"--dot", "--replay", "walk.pcap", "example.com"},
		"a replay of queries carried in https":      {"--doh", "--replay", "walk.pcap", "example.com"},
		"a replay watched for changes":              {"--watch", "30s", "--replay", "walk.pcap", "example.com"},
		"a replay remembered as the latest walk":    {"--diff", "--replay", "walk.pcap", "example.com"},
		"a replay timed against a resolver":         {"--resolver", "192.0.2.1", "--replay", "walk.pcap", "example.com"},
		"a replay that asks the registry":           {"--rdap", "--replay", "walk.pcap", "example.com"},
		"a replay that asks for the SPF policy":     {"--spf", "--replay", "walk.pcap", "example.com"},
		"a replay that connects to mail servers":    {"--mail", "--dnssec", "--tlsa", "--replay", "walk.pcap", "example.com"},
		"a replay that checks each resolver":        {"--check-resolver", "--replay", "walk.pcap", "example.com"},
		"an unknown colour":                         {"--color", "sometimes", "example.com"},
		"a timeout of nothing":                      {"--timeout", "0", "example.com"},
		"a negative retry count":                    {"--retries", "-1", "example.com"},
		"no zone cuts to follow":                    {"--max-depth", "0", "example.com"},
		"no queries to make":                        {"--max-queries", "0", "example.com"},
		"no aliases to chase":                       {"--max-cname", "0", "example.com"},
		"a negative budget":                         {"--max-queries", "-5", "example.com"},
		"a port beyond the range":                   {"--port", "70000", "example.com"},
		"a flag nobody has":                         {"--recursive", "example.com"},
		"help":                                      {"--help"},

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

// TestParseSaysWhatIsWrong covers the mistakes the flag package finds itself,
// which it says with one dash and follows with the whole usage, burying them.
// Each is said once, as the rest of the command line's are.
func TestParseSaysWhatIsWrong(t *testing.T) {
	tests := map[string]struct {
		args []string
		want string
	}{
		"a flag there is no such thing as":    {[]string{"--bogus", "example.com"}, "--bogus is not a flag; --help lists them"},
		"a letter there is no such flag of":   {[]string{"-z", "example.com"}, "-z is not a flag; --help lists them"},
		"a number that is not one":            {[]string{"--retries", "x", "example.com"}, `--retries "x" is not a number`},
		"a number too large to hold":          {[]string{"--max-queries", "99999999999999999999", "example.com"}, `--max-queries "99999999999999999999" is out of range`},
		"a length of time that is not one":    {[]string{"--timeout", "x", "example.com"}, `--timeout "x" is not a length of time, such as 2s`},
		"a switch set to something else":      {[]string{"--dnssec=maybe", "example.com"}, `--dnssec "maybe" is neither true nor false`},
		"a value the flag gives a reason for": {[]string{"--try-ns", "nonsense", "example.com"}, `--try-ns "nonsense" is not ZONE=SERVER`},
		"a value missing at the very end":     {[]string{"--names"}, "--names needs a value"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			_, err := cli.Parse(test.args, &out)
			if !errors.Is(err, cli.ErrUsage) {
				t.Fatalf("got error %v, want a usage problem", err)
			}
			if out.Len() > 0 {
				t.Errorf("got %q written, want the mistake said once, in the error", out.String())
			}
			if !strings.HasSuffix(err.Error(), ": "+test.want) {
				t.Errorf("got %q, want it to end %q", err, test.want)
			}
		})
	}
}

// TestParseHelp covers the one time the usage is written whole.
func TestParseHelp(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		var out strings.Builder
		if _, err := cli.Parse([]string{arg}, &out); !errors.Is(err, cli.ErrUsage) {
			t.Fatalf("%s: got error %v, want a usage problem", arg, err)
		}
		if !strings.HasPrefix(out.String(), "usage: dnstree") {
			t.Errorf("%s: got %q, want the usage", arg, out.String())
		}
	}
}
