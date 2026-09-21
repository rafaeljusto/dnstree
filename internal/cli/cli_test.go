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
		"a walk explained": {
			args: []string{"--explain", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A", Explain: true},
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
				Resolver: netip.MustParseAddrPort("192.0.2.1:53"),
			},
		},
		"the older name for it": {
			args: []string{"--asn-resolver", "192.0.2.1", "example.com"},
			want: cli.Config{
				Name: "example.com", Type: "A",
				Resolver: netip.MustParseAddrPort("192.0.2.1:53"),
			},
		},
		"no question put to a resolver": {
			args: []string{"--no-compare", "example.com"},
			want: cli.Config{Name: "example.com", Type: "A"},
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

func TestParseRejects(t *testing.T) {
	tests := map[string][]string{
		"nothing to resolve":      {},
		"too many arguments":      {"example.com", "A", "please"},
		"two address families":    {"-4", "-6", "example.com"},
		"two transports":          {"--udp", "--doh", "example.com"},
		"an unknown format":       {"--format", "runes", "example.com"},
		"live json":               {"--format", "json", "--live", "example.com"},
		"live dot":                {"--format", "dot", "--live", "example.com"},
		"explained json":          {"--format", "json", "--explain", "example.com"},
		"explained dot":           {"--format", "dot", "--explain", "example.com"},
		"an unknown colour":       {"--color", "sometimes", "example.com"},
		"a timeout of nothing":    {"--timeout", "0", "example.com"},
		"a negative retry count":  {"--retries", "-1", "example.com"},
		"a port beyond the range": {"--port", "70000", "example.com"},
		"a flag nobody has":       {"--recursive", "example.com"},
		"help":                    {"--help"},

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

// TestParseUsage covers the help itself, which is the only documentation a
// reader has in front of them at the time.
func TestParseUsage(t *testing.T) {
	var out strings.Builder
	if _, err := cli.Parse(nil, &out); !errors.Is(err, cli.ErrUsage) {
		t.Fatalf("got error %v, want a usage problem", err)
	}

	for _, want := range []string{"usage: dnstree", "--dnssec", "--format", "--explain", "Exit codes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("got usage without %q:\n%s", want, out.String())
		}
	}
}
