package cli_test

import (
	"errors"
	"io"
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
		"the whole surface": {
			args: []string{
				"-6", "--dot", "--fallback", "--all", "--dnssec", "--check-ns", "--no-asn",
				"--format", "json", "--color", "never", "--timeout", "5s", "--retries", "3",
				"--max-depth", "8", "--max-queries", "32", "--max-cname", "4", "--port", "5353",
				"--root-hints", "hints", "--trust-anchors", "anchors", "--debug",
				"example.com", "ns",
			},
			want: cli.Config{
				Name: "example.com", Type: "NS", Family: 6, Proto: "dot",
				Fallback: true, All: true, DNSSEC: true, CheckNS: true,
				Format: "json", Color: tree.ColorNever, Timeout: 5 * time.Second,
				Retries: 3, MaxDepth: 8, MaxQueries: 32, MaxCNAME: 4, Port: 5353,
				RootHints: "hints", TrustAnchors: "anchors", Debug: true,
			},
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
			if !strings.Contains(strings.Join(test.args, " "), "--no-asn") {
				want.ASN = true
			}

			got, err := cli.Parse(test.args, io.Discard)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if *got != want {
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
		"an unknown colour":       {"--color", "sometimes", "example.com"},
		"a timeout of nothing":    {"--timeout", "0", "example.com"},
		"a negative retry count":  {"--retries", "-1", "example.com"},
		"a port beyond the range": {"--port", "70000", "example.com"},
		"a flag nobody has":       {"--recursive", "example.com"},
		"help":                    {"--help"},
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

	for _, want := range []string{"usage: dnstree", "--dnssec", "--format", "Exit codes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("got usage without %q:\n%s", want, out.String())
		}
	}
}
