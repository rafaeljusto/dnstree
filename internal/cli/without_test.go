package cli_test

import (
	"io"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/cli"
)

func TestParseWithout(t *testing.T) {
	for _, tt := range []struct {
		name   string
		values []string
		want   []string
	}{
		{name: "a nameserver", values: []string{"ns1.example.com"}, want: []string{"ns1.example.com."}},
		{name: "a nameserver in capitals", values: []string{"NS1.Example.COM."}, want: []string{"ns1.example.com."}},
		{name: "a nameserver in another script", values: []string{"ns.bücher.example"}, want: []string{"ns.xn--bcher-kva.example."}},
		{name: "an address", values: []string{"192.0.2.1"}, want: []string{"192.0.2.1"}},
		{name: "an IPv6 address", values: []string{"2001:db8::53"}, want: []string{"2001:db8::53"}},
		{name: "an IPv4 address mapped into IPv6", values: []string{"::ffff:192.0.2.1"}, want: []string{"192.0.2.1"}},
		{name: "a prefix, masked", values: []string{"192.0.2.77/24"}, want: []string{"192.0.2.0/24"}},
		{name: "a prefix over the mapped addresses", values: []string{"::ffff:192.0.2.0/120"}, want: []string{"192.0.2.0/24"}},
		{name: "several, in the order given", values: []string{"ns1.example.com", "2001:db8::/32"}, want: []string{"ns1.example.com.", "2001:db8::/32"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var args []string
			for _, value := range tt.values {
				args = append(args, "--without", value)
			}
			cfg, err := cli.Parse(append(args, "example.com"), io.Discard)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(cfg.Without) != len(tt.want) {
				t.Fatalf("got %v, want %v", cfg.Without, tt.want)
			}
			for i, down := range cfg.Without {
				if got := down.String(); got != tt.want[i] {
					t.Errorf("got %s, want %s", got, tt.want[i])
				}
			}
		})
	}
}

func TestParseWithoutRejects(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "nothing", args: []string{"--without", "", "example.com"}},
		{name: "the root", args: []string{"--without", ".", "example.com"}},
		{name: "a network by its AS, which needs the lookups first", args: []string{"--without", "AS13335", "example.com"}},
		{name: "an address with a port", args: []string{"--without", "192.0.2.1:53", "example.com"}},
		{name: "a prefix length that is not one", args: []string{"--without", "192.0.2.0/33", "example.com"}},
		{name: "a mapped prefix wider than the mapping", args: []string{"--without", "::ffff:0:0/80", "example.com"}},
		{name: "a walk already made", args: []string{"--from", "walk.json", "--without", "ns1.example.com"}},
		{name: "a walk to be remembered as the last one", args: []string{"--diff", "--without", "ns1.example.com", "example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := cli.Parse(tt.args, io.Discard); err == nil {
				t.Errorf("got no error for %q, want one", tt.args)
			}
		})
	}
}
