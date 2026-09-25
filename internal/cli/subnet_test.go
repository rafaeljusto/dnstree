package cli_test

import (
	"io"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/cli"
)

func TestParseSubnet(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "a prefix", value: "203.0.113.0/24", want: "203.0.113.0/24"},
		{name: "an IPv6 prefix", value: "2001:db8::/48", want: "2001:db8::/48"},
		// The subnet says which network is asking. A whole address would say
		// which machine, which is more than the question needs.
		{name: "a bare address is a network", value: "203.0.113.57", want: "203.0.113.0/24"},
		{name: "a bare IPv6 address", value: "2001:db8::1", want: "2001:db8::/56"},
		// Whatever was typed, the bits past the prefix do not go on the wire.
		{name: "a prefix is masked", value: "203.0.113.57/24", want: "203.0.113.0/24"},
		{name: "a whole address as a prefix", value: "203.0.113.57/32", want: "203.0.113.57/32"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := cli.Parse([]string{"--subnet", tt.value, "example.com"}, io.Discard)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := cfg.Subnet.String(); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// TestParseNoSubnet covers the default: a walk tells the servers on the way
// down nothing about where it is being run from.
func TestParseNoSubnet(t *testing.T) {
	cfg, err := cli.Parse([]string{"example.com"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Subnet.IsValid() {
		t.Errorf("got %s, want no subnet", cfg.Subnet)
	}
}

func TestParseSubnetRejects(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
	}{
		{name: "not an address at all", value: "somewhere"},
		{name: "a name", value: "example.com"},
		{name: "a prefix length that is not one", value: "203.0.113.0/33"},
		{name: "an empty value", value: "/24"},
		// Written that way it would go out as an IPv6 subnet carrying IPv6
		// prefix lengths, which no IPv4 client is inside of.
		{name: "IPv4 written as IPv6", value: "::ffff:203.0.113.0/120"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := cli.Parse([]string{"--subnet", tt.value, "example.com"}, io.Discard); err == nil {
				t.Errorf("got no error for %q, want one", tt.value)
			}
		})
	}
}
