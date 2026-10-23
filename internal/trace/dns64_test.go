package trace_test

import (
	"net/netip"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestEmbedded reads the table of RFC 6052 section 2.4, where 192.0.2.33 is
// put under 2001:db8:122:344::/n at each length.
func TestEmbedded(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		addr string
		bits int
		ok   bool
	}{
		"under a /32":                         {addr: "2001:db8:c000:221::", bits: 32, ok: true},
		"under a /40":                         {addr: "2001:db8:1c0:2:21::", bits: 40, ok: true},
		"under a /48":                         {addr: "2001:db8:122:c000:2:2100::", bits: 48, ok: true},
		"under a /56":                         {addr: "2001:db8:122:3c0:0:221::", bits: 56, ok: true},
		"under a /64":                         {addr: "2001:db8:122:344:c0:2:2100:0", bits: 64, ok: true},
		"under a /96":                         {addr: "2001:db8:122:344::192.0.2.33", bits: 96, ok: true},
		"a nonzero octet at bits 64 to 71":    {addr: "2001:db8:122:344:ff00:2:2100:0", bits: 64},
		"a length RFC 6052 does not allow":    {addr: "2001:db8:122:344::192.0.2.33", bits: 80},
		"an IPv4 address carries none":        {addr: "192.0.2.33", bits: 96},
		"an IPv4-mapped address carries none": {addr: "::ffff:192.0.2.33", bits: 96},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, ok := trace.Embedded(netip.MustParseAddr(test.addr), test.bits)
			if ok != test.ok || ok && got != netip.MustParseAddr("192.0.2.33") {
				t.Errorf("got %s, %t, want 192.0.2.33, %t", got, ok, test.ok)
			}
		})
	}
}

func TestSynthesised(t *testing.T) {
	t.Parallel()

	prefixes := []netip.Prefix{netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("64:ff9b::/96")}
	if got, ok := trace.Synthesised(netip.MustParseAddr("64:ff9b::c000:219"), prefixes); !ok || got.String() != "192.0.2.25" {
		t.Errorf("got %s, %t, want 192.0.2.25 out of the second prefix", got, ok)
	}
	if _, ok := trace.Synthesised(netip.MustParseAddr("2001:db9::1"), prefixes); ok {
		t.Error("got an address outside every prefix read as made up")
	}
}
