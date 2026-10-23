package dnssec_test

import (
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestSuppose covers the DS --try-ds gives: it stands in for whatever the
// parent said of the zone's DS, signed or not, and is checked against the keys
// like the parent's would be. Only the zone it was given for takes it.
func TestSuppose(t *testing.T) {
	root := newZone(t, ".")
	child := newZone(t, "example.")
	other := newZone(t, "example.")
	signed := func(rrset ...dns.RR) []dns.RR {
		return append(rrset, root.sign(t, rrset, time.Now().Add(time.Hour)))
	}

	tests := map[string]struct {
		zone      string
		supposed  *dns.DS
		authority func() []dns.RR
		state     trace.DNSSECState
		reason    string
	}{
		"a DS for a zone the parent proves has none": {
			zone: "example.", supposed: child.ds(),
			authority: func() []dns.RR { return root.denies(t, "example.") },
			state:     trace.Secure},
		"a DS in place of the parent's own for other keys": {
			zone: "example.", supposed: child.ds(),
			authority: func() []dns.RR { return signed(other.ds()) },
			state:     trace.Secure},
		"a DS that points at none of the keys": {
			zone: "example.", supposed: other.ds(),
			authority: func() []dns.RR { return signed(child.ds()) },
			state:     trace.Bogus,
			reason:    "the zone publishes no key"},
		"a DS for another zone, beside the parent's": {
			zone: "elsewhere.", supposed: other.ds(),
			authority: func() []dns.RR { return signed(child.ds()) },
			state:     trace.Secure},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chain := dnssec.New(root.anchors(t, dns.SHA256))
			if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
				t.Fatalf("got %+v entering the root, want it secure", status)
			}
			chain.Suppose(test.zone, []*dns.DS{test.supposed})

			status := chain.Enter("example.", test.authority(), child.dnskeys(t))
			if status.State != test.state || !strings.Contains(status.Reason, test.reason) {
				t.Fatalf("got %+v, want %s with %q", status, test.state, test.reason)
			}
		})
	}
}
