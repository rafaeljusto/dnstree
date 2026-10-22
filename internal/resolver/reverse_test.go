package resolver_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// The reverse tests delegate a /24 and a /32 of IPv6 straight from the root,
// each to a server inside it, beside com. and example.com., whose names the
// PTR records give.
const (
	reverseRootZone = `
@                         IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                         IN NS   a.root-servers.net.
a.root-servers.net.       IN A    192.0.2.1
com.                      IN NS   ns.com.
ns.com.                   IN A    192.0.2.2
2.0.192.in-addr.arpa.     IN NS   ns.2.0.192.in-addr.arpa.
ns.2.0.192.in-addr.arpa.  IN A    192.0.2.4
8.b.d.0.1.0.0.2.ip6.arpa. IN NS   ns.8.b.d.0.1.0.0.2.ip6.arpa.
ns.8.b.d.0.1.0.0.2.ip6.arpa. IN A 192.0.2.5
`

	reverseComZone = `
@           IN SOA ns hostmaster 1 7200 3600 1209600 3600
@           IN NS  ns
ns          IN A   192.0.2.2
example     IN NS  ns.example
ns.example  IN A   192.0.2.3
`

	reverseExampleZone = `
@         IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@         IN NS    ns
ns        IN A     192.0.2.3
mail      IN A     192.0.2.25
mail      IN AAAA  2001:db8::25
other     IN A     192.0.2.99
two       IN A     192.0.2.28
alias     IN CNAME host
host      IN A     192.0.2.29
classless IN A     192.0.2.40
`

	reverseV4Zone = `
@      IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@      IN NS    ns
ns     IN A     192.0.2.4
25     IN PTR   mail.example.com.
26     IN PTR   other.example.com.
27     IN PTR   missing.example.com.
28     IN PTR   other.example.com.
28     IN PTR   two.example.com.
29     IN PTR   alias.example.com.
40     IN CNAME 40.sub
40.sub IN PTR   classless.example.com.
`

	reverseV6Zone = `
@  IN SOA ns hostmaster 1 7200 3600 1209600 3600
@  IN NS  ns
ns IN A   192.0.2.5
5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR mail.example.com.
`
)

// reversed builds the root, com., example.com. with behaviour and the two
// reverse zones, all signed, and a run that confirms addr.
func reversed(tb testing.TB, behaviour fakens.Behaviour, addr netip.Addr) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: reverseRootZone, Declared: "192.0.2.1", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: reverseComZone, Declared: "192.0.2.2", DNSSEC: true})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: reverseExampleZone, Declared: "192.0.2.3",
		DNSSEC: true, Behaviour: behaviour,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.2.0.192.in-addr.arpa.", Origin: "2.0.192.in-addr.arpa.", Zone: reverseV4Zone, Declared: "192.0.2.4", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.8.b.d.0.1.0.0.2.ip6.arpa.", Origin: "8.b.d.0.1.0.0.2.ip6.arpa.", Zone: reverseV6Zone, Declared: "192.0.2.5", DNSSEC: true,
	})

	return harness{hierarchy, root}, resolver.Config{Confirm: addr, DNSSEC: true, Anchors: root.Anchors(tb)}
}

// pointing is each name the check looked up, as the name and, where it points
// back, "back".
func pointing(c *trace.Reverse) []string {
	var names []string
	for _, name := range c.Names {
		text := name.Name
		if name.Back(c.Addr) {
			text += " back"
		}
		names = append(names, text)
	}
	return names
}

func TestReverseConfirmed(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		addr      string
		behaviour fakens.Behaviour

		names     []string
		confirmed bool
		alias     string // where the PTR walk was sent, empty for nowhere
		warning   string // a part of a warning that has to be there
	}{
		"a name that holds the address points back": {
			addr:      "192.0.2.25",
			names:     []string{"mail.example.com. back"},
			confirmed: true,
		},
		"a name that holds another address does not point back": {
			addr:    "192.0.2.26",
			names:   []string{"other.example.com."},
			warning: "other.example.com., which the PTR of 192.0.2.26 names, does not point back to it",
		},
		"a name that does not exist does not point back": {
			addr:    "192.0.2.27",
			names:   []string{"missing.example.com."},
			warning: "does not point back",
		},
		"of two names, the one that holds the address is enough": {
			addr:      "192.0.2.28",
			names:     []string{"other.example.com.", "two.example.com. back"},
			confirmed: true,
		},
		"a name that is an alias is followed to its address": {
			addr:      "192.0.2.29",
			names:     []string{"alias.example.com. back"},
			confirmed: true,
		},
		"a delegation below a /24 is followed to the PTR set it leads to": {
			addr:      "192.0.2.40",
			names:     []string{"classless.example.com. back"},
			confirmed: true,
			alias:     "40.sub.2.0.192.in-addr.arpa.",
		},
		"an address with no PTR has no name to point back": {
			addr: "192.0.2.30",
		},
		"an IPv6 address is held against the AAAA set": {
			addr:      "2001:db8::25",
			names:     []string{"mail.example.com. back"},
			confirmed: true,
		},
		"an address set that does not validate confirms nothing": {
			addr: "192.0.2.25", behaviour: fakens.Behaviour{BadSignature: true},
			names:   []string{"mail.example.com."},
			warning: "so a receiver that validates cannot confirm it",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			addr := netip.MustParseAddr(tt.addr)
			h, cfg := reversed(t, tt.behaviour, addr)
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), reverseName(addr), "PTR")
			if err != nil {
				t.Fatal(err)
			}
			c := tr.Reverse
			if c == nil {
				t.Fatal("no reverse check")
			}
			if !slices.Equal(pointing(c), tt.names) {
				t.Errorf("names %q, want %q", pointing(c), tt.names)
			}
			if c.Confirmed() != tt.confirmed {
				t.Errorf("confirmed %v, want %v", c.Confirmed(), tt.confirmed)
			}
			if c.PTR.Alias != tt.alias {
				t.Errorf("the PTR walk went to %q, want %q", c.PTR.Alias, tt.alias)
			}
			if c.Cut {
				t.Error("cut, with budget to spare")
			}
			if tt.warning != "" && !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, tt.warning) }) {
				t.Errorf("no warning with %q in %q", tt.warning, tr.Warnings)
			}
			if tt.warning == "" && slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "PTR of") }) {
				t.Errorf("a warning about the PTR in %q", tr.Warnings)
			}
			// Somebody else's broken zone is never the walk's own.
			if tr.Broken() {
				t.Error("the chain of trust is broken by a lookup of the check")
			}
		})
	}
}

func TestReverseLeftAlone(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("192.0.2.25")
	h, cfg := reversed(t, fakens.Behaviour{}, addr)
	for name, run := range map[string]struct {
		cfg   resolver.Config
		qtype string
	}{
		"a run with no address to confirm": {cfg: resolver.Config{DNSSEC: true, Anchors: cfg.Anchors}, qtype: "PTR"},
		"a question for another type":      {cfg: cfg, qtype: "TXT"},
	} {
		tr, err := newResolver(t, h, run.cfg).Resolve(t.Context(), reverseName(addr), run.qtype)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Reverse != nil {
			t.Errorf("%s: checked %q", name, pointing(tr.Reverse))
		}
	}
}

func TestReverseBudget(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("192.0.2.28")
	h, cfg := reversed(t, fakens.Behaviour{}, addr)
	full, err := newResolver(t, h, cfg).Resolve(t.Context(), reverseName(addr), "PTR")
	if err != nil {
		t.Fatal(err)
	}

	// Enough for the walk and the first name, never the second.
	cfg.Budget.MaxQueries = queried(full) - 1
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), reverseName(addr), "PTR")
	if err != nil {
		t.Fatal(err)
	}
	c := tr.Reverse
	if c == nil || !c.Cut {
		t.Fatal("a check the budget stopped is not marked cut")
	}
	if c.PTR.Err != "" || len(c.Names) != 2 {
		t.Fatalf("the PTR walk came to %q with %q, want both names before the budget ran out", c.PTR.Err, pointing(c))
	}
	if c.Confirmed() {
		t.Error("confirmed by a name that was never looked up")
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "ran out of budget") }) {
		t.Errorf("no warning about the budget in %q", tr.Warnings)
	}
}

// queried is how many queries the walk sent, check lookups included.
func queried(tr *trace.Trace) int {
	n := 0
	for step := range tr.Steps() {
		if step.Queried() {
			n++
		}
	}
	return n
}

// reverseName is the name the PTR of addr is asked under, as -x writes it.
func reverseName(addr netip.Addr) string {
	if addr.Is4() {
		b := addr.As4()
		return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}).String() + ".in-addr.arpa."
	}
	var nibbles []string
	b := addr.As16()
	for _, b := range slices.Backward(b[:]) {
		nibbles = append(nibbles, string("0123456789abcdef"[b&0xf]), string("0123456789abcdef"[b>>4]))
	}
	return strings.Join(nibbles, ".") + ".ip6.arpa."
}
