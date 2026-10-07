package resolver_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// The service tests resolve against com., with example.com. and two providers
// its records may send a client to: provider.com., signed, and plain.com.,
// not.
const (
	svcbComZone = `
@           IN SOA ns hostmaster 1 7200 3600 1209600 3600
@           IN NS  ns
ns          IN A   192.0.2.2
example     IN NS  ns.example
ns.example  IN A   192.0.2.3
provider    IN NS  ns.provider
ns.provider IN A   192.0.2.5
plain       IN NS  ns.plain
ns.plain    IN A   192.0.2.6
`

	svcbExampleZone = `
@       IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@       IN NS    ns
ns      IN A     192.0.2.3
@       IN HTTPS 0 cdn.provider.com.
@       IN A     192.0.2.80
www     IN HTTPS 1 . alpn="h2" ipv4hint="192.0.2.81"
www     IN A     192.0.2.81
stale   IN HTTPS 1 . ipv4hint="192.0.2.99"
stale   IN A     192.0.2.82
both    IN HTTPS 1 . ipv4hint="192.0.2.83" ipv6hint="2001:db8::1"
both    IN A     192.0.2.83
both    IN AAAA  2001:db8::2
loop    IN HTTPS 0 loop2.example.com.
loop2   IN HTTPS 0 loop.example.com.
none    IN HTTPS 0 .
mixed   IN HTTPS 0 cdn.provider.com.
mixed   IN HTTPS 1 .
mixed   IN A     192.0.2.84
twice   IN HTTPS 0 nothing.provider.com.
twice   IN HTTPS 0 cdn.provider.com.
unsigned IN HTTPS 0 svc.plain.com.
empty   IN HTTPS 0 nothing.provider.com.
long    IN HTTPS 0 empty.example.com.
gone    IN HTTPS 1 missing.provider.com.
bare    IN A     192.0.2.85
many    IN HTTPS 2 edge.provider.com.
many    IN HTTPS 1 . ipv4hint="192.0.2.86"
many    IN A     192.0.2.86
_8443._https IN HTTPS 1 edge.provider.com. port=8443
`

	svcbProviderZone = `
@       IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@       IN NS    ns
ns      IN A     192.0.2.5
cdn     IN HTTPS 1 edge alpn="h3" ipv4hint="192.0.2.1"
edge    IN A     192.0.2.7
nothing IN A     192.0.2.8
ech     IN HTTPS 1 . ech="AEX+DQBBAAA="
ech     IN A     192.0.2.9
`

	svcbPlainZone = `
@       IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@       IN NS    ns
ns      IN A     192.0.2.6
svc     IN HTTPS 1 . alpn="h2" ech="AEX+DQBBAAA="
svc     IN A     192.0.2.10
jump    IN HTTPS 0 ech.provider.com.
`
)

// served builds the root, com., example.com., provider.com. with behaviour and
// plain.com., signing all but plain.com. where signed is set.
func served(tb testing.TB, signed bool, behaviour fakens.Behaviour) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: signed,
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: svcbComZone, Declared: "192.0.2.2", DNSSEC: signed})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: svcbExampleZone, Declared: "192.0.2.3",
		DNSSEC: signed, Denial: fakens.DenialNSEC3,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.provider.com.", Origin: "provider.com.", Zone: svcbProviderZone, Declared: "192.0.2.5",
		DNSSEC: signed, Denial: fakens.DenialNSEC3, Behaviour: behaviour,
	})
	hierarchy.Add(fakens.Config{Name: "ns.plain.com.", Origin: "plain.com.", Zone: svcbPlainZone, Declared: "192.0.2.6"})

	h := harness{hierarchy, root}
	cfg := resolver.Config{SVCB: true}
	if signed {
		cfg.DNSSEC, cfg.Anchors = true, root.Anchors(tb)
	}
	return h, cfg
}

// chain is the names of the sets the path looked up, in order.
func chain(p *trace.ServicePath) []string {
	var names []string
	for _, set := range p.Chain {
		names = append(names, set.Lookup.Name)
	}
	return names
}

// reached is each target as its name and its addresses.
func reached(p *trace.ServicePath) []string {
	var targets []string
	for _, target := range p.Targets {
		text := target.Name
		for _, addr := range target.Addrs {
			text += " " + addr.String()
		}
		targets = append(targets, text)
	}
	return targets
}

func TestServicePath(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		qname, qtype string
		family       int
		maxCNAME     int
		behaviour    fakens.Behaviour

		chain    []string
		targets  []string
		stray    []string // the stray hints of every target
		fallback bool
		none     bool
		stopped  string // a part of Stopped, empty for none
		warning  string // a part of a warning that has to be there
	}{
		"an alias is followed into another zone, to the target and its addresses": {
			qname: "example.com", qtype: "HTTPS",
			chain:   []string{"example.com.", "cdn.provider.com."},
			targets: []string{"edge.provider.com. 192.0.2.7"},
			stray:   []string{"192.0.2.1"},
			warning: "hint at 192.0.2.1, which is not among its addresses",
		},
		"a question for another type looks the HTTPS set up on its own": {
			qname: "example.com", qtype: "A",
			chain:   []string{"example.com.", "cdn.provider.com."},
			targets: []string{"edge.provider.com. 192.0.2.7"},
			stray:   []string{"192.0.2.1"},
		},
		"a target of . is the owner of the record, and a hint among its addresses is no warning": {
			qname: "www.example.com", qtype: "HTTPS",
			chain:   []string{"www.example.com."},
			targets: []string{"www.example.com. 192.0.2.81"},
		},
		"a hint that is none of the target's addresses is said": {
			qname: "stale.example.com", qtype: "HTTPS",
			targets: []string{"stale.example.com. 192.0.2.82"},
			stray:   []string{"192.0.2.99"},
			warning: "update the hint or remove it",
		},
		"a hint of each family is held against the addresses of its own": {
			qname: "both.example.com", qtype: "HTTPS",
			targets: []string{"both.example.com. 192.0.2.83 2001:db8::2"},
			stray:   []string{"2001:db8::1"},
		},
		"a family the run does not ask is not judged": {
			qname: "both.example.com", qtype: "HTTPS", family: 4,
			targets: []string{"both.example.com. 192.0.2.83"},
		},
		"aliases that point at each other are a loop": {
			qname: "loop.example.com", qtype: "HTTPS",
			chain:   []string{"loop.example.com.", "loop2.example.com."},
			stopped: "loop back to loop.example.com.",
			warning: "loop back to loop.example.com.",
		},
		"a chain as long as --max-cname allows is followed to its end": {
			qname: "example.com", qtype: "HTTPS", maxCNAME: 1,
			chain:   []string{"example.com.", "cdn.provider.com."},
			targets: []string{"edge.provider.com. 192.0.2.7"},
			stray:   []string{"192.0.2.1"},
		},
		"an alias past --max-cname is not followed": {
			qname: "long.example.com", qtype: "HTTPS", maxCNAME: 1,
			chain:   []string{"long.example.com.", "empty.example.com."},
			stopped: "past --max-cname 1",
			warning: "raise --max-cname",
		},
		"an alias to . says there is no service": {
			qname: "none.example.com", qtype: "HTTPS",
			chain: []string{"none.example.com."},
			none:  true,
		},
		"alias and service mode together follow the alias": {
			qname: "mixed.example.com", qtype: "HTTPS",
			chain:   []string{"mixed.example.com.", "cdn.provider.com."},
			targets: []string{"edge.provider.com. 192.0.2.7"},
			stray:   []string{"192.0.2.1"},
			warning: "a client ignores the service mode ones",
		},
		"of several aliases the first by name is followed": {
			qname: "twice.example.com", qtype: "HTTPS",
			chain:   []string{"twice.example.com.", "cdn.provider.com."},
			targets: []string{"edge.provider.com. 192.0.2.7"},
			stray:   []string{"192.0.2.1"},
			warning: "has 2 HTTPS records in alias mode",
		},
		"an alias to a name with no records falls back to that name's addresses": {
			qname: "empty.example.com", qtype: "HTTPS",
			chain:    []string{"empty.example.com.", "nothing.provider.com."},
			targets:  []string{"nothing.provider.com. 192.0.2.8"},
			fallback: true,
		},
		"a name with no records falls back with nothing more to look up": {
			qname: "bare.example.com", qtype: "HTTPS",
			chain:    []string{"bare.example.com."},
			fallback: true,
		},
		"a target that does not exist has nothing to connect to": {
			qname: "gone.example.com", qtype: "HTTPS",
			targets: []string{"missing.provider.com."},
			warning: "has no address, so a client has nothing to connect to",
		},
		"every record of a set is followed, best priority first": {
			qname: "many.example.com", qtype: "HTTPS",
			targets: []string{"many.example.com. 192.0.2.86", "edge.provider.com. 192.0.2.7"},
		},
		"a name with a port prefix is asked as it is": {
			qname: "_8443._https.example.com", qtype: "HTTPS",
			chain:   []string{"_8443._https.example.com."},
			targets: []string{"edge.provider.com. 192.0.2.7"},
		},
		"a set that does not validate stops the chain": {
			qname: "example.com", qtype: "HTTPS", behaviour: fakens.Behaviour{BadSignature: true},
			chain:   []string{"example.com.", "cdn.provider.com."},
			stopped: "does not validate",
			warning: "so a client that validates gets none of it",
		},
		"a lookup that fails stops the chain": {
			qname: "example.com", qtype: "HTTPS", behaviour: fakens.Behaviour{ServFailType: dns.TypeHTTPS},
			chain:   []string{"example.com.", "cdn.provider.com."},
			stopped: "the HTTPS lookup of cdn.provider.com. failed",
			warning: "so a client connects without what its records offer",
		},
		"a signed set with an ech key reached through an unsigned alias is not vouched for": {
			qname: "jump.plain.com", qtype: "HTTPS",
			chain:   []string{"jump.plain.com.", "ech.provider.com."},
			targets: []string{"ech.provider.com. 192.0.2.9"},
			warning: "ech.provider.com. publishes an ECH configuration in an answer that is insecure",
		},
		"a target whose address lookups fail is said": {
			qname: "example.com", qtype: "HTTPS", family: 4, behaviour: fakens.Behaviour{ServFailType: dns.TypeA},
			chain:   []string{"example.com.", "cdn.provider.com."},
			targets: []string{"edge.provider.com."},
			warning: "the addresses of edge.provider.com., which the HTTPS records of example.com. lead to, could not be looked up",
		},
		"an alias into an unsigned zone leaves its ech key unvouched for": {
			qname: "unsigned.example.com", qtype: "HTTPS",
			chain:   []string{"unsigned.example.com.", "svc.plain.com."},
			targets: []string{"svc.plain.com. 192.0.2.10"},
			warning: "svc.plain.com. publishes an ECH configuration in an answer that is insecure",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := served(t, true, tt.behaviour)
			cfg.Family = tt.family
			cfg.Budget.MaxCNAME = tt.maxCNAME
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, tt.qtype)
			if err != nil {
				t.Fatal(err)
			}
			p := tr.ServicePath
			if p == nil {
				t.Fatal("no service path")
			}
			if tt.chain != nil && !slices.Equal(chain(p), tt.chain) {
				t.Errorf("chain %q, want %q", chain(p), tt.chain)
			}
			if !slices.Equal(reached(p), tt.targets) {
				t.Errorf("targets %q, want %q", reached(p), tt.targets)
			}
			var stray []string
			for _, target := range p.Targets {
				for _, hint := range target.Stray {
					stray = append(stray, hint.String())
				}
			}
			if !slices.Equal(stray, tt.stray) {
				t.Errorf("stray hints %q, want %q", stray, tt.stray)
			}
			if p.Fallback != tt.fallback || p.None != tt.none {
				t.Errorf("fallback %v and none %v, want %v and %v", p.Fallback, p.None, tt.fallback, tt.none)
			}
			if tt.stopped == "" && p.Stopped != "" || !strings.Contains(p.Stopped, tt.stopped) {
				t.Errorf("stopped %q, want %q", p.Stopped, tt.stopped)
			}
			if p.Cut {
				t.Error("cut, with budget to spare")
			}
			if tt.warning != "" && !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, tt.warning) }) {
				t.Errorf("no warning with %q in %q", tt.warning, tr.Warnings)
			}
			for _, set := range p.Chain {
				if set.Lookup.Err == "" && set.Lookup.DNSSEC == nil {
					t.Errorf("the set at %s carries no verdict", set.Lookup.Name)
				}
			}
		})
	}
}

// TestServicePathUnsigned covers a path walked without --dnssec, which judges
// the hints all the same and says nothing it did not check.
func TestServicePathUnsigned(t *testing.T) {
	t.Parallel()

	h, cfg := served(t, false, fakens.Behaviour{})
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "HTTPS")
	if err != nil {
		t.Fatal(err)
	}
	p := tr.ServicePath
	if got := reached(p); !slices.Equal(got, []string{"edge.provider.com. 192.0.2.7"}) {
		t.Fatalf("targets %q", got)
	}
	if !slices.Equal(p.Targets[0].Stray, []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
		t.Errorf("stray %v", p.Targets[0].Stray)
	}
	for _, set := range p.Chain {
		if set.Lookup.DNSSEC != nil {
			t.Errorf("the set at %s carries a verdict nothing checked", set.Lookup.Name)
		}
	}
}

// TestServicePathOutOfBudget covers a budget that runs out on the way, which
// is said rather than taken for an answer.
func TestServicePathOutOfBudget(t *testing.T) {
	t.Parallel()

	h, cfg := served(t, false, fakens.Behaviour{})
	cfg.Budget.MaxQueries = 5
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "HTTPS")
	if err != nil {
		t.Fatal(err)
	}
	p := tr.ServicePath
	if !p.Cut {
		t.Errorf("not cut: %+v", p)
	}
	if len(p.Targets) > 0 && len(p.Targets[0].Stray) > 0 {
		t.Errorf("a hint was judged on a budget that ran out: %v", p.Targets[0].Stray)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "ran out of budget") }) {
		t.Errorf("no budget warning in %q", tr.Warnings)
	}
}
