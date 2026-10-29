package resolver_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// The SRV tests resolve against com., with example.com. and two zones its
// records may send a client to: provider.com., signed, and plain.com., not.
const (
	srvComZone = `
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

	srvExampleZone = `
@                 IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@                 IN NS    ns
ns                IN A     192.0.2.3
chat1             IN A     192.0.2.10
chat1             IN AAAA  2001:db8::10
www               IN CNAME chat1
_xmpp-client._tcp IN SRV   20 50 5222 chat2.provider.com.
_xmpp-client._tcp IN SRV   10 50 5222 chat1.example.com.
_none._tcp        IN SRV   0 0 0 .
_mixed._tcp       IN SRV   0 0 0 .
_mixed._tcp       IN SRV   10 0 80 chat1.example.com.
_alias._tcp       IN SRV   10 0 80 www.example.com.
_gone._tcp        IN SRV   10 0 80 missing.provider.com.
_bare._tcp        IN SRV   10 0 80 noaddr.provider.com.
_ports._tcp       IN SRV   10 0 443 chat1.example.com.
_ports._tcp       IN SRV   10 0 80 chat1.example.com.
_ports._tcp       IN SRV   20 0 80 chat2.provider.com.
_plain._tcp       IN SRV   10 0 80 svc.plain.com.
_three._tcp       IN SRV   10 0 80 chat1.example.com.
_three._tcp       IN SRV   20 0 80 chat2.provider.com.
_three._tcp       IN SRV   30 0 80 svc.plain.com.
_three._tcp       IN SRV   40 0 443 chat1.example.com.
_service._tcp     IN CNAME _xmpp-client._tcp
`

	srvProviderZone = `
@       IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@       IN NS    ns
ns      IN A     192.0.2.5
chat2   IN A     192.0.2.20
noaddr  IN TXT   "nothing here"
`

	srvPlainZone = `
@       IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@       IN NS    ns
ns      IN A     192.0.2.6
svc     IN A     192.0.2.30
`
)

// srvServed builds the root, com., example.com. with behaviour, provider.com.
// with provider and plain.com., signing all but plain.com.
func srvServed(tb testing.TB, behaviour, provider fakens.Behaviour) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: srvComZone, Declared: "192.0.2.2", DNSSEC: true})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: srvExampleZone, Declared: "192.0.2.3",
		DNSSEC: true, Denial: fakens.DenialNSEC3, Behaviour: behaviour,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.provider.com.", Origin: "provider.com.", Zone: srvProviderZone, Declared: "192.0.2.5",
		DNSSEC: true, Denial: fakens.DenialNSEC3, Behaviour: provider,
	})
	hierarchy.Add(fakens.Config{Name: "ns.plain.com.", Origin: "plain.com.", Zone: srvPlainZone, Declared: "192.0.2.6"})

	h := harness{hierarchy, root}
	return h, resolver.Config{SRV: true, DNSSEC: true, Anchors: root.Anchors(tb)}
}

// srvReached is each target as its priority, port, name and addresses.
func srvReached(s *trace.SRV) []string {
	var targets []string
	for _, target := range s.Targets {
		text := fmt.Sprintf("%d %d %s", target.Priority, target.Port, target.Name)
		for _, addr := range target.Addrs {
			text += " " + addr.String()
		}
		targets = append(targets, text)
	}
	return targets
}

func TestSRV(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		qname, qtype string
		family       int
		behaviour    fakens.Behaviour // of example.com.
		provider     fakens.Behaviour // of provider.com.

		targets []string
		none    bool
		stopped string // a part of Stopped, empty for none
		warning string // a part of a warning that has to be there
		unsaid  string // a part of a warning that must not be there
	}{
		"every target is followed to its addresses, best priority first": {
			qname: "_xmpp-client._tcp.example.com", qtype: "SRV",
			targets: []string{"10 5222 chat1.example.com. 192.0.2.10 2001:db8::10", "20 5222 chat2.provider.com. 192.0.2.20"},
			unsaid:  "SRV",
		},
		"a question for another type looks the SRV set up on its own": {
			qname: "_xmpp-client._tcp.example.com", qtype: "TXT",
			targets: []string{"10 5222 chat1.example.com. 192.0.2.10 2001:db8::10", "20 5222 chat2.provider.com. 192.0.2.20"},
		},
		"a set reached through an alias is read at the name the alias ends on": {
			qname: "_service._tcp.example.com", qtype: "SRV",
			targets: []string{"10 5222 chat1.example.com. 192.0.2.10 2001:db8::10", "20 5222 chat2.provider.com. 192.0.2.20"},
		},
		"a family the run does not ask is not looked up": {
			qname: "_xmpp-client._tcp.example.com", qtype: "SRV", family: 4,
			targets: []string{"10 5222 chat1.example.com. 192.0.2.10", "20 5222 chat2.provider.com. 192.0.2.20"},
		},
		"a lone target of . says the service is not offered": {
			qname: "_none._tcp.example.com", qtype: "SRV",
			none:   true,
			unsaid: "SRV",
		},
		"a target of . beside others is said, and the others followed": {
			qname: "_mixed._tcp.example.com", qtype: "SRV",
			targets: []string{"10 80 chat1.example.com. 192.0.2.10 2001:db8::10"},
			warning: "has an SRV record with a target of . beside others",
		},
		"a target that is an alias is said": {
			qname: "_alias._tcp.example.com", qtype: "SRV",
			targets: []string{"10 80 www.example.com. 192.0.2.10 2001:db8::10"},
			warning: "www.example.com., which the SRV records of _alias._tcp.example.com. name, is an alias for chat1.example.com., which RFC 2782 forbids",
		},
		"a target that does not exist has nothing to connect to": {
			qname: "_gone._tcp.example.com", qtype: "SRV",
			targets: []string{"10 80 missing.provider.com."},
			warning: "missing.provider.com., which the SRV records of _gone._tcp.example.com. name, has no address",
		},
		"a target with no address has nothing to connect to": {
			qname: "_bare._tcp.example.com", qtype: "SRV",
			targets: []string{"10 80 noaddr.provider.com."},
			warning: "noaddr.provider.com., which the SRV records of _bare._tcp.example.com. name, has no address",
		},
		"a target denied without a proof is not said to have no address": {
			qname: "_gone._tcp.example.com", qtype: "SRV", provider: fakens.Behaviour{NoDenialFor: "missing.provider.com."},
			targets: []string{"10 80 missing.provider.com."},
			unsaid:  "has no address",
		},
		"a target whose address lookups fail is said": {
			qname: "_xmpp-client._tcp.example.com", qtype: "SRV", family: 4, provider: fakens.Behaviour{ServFailType: dns.TypeA},
			targets: []string{"10 5222 chat1.example.com. 192.0.2.10", "20 5222 chat2.provider.com."},
			warning: "the addresses of chat2.provider.com., which the SRV records of _xmpp-client._tcp.example.com. name, could not be looked up",
		},
		"a target whose addresses do not validate is said": {
			qname: "_xmpp-client._tcp.example.com", qtype: "SRV", provider: fakens.Behaviour{BadSignature: true},
			targets: []string{"10 5222 chat1.example.com. 192.0.2.10 2001:db8::10", "20 5222 chat2.provider.com."},
			warning: "the addresses of chat2.provider.com., which the SRV records of _xmpp-client._tcp.example.com. name, do not validate",
		},
		"a target in an unsigned zone is followed like any other": {
			qname: "_plain._tcp.example.com", qtype: "SRV",
			targets: []string{"10 80 svc.plain.com. 192.0.2.30"},
			unsaid:  "SRV",
		},
		"a set that does not validate is not followed": {
			qname: "_xmpp-client._tcp.example.com", qtype: "TXT", behaviour: fakens.Behaviour{BadSignature: true},
			stopped: "the SRV set does not validate",
			warning: "so a client that validates finds no server for the service",
		},
		"a lookup that fails is not followed": {
			qname: "_xmpp-client._tcp.example.com", qtype: "TXT", behaviour: fakens.Behaviour{ServFailType: dns.TypeSRV},
			stopped: "the SRV lookup failed",
			warning: "so a client finds no server for the service",
		},
		"a name with no SRV records has no targets": {
			qname: "chat1.example.com", qtype: "A",
			unsaid: "SRV",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := srvServed(t, tt.behaviour, tt.provider)
			cfg.Family = tt.family
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, tt.qtype)
			if err != nil {
				t.Fatal(err)
			}
			s := tr.SRV
			if s == nil {
				t.Fatal("no SRV check")
			}
			if got := srvReached(s); !slices.Equal(got, tt.targets) {
				t.Errorf("targets %q, want %q", got, tt.targets)
			}
			if s.None != tt.none {
				t.Errorf("none %v, want %v", s.None, tt.none)
			}
			if tt.stopped == "" && s.Stopped != "" || !strings.Contains(s.Stopped, tt.stopped) {
				t.Errorf("stopped %q, want %q", s.Stopped, tt.stopped)
			}
			if s.Cut || s.Left > 0 {
				t.Errorf("cut with %d left, with budget to spare", s.Left)
			}
			if tt.warning != "" && !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, tt.warning) }) {
				t.Errorf("no warning with %q in %q", tt.warning, tr.Warnings)
			}
			if tt.unsaid != "" && slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, tt.unsaid) }) {
				t.Errorf("a warning with %q in %q", tt.unsaid, tr.Warnings)
			}
			if s.Lookup.Err == "" && s.Lookup.DNSSEC == nil {
				t.Error("the SRV set carries no verdict")
			}
		})
	}
}

// TestSRVHostLookedUpOnce covers a host named by several records, on several
// ports: a client connects to the same addresses, so they are asked once.
func TestSRVHostLookedUpOnce(t *testing.T) {
	t.Parallel()

	h, cfg := srvServed(t, fakens.Behaviour{}, fakens.Behaviour{})
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "_ports._tcp.example.com", "SRV")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"10 80 chat1.example.com. 192.0.2.10 2001:db8::10",
		"10 443 chat1.example.com. 192.0.2.10 2001:db8::10",
		"20 80 chat2.provider.com. 192.0.2.20",
	}
	if got := srvReached(tr.SRV); !slices.Equal(got, want) {
		t.Errorf("targets %q, want %q", got, want)
	}
	asides := 0
	for step := range tr.Steps() {
		if slices.Contains(step.Notes, "A of chat1.example.com. for srv") {
			asides++
		}
	}
	if asides != 1 {
		t.Errorf("chat1.example.com. looked up %d times, want once: %s", asides, format(steps(tr)))
	}
}

// TestSRVOutOfBudget covers a budget that runs out among the targets, which
// says how many it left rather than leaving them out unsaid. The budget runs
// out inside the lookup of the second host, and leaves the third; the fourth
// names the first host again, and keeps what its lookup found.
func TestSRVOutOfBudget(t *testing.T) {
	t.Parallel()

	h, cfg := srvServed(t, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.DNSSEC, cfg.Anchors = false, nil
	cfg.Family = 4
	cfg.Budget.MaxQueries = 4
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "_three._tcp.example.com", "SRV")
	if err != nil {
		t.Fatal(err)
	}
	s := tr.SRV
	if !s.Cut || s.Left != 1 {
		t.Errorf("cut %v with %d left, want a cut that left targets: %+v", s.Cut, s.Left, s)
	}
	if len(s.Targets)+s.Left != 4 {
		t.Errorf("%d targets and %d left, want 4 in all", len(s.Targets), s.Left)
	}
	if last := s.Targets[len(s.Targets)-1]; last.Port != 443 || len(last.Addrs) == 0 {
		t.Errorf("got %+v last, want the record past the budget whose host was asked already, with its addresses", last)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "ran out of budget") }) {
		t.Errorf("no budget warning in %q", tr.Warnings)
	}
	if slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "could not be looked up") }) {
		t.Errorf("a target the budget stopped is said to have failed: %q", tr.Warnings)
	}
}

// TestSRVOutOfBudgetBeforeTheSet covers a budget that runs out before the SRV
// set is answered: the check says so, and a raise is what it asks for.
func TestSRVOutOfBudgetBeforeTheSet(t *testing.T) {
	t.Parallel()

	h, cfg := srvServed(t, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.DNSSEC, cfg.Anchors = false, nil
	cfg.Budget.MaxQueries = 3
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "_xmpp-client._tcp.example.com", "TXT")
	if err != nil {
		t.Fatal(err)
	}
	if s := tr.SRV; !s.Cut || !strings.Contains(s.Stopped, "budget") {
		t.Errorf("cut %v and stopped %q, want a cut the budget stopped", s.Cut, s.Stopped)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "raise the budget") }) {
		t.Errorf("no budget warning in %q", tr.Warnings)
	}
}

// TestSRVLeavesTheChain is a target in a zone that does not validate: the zone
// is the provider's, so the run's chain of trust and its exit code stay the
// name's own.
func TestSRVLeavesTheChain(t *testing.T) {
	t.Parallel()

	h, cfg := srvServed(t, fakens.Behaviour{}, fakens.Behaviour{BadSignature: true})
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "_xmpp-client._tcp.example.com", "SRV")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if chain := tr.Chain(); tr.Broken() || chain == nil || chain.DNSSEC.State != trace.Secure {
		t.Errorf("got the chain at %+v, want the secure answer's: %s", chain, format(steps(tr)))
	}
}

// TestSRVUnreachableTarget covers a target at an address no client on the
// internet can reach, said only for a walk that started from public roots.
func TestSRVUnreachableTarget(t *testing.T) {
	t.Parallel()

	const root = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    198.41.0.4
com.                IN NS   ns.com.
ns.com.             IN A    192.5.6.30
`
	const com = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
ns         IN A    192.5.6.30
example    IN NS   ns.example
ns.example IN A    45.0.0.3
`
	const example = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
ns         IN A    45.0.0.3
_sip._udp  IN SRV  10 0 5060 sip.example.com.
sip        IN A    10.0.0.5
sip        IN A    45.0.0.5
`
	hierarchy := fakens.NewHierarchy(t)
	start := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: root, Declared: "198.41.0.4"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: com, Declared: "192.5.6.30"})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: example, Declared: "45.0.0.3"})

	tr, err := newResolver(t, harness{hierarchy, start}, resolver.Config{SRV: true, Family: 4}).
		Resolve(t.Context(), "_sip._udp.example.com", "SRV")
	if err != nil {
		t.Fatal(err)
	}
	if got := tr.SRV.Targets; len(got) != 1 || len(got[0].Unreachable) != 1 || got[0].Unreachable[0].String() != "10.0.0.5" {
		t.Fatalf("got targets %+v, want 10.0.0.5 alone unreachable", got)
	}
	want := "sip.example.com., which the SRV records of _sip._udp.example.com. name, has 10.0.0.5, a private address no client on the internet can reach"
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, want) }) {
		t.Errorf("no warning with %q in %q", want, tr.Warnings)
	}
}
