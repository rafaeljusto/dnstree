package resolver_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// dsyncComZone is com. with room for the DSYNC under test, and the hosts the
// records name.
const dsyncComZone = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
ns         IN A    192.0.2.2
example    IN NS   ns.example
ns.example IN A    192.0.2.3
notify     IN A    192.0.2.80
notify     IN AAAA 2001:db8::80
`

// TestDSYNC finds where the parent of the zone the walk ended in takes notices
// about it (RFC 9859), and says what keeps one from arriving.
func TestDSYNC(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		dsync     string
		dnssec    bool
		behaviour fakens.Behaviour
		state     trace.DSYNCState
		name      string
		endpoints []string
		addrs     []string
		warning   string
	}{
		"a parent that publishes nothing": {
			dnssec: true,
			state:  trace.DSYNCNone,
		},
		"a record for the zone alone": {
			dsync: `
example._dsync IN DSYNC CDS   NOTIFY 5359 notify
_dsync         IN DSYNC CSYNC NOTIFY 5360 notify`,
			dnssec:    true,
			state:     trace.DSYNCFound,
			name:      "example._dsync.com.",
			endpoints: []string{"CDS NOTIFY 5359 notify.com."},
			addrs:     []string{"192.0.2.80", "2001:db8::80"},
		},
		"the parent's default, where nothing is for the zone alone": {
			dsync: `
_dsync IN DSYNC CDS   NOTIFY 5359 notify
_dsync IN DSYNC CSYNC NOTIFY 5360 notify`,
			dnssec:    true,
			state:     trace.DSYNCFound,
			name:      "_dsync.com.",
			endpoints: []string{"CDS NOTIFY 5359 notify.com.", "CSYNC NOTIFY 5360 notify.com."},
			addrs:     []string{"192.0.2.80", "2001:db8::80"},
		},
		"a set nobody checked the signature of": {
			dsync:     `_dsync IN DSYNC CDS NOTIFY 5359 notify`,
			state:     trace.DSYNCFound,
			name:      "_dsync.com.",
			endpoints: []string{"CDS NOTIFY 5359 notify.com."},
			addrs:     []string{"192.0.2.80", "2001:db8::80"},
		},
		"a denial for the zone alone that does not validate": {
			dsync:     `_dsync IN DSYNC CDS NOTIFY 5359 notify`,
			dnssec:    true,
			behaviour: fakens.Behaviour{NoDenialFor: "example._dsync.com."},
			state:     trace.DSYNCBogus,
			warning:   "the DSYNC at example._dsync.com. does not validate",
		},
		"two records for one type and scheme": {
			dsync: `
_dsync IN DSYNC CDS NOTIFY 5359 notify
_dsync IN DSYNC CDS NOTIFY 5360 notify`,
			dnssec:    true,
			state:     trace.DSYNCFound,
			name:      "_dsync.com.",
			endpoints: []string{"CDS NOTIFY 5359 notify.com.", "CDS NOTIFY 5360 notify.com. (ignored)"},
			addrs:     []string{"192.0.2.80", "2001:db8::80"},
			warning:   "has more than one DSYNC for CDS NOTIFY",
		},
		"a target with no address": {
			dsync:     `_dsync IN DSYNC CDS NOTIFY 5359 nowhere`,
			dnssec:    true,
			state:     trace.DSYNCFound,
			name:      "_dsync.com.",
			endpoints: []string{"CDS NOTIFY 5359 nowhere.com."},
			warning:   "the DSYNC target nowhere.com. that com. names for notices about example.com. has no address",
		},
		"a target denied without a proof": {
			dsync:     `_dsync IN DSYNC CDS NOTIFY 5359 gone`,
			dnssec:    true,
			behaviour: fakens.Behaviour{NoDenialFor: "gone.com."},
			state:     trace.DSYNCFound,
			name:      "_dsync.com.",
			endpoints: []string{"CDS NOTIFY 5359 gone.com."},
		},
		"a parent that fails the lookup": {
			dsync:     `_dsync IN DSYNC CDS NOTIFY 5359 notify`,
			behaviour: fakens.Behaviour{ServFailType: 66},
			state:     trace.DSYNCUnchecked,
			warning:   "the DSYNC lookup of example._dsync.com. failed",
		},
		"records a notifier passes over": {
			dsync: `
_dsync IN DSYNC CDS   0      5359 notify
_dsync IN DSYNC CSYNC NOTIFY 0    notify
_dsync IN DSYNC TXT   NOTIFY 53   notify`,
			dnssec:    true,
			state:     trace.DSYNCFound,
			name:      "_dsync.com.",
			endpoints: []string{"CDS 0 5359 notify.com. (ignored)", "CSYNC NOTIFY 0 notify.com. (ignored)", "TXT NOTIFY 53 notify.com. (ignored)"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{
				Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: test.dnssec,
			})
			hierarchy.Add(fakens.Config{
				Name: "ns.com.", Origin: "com.", Zone: dsyncComZone + test.dsync, Declared: "192.0.2.2",
				DNSSEC: test.dnssec, Behaviour: test.behaviour,
			})
			hierarchy.Add(fakens.Config{
				Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: test.dnssec,
			})
			cfg := resolver.Config{CheckDS: true}
			if test.dnssec {
				cfg.DNSSEC, cfg.Anchors = true, root.Anchors(t)
			}

			tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "example.com", "SOA")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			d := dsyncOf(tr)
			if d == nil || d.State != test.state {
				t.Fatalf("got %+v, want %s: %s", d, test.state, format(steps(tr)))
			}
			if d.Name != test.name {
				t.Errorf("got the set at %q, want %q", d.Name, test.name)
			}

			var endpoints, addrs []string
			for _, e := range d.Endpoints {
				text := e.Type + " " + e.Scheme + " " + strconv.Itoa(int(e.Port)) + " " + e.Target
				if e.Ignored != "" {
					text += " (ignored)"
				} else if len(addrs) == 0 {
					for _, addr := range e.Addrs {
						addrs = append(addrs, addr.String())
					}
				}
				endpoints = append(endpoints, text)
			}
			if !slices.Equal(endpoints, test.endpoints) {
				t.Errorf("got endpoints %q, want %q", endpoints, test.endpoints)
			}
			if !slices.Equal(addrs, test.addrs) {
				t.Errorf("got addresses %q, want %q", addrs, test.addrs)
			}

			warnings := strings.Join(tr.Warnings, "\n")
			if test.warning != "" && !strings.Contains(warnings, test.warning) {
				t.Errorf("got warnings %q, want one saying %q", tr.Warnings, test.warning)
			}
			if test.warning == "" && strings.Contains(warnings, "DSYNC") {
				t.Errorf("got warnings %q, want none about the DSYNC", tr.Warnings)
			}
			// Somebody else's broken zone is never the run's broken chain.
			if chain := tr.Chain(); chain != nil && chain.DNSSEC.State == trace.Bogus {
				t.Errorf("got the run's chain bogus at %s, want the DSYNC kept apart", chain.Zone)
			}
		})
	}
}

// TestDSYNCOutOfBudget runs out of budget at every point of the address
// lookups: a target the budget never reached is not one with no address.
func TestDSYNCOutOfBudget(t *testing.T) {
	t.Parallel()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "com.", Declared: "192.0.2.2", Zone: dsyncComZone + `
other  IN A     192.0.2.81
_dsync IN DSYNC CDS   NOTIFY 5359 notify
_dsync IN DSYNC CSYNC NOTIFY 5360 other`,
	})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3"})

	for budget := 1; budget <= 30; budget++ {
		cfg := resolver.Config{CheckDS: true, Budget: resolver.Budget{MaxQueries: budget}}
		tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "example.com", "SOA")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		for _, w := range tr.Warnings {
			if strings.Contains(w, "has no address") {
				t.Errorf("budget %d: got %q, want no target said to have no address", budget, w)
			}
		}
	}
}

// TestDSYNCDelegated is a parent that hands its _dsync names to a zone of
// their own, whose signatures do not hold: the set is bogus, and the run's
// chain of trust is not.
func TestDSYNCDelegated(t *testing.T) {
	t.Parallel()

	const comZone = dsyncComZone + `
_dsync    IN NS ns._dsync
ns._dsync IN A  192.0.2.90
`
	const dsyncZone = `
@  IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@  IN NS    ns
ns IN A     192.0.2.90
@  IN DSYNC CDS NOTIFY 5359 notify.com.
`
	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: true})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns._dsync.com.", Origin: "_dsync.com.", Zone: dsyncZone, Declared: "192.0.2.90", DNSSEC: true,
		Behaviour: fakens.Behaviour{BadSignature: true},
	})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{CheckNS: true, DNSSEC: true, Anchors: root.Anchors(t)}).
		Resolve(t.Context(), "example.com", "SOA")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	d := dsyncOf(tr)
	if d == nil || d.State != trace.DSYNCBogus {
		t.Fatalf("got %+v, want bogus: %s", d, format(steps(tr)))
	}
	if chain := tr.Chain(); chain == nil || chain.DNSSEC.State != trace.Secure {
		t.Errorf("got the run's chain %+v, want it secure", chain)
	}
}

// TestDSYNCLongName is a zone whose name leaves no room for the _dsync label:
// the name for it alone is skipped, and the parent's default still asked.
func TestDSYNCLongName(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 55)
	comZone := `
@        IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@        IN NS    ns
ns       IN A     192.0.2.2
notify   IN A     192.0.2.80
_dsync   IN DSYNC CDS NOTIFY 5359 notify
ns2      IN A     192.0.2.3
` + long + ` IN NS ns2
`
	zone := `
@  IN SOA ns2.com. hostmaster.com. 1 7200 3600 1209600 3600
@  IN NS  ns2.com.
`
	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns2.com.", Origin: long + ".com.", Zone: zone, Declared: "192.0.2.3"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{CheckDS: true}).Resolve(t.Context(), long+".com", "SOA")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	d := dsyncOf(tr)
	if d == nil || d.State != trace.DSYNCFound || d.Name != "_dsync.com." {
		t.Fatalf("got %+v, want the default found: %s", d, format(steps(tr)))
	}
	if len(d.Lookups) != 1 || !strings.Contains(d.Reason, "longer than 255 octets") {
		t.Errorf("got lookups %+v and reason %q, want the name for the zone skipped", d.Lookups, d.Reason)
	}
}

func dsyncOf(tr *trace.Trace) *trace.DSYNC {
	for _, request := range tr.Requests() {
		if request.DSYNC != nil {
			return request.DSYNC
		}
	}
	return nil
}
