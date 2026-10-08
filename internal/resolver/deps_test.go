package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// The dependency tests resolve names of com. served from other TLDs:
// example.com. by a host in dnshost.net. and a backup in backup.org., which
// lean on each other and on cheap-vps.io.; lost.com. by dnshost.net. and a
// name in io. that does not exist.
const (
	depsRootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
net.                IN NS   ns.net.
ns.net.             IN A    192.0.2.3
org.                IN NS   ns.org.
ns.org.             IN A    192.0.2.4
io.                 IN NS   ns.io.
ns.io.              IN A    192.0.2.5
`

	depsComZone = `
@       IN SOA ns hostmaster 1 7200 3600 1209600 3600
@       IN NS  ns
ns      IN A   192.0.2.2
example IN NS  ns1.dnshost.net.
example IN NS  ns2.backup.org.
lost    IN NS  ns.dnshost.net.
lost    IN NS  ns.gone.io.
`

	depsNetZone = `
@       IN SOA ns hostmaster 1 7200 3600 1209600 3600
@       IN NS  ns
ns      IN A   192.0.2.3
dnshost IN NS  ns.dnshost
dnshost IN NS  ns.backup.org.
ns.dnshost IN A 192.0.2.10
`

	depsOrgZone = `
@       IN SOA ns hostmaster 1 7200 3600 1209600 3600
@       IN NS  ns
ns      IN A   192.0.2.4
backup  IN NS  ns1.cheap-vps.io.
backup  IN NS  ns.dnshost.net.
`

	depsIOZone = `
@         IN SOA ns hostmaster 1 7200 3600 1209600 3600
@         IN NS  ns
ns        IN A   192.0.2.5
cheap-vps IN NS  ns.cheap-vps
ns.cheap-vps IN A 192.0.2.12
`

	depsDNSHostZone = `
@   IN SOA ns hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns
@   IN NS  ns.backup.org.
ns  IN A   192.0.2.10
ns1 IN A   192.0.2.20
`

	depsBackupZone = `
@   IN SOA ns1.cheap-vps.io. hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns1.cheap-vps.io.
@   IN NS  ns.dnshost.net.
ns  IN A   192.0.2.10
ns2 IN A   192.0.2.20
`

	depsCheapVPSZone = `
@   IN SOA ns hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns
ns  IN A   192.0.2.12
ns1 IN A   192.0.2.10
`

	depsExampleZone = `
@   IN SOA ns1.dnshost.net. hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns1.dnshost.net.
@   IN NS  ns2.backup.org.
www IN A   192.0.2.80
`

	depsLostZone = `
@   IN SOA ns.dnshost.net. hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns.dnshost.net.
@   IN NS  ns.gone.io.
www IN A   192.0.2.81
`
)

// depending builds the hierarchy, signing every zone but cheap-vps.io. where
// signed is set.
func depending(tb testing.TB, signed bool) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: depsRootZone, Declared: "192.0.2.1", DNSSEC: signed})
	for _, zone := range []fakens.Config{
		{Name: "ns.com.", Origin: "com.", Zone: depsComZone, Declared: "192.0.2.2"},
		{Name: "ns.net.", Origin: "net.", Zone: depsNetZone, Declared: "192.0.2.3"},
		{Name: "ns.org.", Origin: "org.", Zone: depsOrgZone, Declared: "192.0.2.4"},
		{Name: "ns.io.", Origin: "io.", Zone: depsIOZone, Declared: "192.0.2.5"},
		{Name: "ns.dnshost.net.", Origin: "dnshost.net.", Zone: depsDNSHostZone, Declared: "192.0.2.10"},
		{Name: "ns.dnshost.net.", Origin: "backup.org.", Zone: depsBackupZone, Declared: "192.0.2.10"},
		{Name: "ns1.dnshost.net.", Origin: "example.com.", Zone: depsExampleZone, Declared: "192.0.2.20"},
		{Name: "ns.dnshost.net.", Origin: "lost.com.", Zone: depsLostZone, Declared: "192.0.2.10"},
	} {
		zone.DNSSEC = signed
		hierarchy.Add(zone)
	}
	hierarchy.Add(fakens.Config{Name: "ns.cheap-vps.io.", Origin: "cheap-vps.io.", Zone: depsCheapVPSZone, Declared: "192.0.2.12"})

	h := harness{hierarchy, root}
	cfg := resolver.Config{Deps: true, Budget: resolver.Budget{MaxQueries: 512}}
	if signed {
		cfg.DNSSEC, cfg.Anchors = true, root.Anchors(tb)
	}
	return h, cfg
}

// pulled is each zone as the zone, and where it came from.
func pulled(d *trace.Dependencies) []string {
	var zones []string
	for _, zone := range d.Zones {
		text := zone.Zone
		if zone.Via != "" {
			text += " by " + zone.Via + " of " + zone.For
		}
		zones = append(zones, text)
	}
	return zones
}

func TestDependencies(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		qname      string
		signed     bool
		minimise   bool
		maxQueries int

		zones      []string
		unresolved []string // name of zone: a part of the reason
		unsigned   []string
		stopped    string // a part of Stopped, empty for none
		dangling   string // the name a nameserver was left pointing into
		warning    string // a part of a warning that has to be there
	}{
		"every nameserver is followed, and the zones each lookup came to are kept once": {
			qname: "www.example.com",
			zones: []string{
				"com.", "example.com.",
				"net. by ns1.dnshost.net. of example.com.", "dnshost.net. by ns1.dnshost.net. of example.com.",
				"org. by ns2.backup.org. of example.com.", "backup.org. by ns2.backup.org. of example.com.",
				"io. by ns1.cheap-vps.io. of backup.org.", "cheap-vps.io. by ns1.cheap-vps.io. of backup.org.",
			},
		},
		"a minimised walk depends on the same zones": {
			qname: "www.example.com", minimise: true,
			zones: []string{
				"com.", "example.com.",
				"net. by ns1.dnshost.net. of example.com.", "dnshost.net. by ns1.dnshost.net. of example.com.",
				"org. by ns2.backup.org. of example.com.", "backup.org. by ns2.backup.org. of example.com.",
				"io. by ns1.cheap-vps.io. of backup.org.", "cheap-vps.io. by ns1.cheap-vps.io. of backup.org.",
			},
		},
		"a nameserver that does not exist is said, and the rest are still followed": {
			qname: "www.lost.com",
			zones: []string{
				"com.", "lost.com.",
				"net. by ns.dnshost.net. of lost.com.", "dnshost.net. by ns.dnshost.net. of lost.com.",
				"io. by ns.gone.io. of lost.com.",
				"org. by ns.backup.org. of dnshost.net.", "backup.org. by ns.backup.org. of dnshost.net.",
				"cheap-vps.io. by ns1.cheap-vps.io. of backup.org.",
			},
			unresolved: []string{"ns.gone.io. of lost.com.: does not exist"},
			dangling:   "gone.io.",
		},
		"a zone whose delegation is unsigned is said to be": {
			qname: "www.example.com", signed: true,
			unsigned: []string{"cheap-vps.io."},
		},
		"a budget that runs out leaves the list short, and says so": {
			qname: "www.example.com", maxQueries: 12,
			stopped: "the budget ran out",
			warning: "raise --max-queries",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := depending(t, tt.signed)
			cfg.Minimise = tt.minimise
			if tt.maxQueries > 0 {
				cfg.Budget.MaxQueries = tt.maxQueries
			}
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := tr.Result(); got == nil || got.Kind != trace.KindAnswer {
				t.Fatalf("the walk did not reach an answer: %v", got)
			}
			d := tr.Dependencies
			if d == nil {
				t.Fatal("no dependencies were recorded")
			}

			if tt.zones != nil && !slices.Equal(pulled(d), tt.zones) {
				t.Errorf("zones:\n got %q\nwant %q", pulled(d), tt.zones)
			}
			var unresolved []string
			for _, ns := range d.Unresolved {
				unresolved = append(unresolved, ns.Name+" of "+ns.For+": "+ns.Err)
			}
			if !slices.Equal(unresolved, tt.unresolved) {
				t.Errorf("unresolved = %q, want %q", unresolved, tt.unresolved)
			}
			if tt.signed {
				var unsigned []string
				for _, zone := range d.Zones {
					if zone.DNSSEC == nil {
						t.Errorf("%s carries no verdict", zone.Zone)
					} else if zone.DNSSEC.State == trace.Insecure {
						unsigned = append(unsigned, zone.Zone)
					}
				}
				if !slices.Equal(unsigned, tt.unsigned) {
					t.Errorf("unsigned = %q, want %q", unsigned, tt.unsigned)
				}
			}
			if tt.stopped == "" && d.Stopped != "" || !strings.Contains(d.Stopped, tt.stopped) {
				t.Errorf("Stopped = %q, want it to hold %q", d.Stopped, tt.stopped)
			}
			var dangling string
			for step := range tr.Steps() {
				if step.Dangling != nil && step.Dangling.Kind == trace.DanglingNameserver {
					dangling = step.Dangling.Missing
				}
			}
			if dangling != tt.dangling {
				t.Errorf("dangling = %q, want %q", dangling, tt.dangling)
			}
			if tt.warning != "" && !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, tt.warning) }) {
				t.Errorf("no warning holds %q: %q", tt.warning, tr.Warnings)
			}
		})
	}
}

func TestDependenciesOnlyWhenAsked(t *testing.T) {
	t.Parallel()

	h, cfg := depending(t, false)
	cfg.Deps = false
	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Dependencies != nil {
		t.Errorf("Dependencies = %+v without --deps", tr.Dependencies)
	}
}
