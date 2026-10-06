package resolver_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestDangling covers the names left pointing at something nobody holds: a
// nameserver whose name does not exist, an alias whose target does not, and a
// zone every server of which answers without authority for it.
func TestDangling(t *testing.T) {
	t.Parallel()

	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
net.                IN NS   ns.net.
ns.net.             IN A    192.0.2.6
`
	const netZone = `
@         IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@         IN NS   ns
ns        IN A    192.0.2.6
outside   IN NS   ns.outside
ns.outside IN A   192.0.2.7
host      IN NS   ns.host
ns.host   IN A    192.0.2.20
`
	const outsideZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.7
good  IN A    192.0.2.3
`
	const hostZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.20
ns1   IN A    192.0.2.21
ns2   IN A    192.0.2.22
x     IN A    192.0.2.23
`
	const aliasZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.3
www   IN A    192.0.2.10
shop  IN CNAME gone.host.net.
store IN CNAME www.nowhere.net.
here  IN CNAME gone.example.com.
`
	// comFor delegates example.com to the nameservers given. The ones inside
	// it are ns1.example, glued to an IPv4 address, and ns2.example, glued to
	// an IPv6 one.
	comFor := func(nameservers ...string) string {
		zone := `
@           IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@           IN NS   ns
ns          IN A    192.0.2.2
ns1.example IN A    192.0.2.30
ns2.example IN AAAA 2001:db8::30
`
		for _, name := range nameservers {
			zone += "example IN NS " + name + "\n"
		}
		return zone
	}

	build := func(tb testing.TB, com string, refuse bool) harness {
		hierarchy := fakens.NewHierarchy(tb)
		root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
		hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: com, Declared: "192.0.2.2"})
		hierarchy.Add(fakens.Config{Name: "ns.net.", Origin: "net.", Zone: netZone, Declared: "192.0.2.6"})
		hierarchy.Add(fakens.Config{Name: "ns.outside.net.", Origin: "outside.net.", Zone: outsideZone, Declared: "192.0.2.7"})
		hierarchy.Add(fakens.Config{Name: "good.outside.net.", Origin: "example.com.", Zone: aliasZone, Declared: "192.0.2.3"})
		hierarchy.Add(fakens.Config{Name: "ns.host.net.", Origin: "host.net.", Zone: hostZone, Declared: "192.0.2.20"})
		for _, address := range []string{"192.0.2.21", "192.0.2.22", "192.0.2.30", "2001:db8::30"} {
			hierarchy.Add(fakens.Config{
				Name: "ns.host.net.", Origin: "example.com.", Zone: aliasZone, Declared: address,
				Behaviour: fakens.Behaviour{Refuse: refuse},
			})
		}
		return harness{hierarchy, root}
	}

	tests := map[string]struct {
		com    string
		refuse bool
		cfg    resolver.Config
		name   string
		want   *trace.Dangling
		answer bool
	}{
		"a nameserver under a domain nobody registered": {
			com:  comFor("ns.gone.net.", "good.outside.net."),
			want: &trace.Dangling{Kind: trace.DanglingNameserver, Name: "example.com.", Target: "ns.gone.net.", Missing: "gone.net.", Zone: "net."},
		},
		"a nameserver missing from a domain that exists": {
			com:  comFor("lost.outside.net.", "good.outside.net."),
			want: &trace.Dangling{Kind: trace.DanglingNameserver, Name: "example.com.", Target: "lost.outside.net.", Missing: "lost.outside.net.", Zone: "outside.net."},
		},
		"a nameserver after one that answered is only looked up by --all": {
			com: comFor("good.outside.net.", "ns.gone.net."),
		},
		"--all looks up every nameserver named outside the zone": {
			com:  comFor("good.outside.net.", "ns.gone.net."),
			cfg:  resolver.Config{All: true},
			want: &trace.Dangling{Kind: trace.DanglingNameserver, Name: "example.com.", Target: "ns.gone.net.", Missing: "gone.net.", Zone: "net."},
		},
		"an alias for a name missing from a zone somebody else runs": {
			com:  comFor("good.outside.net."),
			name: "shop.example.com",
			want: &trace.Dangling{Kind: trace.DanglingAlias, Name: "shop.example.com.", Target: "gone.host.net.", Missing: "gone.host.net.", Zone: "host.net."},
		},
		"an alias for a name under a domain nobody registered": {
			com:  comFor("good.outside.net."),
			name: "store.example.com",
			want: &trace.Dangling{Kind: trace.DanglingAlias, Name: "store.example.com.", Target: "www.nowhere.net.", Missing: "nowhere.net.", Zone: "net."},
		},
		"an alias for a name missing from its own zone is the owner's to fix": {
			com:  comFor("good.outside.net."),
			name: "here.example.com",
		},
		"every nameserver of the zone refusing it": {
			com:    comFor("ns1.host.net.", "ns2.host.net."),
			refuse: true,
			want:   &trace.Dangling{Kind: trace.DanglingLame, Name: "example.com."},
		},
		"a nameserver refusing is not the zone abandoned while another answers": {
			com:    comFor("ns1.host.net.", "good.outside.net."),
			refuse: true,
			answer: true,
		},
		"a glued nameserver refusing falls back to one named outside the zone": {
			com:    comFor("ns1.example", "good.outside.net."),
			refuse: true,
			answer: true,
		},
		"a nameserver named outside the zone beside the glue is only looked up by --all": {
			com:    comFor("ns1.example", "ns.gone.net."),
			answer: true,
		},
		"--all looks up the nameservers named outside the zone beside the glue": {
			com:    comFor("ns1.example", "ns.gone.net."),
			cfg:    resolver.Config{All: true},
			want:   &trace.Dangling{Kind: trace.DanglingNameserver, Name: "example.com.", Target: "ns.gone.net.", Missing: "gone.net.", Zone: "net."},
			answer: true,
		},
		"glued nameservers of both families refusing the zone": {
			com:    comFor("ns1.example", "ns2.example"),
			refuse: true,
			want:   &trace.Dangling{Kind: trace.DanglingLame, Name: "example.com."},
		},
		"a nameserver of a family the walk passed over was never asked": {
			com:    comFor("ns1.example", "ns2.example"),
			refuse: true,
			cfg:    resolver.Config{Family: 4},
		},
		"a zone whose nameservers all answer is not dangling": {
			com:    comFor("ns1.host.net.", "ns2.host.net."),
			answer: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			question := tt.name
			if question == "" {
				question = "www.example.com"
			}
			tr, err := newResolver(t, build(t, tt.com, tt.refuse), tt.cfg).Resolve(t.Context(), question, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			var found []*trace.Dangling
			for step := range tr.Steps() {
				if step.Dangling != nil {
					found = append(found, step.Dangling)
				}
			}
			switch {
			case tt.want == nil && len(found) > 0:
				t.Errorf("got %+v, want nothing left dangling: %s", *found[0], format(steps(tr)))
			case tt.want != nil && len(found) != 1:
				t.Errorf("got %d dangling, want %+v: %s", len(found), *tt.want, format(steps(tr)))
			case tt.want != nil && *found[0] != *tt.want:
				t.Errorf("got %+v, want %+v", *found[0], *tt.want)
			}
			if tt.answer {
				if result := tr.Result(); result == nil || result.Kind != trace.KindAnswer {
					t.Errorf("got %+v, want the answer: %s", result, format(steps(tr)))
				}
			}
		})
	}
}

// TestDanglingLameMarksTheReferral covers where a zone every server refused is
// marked: on the referral that pointed at them, since it is the delegation that
// was left behind, after every one of them was asked.
func TestDanglingLameMarksTheReferral(t *testing.T) {
	t.Parallel()

	const comZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns1.example
example IN NS   ns2.example
ns1.example IN A 192.0.2.3
ns2.example IN A 192.0.2.4
`
	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	for _, address := range []string{"192.0.2.3", "192.0.2.4"} {
		hierarchy.Add(fakens.Config{
			Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: address,
			Behaviour: fakens.Behaviour{Refuse: true},
		})
	}

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var referral *trace.Step
	for step := range tr.Steps() {
		if step.Kind == trace.KindReferral && step.Delegation.Zone == "example.com." {
			referral = step
		}
	}
	if referral == nil {
		t.Fatalf("got no referral to example.com.: %s", format(steps(tr)))
	}
	if referral.Dangling == nil || referral.Dangling.Kind != trace.DanglingLame {
		t.Errorf("got %+v on the referral, want it marked lame: %s", referral.Dangling, format(steps(tr)))
	}
}

// TestDanglingForged covers a denial the chain of trust found forged: it is
// nobody's word, so nothing is read off it as missing.
func TestDanglingForged(t *testing.T) {
	t.Parallel()

	const exampleZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.3
shop  IN CNAME gone.com.
`
	for name, test := range map[string]struct {
		com  fakens.Behaviour
		want bool
	}{
		"a signed denial is read":    {want: true},
		"a forged denial is ignored": {com: fakens.Behaviour{BadSignature: true}},
	} {
		t.Run(name, func(t *testing.T) {
			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: true, Behaviour: test.com})
			hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: true})

			cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t)}
			tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "shop.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			var denial, found *trace.Step
			for step := range tr.Steps() {
				if step.Kind == trace.KindNXDomain {
					denial = step
				}
				if step.Dangling != nil {
					found = step
				}
			}
			if denial == nil {
				t.Fatalf("got no denial of gone.com.: %s", format(steps(tr)))
			}
			if !test.want {
				if denial.DNSSEC == nil || denial.DNSSEC.State != trace.Bogus {
					t.Fatalf("got %+v on the denial, want it bogus", denial.DNSSEC)
				}
				if found != nil {
					t.Errorf("got %+v, want nothing read off a forged denial", *found.Dangling)
				}
				return
			}
			if found == nil || found.Dangling.Missing != "gone.com." {
				t.Errorf("got %+v, want gone.com. read as missing: %s", found, format(steps(tr)))
			}
		})
	}
}
