package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
)

// TestPointingRules covers records that point where the standards say they
// must not. They resolve through forgiving resolvers and fail through strict
// ones, and the walk, which is strict, says why.
func TestPointingRules(t *testing.T) {
	t.Parallel()

	const (
		// example.com. is served by a nameserver named in co.uk., where that
		// name is an alias.
		aliasedCom = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns.example.co.uk.
`
		aliasedCoUK = `
@          IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@          IN NS    ns
ns         IN A     192.0.2.4
ns.example IN CNAME host
host       IN A     192.0.2.3
`
		// The glue is right, and the zone itself makes the nameserver an
		// alias.
		aliasedInZone = `
@     IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@     IN NS    ns
ns    IN CNAME host
host  IN A     192.0.2.3
www   IN A     192.0.2.10
`
		apexAlias = `
@     IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@     IN NS    ns
@     IN CNAME www.example.co.uk.
ns    IN A     192.0.2.3
`
		addressCom = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   192.0.2.3.
`
	)

	tests := map[string]struct {
		com, example string
		checkNS      bool
		qname        string
		want         string
	}{
		"a nameserver named by an alias": {
			com: aliasedCom, example: exampleZone, qname: "www.example.com",
			want: "example.com. delegates to ns.example.co.uk., which is an alias for host.co.uk.; name the nameserver by its own name, since resolvers need not follow an alias to find one (RFC 2181 section 10.3)"},
		"a nameserver the zone makes an alias": {
			com: comZone, example: aliasedInZone, checkNS: true, qname: "www.example.com",
			want: "example.com. delegates to ns.example.com., which is an alias for host.example.com.; name the nameserver by its own name, since resolvers need not follow an alias to find one (RFC 2181 section 10.3)"},
		"an alias at the top of a zone": {
			com: comZone, example: apexAlias, qname: "example.com",
			want: "example.com. is an alias at the top of its zone, which hides the zone's SOA and NS from every resolver that asks (RFC 1034 section 3.6.2); serve the records there rather than an alias"},
		"a nameserver named by its address": {
			com: addressCom, example: exampleZone, qname: "www.example.com",
			want: "example.com. delegates to 192.0.2.3., which is an address written as a name, and nothing resolves it; name the nameserver instead (RFC 1035 section 3.3.11)"},
		"an alias below the top of a zone is fine": {
			com: comZone, example: exampleZone + "alias IN CNAME www\n", qname: "alias.example.com"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: test.com, Declared: "192.0.2.2"})
			hierarchy.Add(fakens.Config{Name: "ns.co.uk.", Origin: "co.uk.", Zone: aliasedCoUK, Declared: "192.0.2.4"})
			hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: test.example, Declared: "192.0.2.3"})

			tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{CheckNS: test.checkNS}).
				Resolve(t.Context(), test.qname, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			var pointing []string
			for _, warning := range tr.Warnings {
				if strings.Contains(warning, "RFC 2181") || strings.Contains(warning, "RFC 1034") || strings.Contains(warning, "RFC 1035") {
					pointing = append(pointing, warning)
				}
			}
			switch {
			case test.want == "" && len(pointing) > 0:
				t.Errorf("got %q, want none", pointing)
			case test.want != "" && !slices.Equal(pointing, []string{test.want}):
				t.Errorf("got %q, want once %q", pointing, test.want)
			}
		})
	}
}
