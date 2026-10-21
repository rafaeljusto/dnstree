package resolver_test

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestUnroutableNameserver covers a delegation that hands out an address no
// resolver on the internet can reach, which from outside looks like a server
// that stopped answering. Every address a walk here asks is declared, so
// nothing leaves the machine; the roots sit on a public address, which is
// what tells a walk of the internet from a lab.
func TestUnroutableNameserver(t *testing.T) {
	t.Parallel()

	const publicRoot = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    198.41.0.4
com.                IN NS   ns.com.
ns.com.             IN A    192.5.6.30
net.                IN NS   ns.net.
ns.net.             IN A    192.5.6.31
`
	const com = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
example    IN NS   ns.example
`
	const example = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
www   IN A    45.0.0.10
`
	const net = `
@               IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@               IN NS   ns
outside         IN NS   ns.outside
ns.outside      IN A    45.0.0.4
`
	const outside = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    45.0.0.4
ns.example IN A 192.0.2.53
`

	tests := map[string]struct {
		root, rootAt string
		com          string
		example      string // the zone at ns.example.com., beside its glue
		at           string // where the example.com. server listens
		cfg          resolver.Config
		want         string // the warning, empty for none
		note         string // what the hop to example.com. says, empty for nothing
		skipped      string // an address left unasked whose hop names its kind, empty for none
	}{
		"private glue": {
			com: com + "ns.example IN A 10.0.0.53\n", at: "10.0.0.53",
			want: "com. gives 10.0.0.53 for ns.example.com., a private address no resolver on the internet can reach, usually a record from an internal view of the zone; have the registrar replace it with the server's public address",
			note: "private address"},
		"loopback glue beside a public address": {
			com: com + "ns.example IN A 45.0.0.3\nns.example IN A 127.0.0.1\n", at: "45.0.0.3",
			want:    "com. gives 127.0.0.1 for ns.example.com., a loopback address, which every resolver takes for itself, usually a placeholder never replaced; have the registrar replace it with the server's public address",
			skipped: "127.0.0.1"},
		"glue in a carrier's shared space": {
			com: com + "ns.example IN A 100.64.0.53\n", at: "100.64.0.53",
			want: "com. gives 100.64.0.53 for ns.example.com., an address in the space carriers number their own customers from (RFC 6598), which resolvers outside that carrier cannot reach; have the registrar replace it with the server's public address",
			note: "shared address"},
		"a nameserver named elsewhere, looked up to an example address": {
			com: strings.Replace(com, "example    IN NS   ns.example", "example    IN NS   ns.example.outside.net.", 1), at: "192.0.2.53",
			want: "outside.net. gives 192.0.2.53 for ns.example.outside.net., an address kept for documentation that no resolver on the internet can reach, usually an example never replaced; publish the server's public address in outside.net.",
			note: "documentation address"},
		"the zone's own copy under --check-ns": {
			com: com + "ns.example IN A 45.0.0.3\n", example: "ns IN A 10.0.0.53\n", at: "45.0.0.3",
			cfg:  resolver.Config{CheckNS: true},
			want: "example.com. gives 10.0.0.53 for ns.example.com., a private address no resolver on the internet can reach, usually a record from an internal view of the zone; publish the server's public address in example.com."},
		"a public address": {
			com: com + "ns.example IN A 45.0.0.3\n", at: "45.0.0.3"},
		"a walk started from a lab's root": {
			root: strings.Replace(publicRoot, "198.41.0.4", "10.0.0.1", 1), rootAt: "10.0.0.1",
			com: com + "ns.example IN A 10.0.0.53\n", at: "10.0.0.53"},
		"an address --try-ns was given": {
			com: com + "ns.example IN A 45.0.0.3\n", at: "10.0.0.53",
			cfg: resolver.Config{Try: &trace.Trial{Zone: "example.com.", NS: []string{"10.0.0.53"},
				Addrs: map[string][]netip.Addr{"10.0.0.53": {netip.MustParseAddr("10.0.0.53")}}}}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root, rootAt := cmp.Or(test.root, publicRoot), cmp.Or(test.rootAt, "198.41.0.4")
			hierarchy := fakens.NewHierarchy(t)
			start := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: root, Declared: rootAt})
			hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: test.com + "ns IN A 192.5.6.30\n", Declared: "192.5.6.30"})
			hierarchy.Add(fakens.Config{Name: "ns.net.", Origin: "net.", Zone: net + "ns IN A 192.5.6.31\n", Declared: "192.5.6.31"})
			hierarchy.Add(fakens.Config{Name: "ns.outside.net.", Origin: "outside.net.", Zone: outside, Declared: "45.0.0.4"})
			own := "ns IN A " + test.at + "\n"
			if test.example != "" {
				own = test.example
			}
			hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: example + own, Declared: test.at})

			tr, err := newResolver(t, harness{hierarchy, start}, test.cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if result := tr.Result(); result == nil || result.Kind != trace.KindAnswer {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}

			var reach []string
			for _, warning := range tr.Warnings {
				if strings.Contains(warning, " gives ") {
					reach = append(reach, warning)
				}
			}
			switch {
			case test.want == "" && len(reach) > 0:
				t.Errorf("got %q, want no warning", reach)
			case test.want != "" && !slices.Contains(reach, test.want):
				t.Errorf("got %q, want %q", reach, test.want)
			}
			if test.want != "" && tr.About[test.want] != (trace.Concern{Area: trace.AreaDelegation, Zone: "example.com."}) {
				t.Errorf("got %+v, want it graded under the delegation of example.com.", tr.About[test.want])
			}

			asked := false
			for step := range tr.Steps() {
				if step.Zone != "example.com." || step.Server.IP != netip.MustParseAddr(test.at) {
					continue
				}
				asked = true
				if got := slices.Contains(step.Notes, test.note); test.note != "" && !got {
					t.Errorf("got notes %q on the hop to %s, want %q", step.Notes, test.at, test.note)
				}
				if test.note == "" && slices.ContainsFunc(step.Notes, func(note string) bool { return strings.HasSuffix(note, " address") }) {
					t.Errorf("got notes %q on the hop to %s, want none about its address", step.Notes, test.at)
				}
			}
			if !asked {
				t.Errorf("got no hop to %s: %s", test.at, format(steps(tr)))
			}
			if test.skipped != "" && !slices.ContainsFunc(steps(tr), func(step *trace.Step) bool {
				return step.Kind == trace.KindSkipped && step.Server.IP == netip.MustParseAddr(test.skipped) && slices.Contains(step.Notes, "loopback address")
			}) {
				t.Errorf("got no hop left unasked at %s noted as loopback: %s", test.skipped, format(steps(tr)))
			}
		})
	}
}
