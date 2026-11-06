package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// movingRoot and movingCom delegate example.com. to its own server, which a
// copy at a new provider is held against.
const (
	movingRoot = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
`
	movingCom = `
@          IN SOA ns hostmaster 1 7200 3600 1209600 3600
@          IN NS  ns
ns         IN A   192.0.2.2
example    IN NS  ns.example
ns.example IN A   192.0.2.3
`
	movingOld = `
@             300 IN SOA ns hostmaster 1 7200 3600 1209600 300
@             300 IN NS  ns
ns            300 IN A   192.0.2.3
www           300 IN A   192.0.2.10
@             300 IN MX  10 mail
@             300 IN CAA 0 issue "letsencrypt.org"
s1._domainkey 300 IN TXT "v=DKIM1; p=abc"
`
	// movingNew lost the CAA set and the DKIM key, and took a day's TTL
	// on the MX, which is how an export is usually imported.
	movingNew = `
@             300   IN SOA ns1.new.net. hostmaster 2 7200 3600 1209600 300
@             300   IN NS  ns1.new.net.
www           300   IN A   192.0.2.10
@             86400 IN MX  10 mail
new           300   IN A   192.0.2.7
`
)

// moving puts the run's queries through a hierarchy holding example.com. at
// its own server and at a new provider, which refuses everything if told to.
func moving(t *testing.T, refuse bool) {
	hierarchy := fakens.NewHierarchy(t)
	hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: movingRoot, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: movingCom, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: movingOld, Declared: "192.0.2.3"})
	hierarchy.Add(fakens.Config{Name: "ns1.new.net.", Origin: "example.com.", Zone: movingNew, Declared: "192.0.2.9",
		Behaviour: fakens.Behaviour{Refuse: refuse}})

	previous := carried
	t.Cleanup(func() { carried = previous })
	carried = func(inner transport.Transport) transport.Transport { return hierarchy.Transport(inner) }
}

func TestRunCompareNS(t *testing.T) {
	const names = `www.example.com A
example.com MX CAA
s1._domainkey.example.com TXT
new.example.com
`
	tests := map[string]struct {
		refuse bool
		names  string
		args   []string
		want   int
		lines  []string
		stderr string
	}{
		"a copy that lost records and moved a TTL": {
			names: names, want: exitAnswer,
			lines: []string{
				"example.com. at the servers it is delegated to, against ns1.new.net.: 5 questions",
				"  www.example.com. A              same",
				"  example.com. MX                 ttl 300 -> 86400",
				`  example.com. CAA                nodata at the new servers, answer at the old; missing at the new servers: CAA 0 issue "letsencrypt.org"`,
				`  s1._domainkey.example.com. TXT  nxdomain at the new servers, answer at the old; missing at the new servers: TXT "v=DKIM1; p=abc"`,
				"  new.example.com. A              answer at the new servers, nxdomain at the old; only at the new servers: A 192.0.2.7",
				"1 the same, 4 differ | only the questions asked were compared",
			},
		},
		"held to the same, and found otherwise": {
			names: names, args: []string{"--expect", "same"}, want: exitExpect,
			stderr: "expected same, got 4 of 5 questions served otherwise",
		},
		"held to the same, and found it": {
			names: "www.example.com A\n", args: []string{"--expect", "same"}, want: exitAnswer,
			lines: []string{"  www.example.com. A  same", "1 the same, 0 differ | only the questions asked were compared"},
		},
		"new servers that refuse the zone": {
			refuse: true, names: names, want: exitNoAnswer,
			lines: []string{"  the new servers answered none of them: they may not serve example.com. yet"},
		},
		"a question outside the zone": {
			names: "www.example.com A\nwww.example.org A\n", want: exitUsage,
			stderr: "www.example.org. is not in example.com., which --compare-ns tries",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			moving(t, test.refuse)
			previous := stdin
			t.Cleanup(func() { stdin = previous })
			stdin = strings.NewReader(test.names)

			var stdout, stderr bytes.Buffer
			args := slices.Concat([]string{"--root", "a.root-servers.net.@192.0.2.1", "--timeout", "500ms",
				"--format", "ascii", "--color", "never", "--names", "-",
				"--compare-ns", "example.com=ns1.new.net@192.0.2.9"}, test.args)
			code := run(t.Context(), args, &stdout, &stderr)
			if code != test.want {
				t.Fatalf("got exit %d, want %d:\n%s%s", code, test.want, stdout.String(), stderr.String())
			}
			got := strings.Split(stdout.String(), "\n")
			for _, line := range test.lines {
				if !slices.Contains(got, line) {
					t.Errorf("got\n%s\nwant a line %q", stdout.String(), line)
				}
			}
			if !strings.Contains(stderr.String(), test.stderr) {
				t.Errorf("got %q on stderr, want %q", stderr.String(), test.stderr)
			}
		})
	}
}
