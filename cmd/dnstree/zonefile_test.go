package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// filedServed is example.com. as its server serves it: the serial a signer
// moved, the MX TTL lowered, the TXT gone, and an alias into a domain nobody
// holds any more.
const (
	filedServed = `
@      300 IN SOA   ns hostmaster 2026111601 7200 3600 1209600 300
@      300 IN NS    ns
ns     300 IN A     192.0.2.3
www    300 IN A     192.0.2.10
@      300 IN MX    10 mail
promo  300 IN CNAME promo.gone.com.
sub    300 IN NS    ns.sub
ns.sub 300 IN A     192.0.2.4
*.wild 300 IN A     192.0.2.1
`
	filedSub = `
@  300 IN SOA ns hostmaster 1 7200 3600 1209600 300
@  300 IN NS  ns
ns 300 IN A   192.0.2.4
`
	// filedZone is the file the operator keeps for it.
	filedZone = `@      300  IN SOA   ns hostmaster 1 7200 3600 1209600 300
@      300  IN NS    ns
ns     300  IN A     192.0.2.3
www    300  IN A     192.0.2.10
@      3600 IN MX    10 mail
old    300  IN TXT   "gone"
promo  300  IN CNAME promo.gone.com.
sub    300  IN NS    ns.sub
ns.sub 300  IN A     192.0.2.4
*.wild 300  IN A     192.0.2.1
`
)

func filing(t *testing.T) {
	hierarchy := fakens.NewHierarchy(t)
	hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: movingRoot, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: movingCom, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: filedServed, Declared: "192.0.2.3"})
	hierarchy.Add(fakens.Config{Name: "ns.sub.example.com.", Origin: "sub.example.com.", Zone: filedSub, Declared: "192.0.2.4"})
	hierarchy.Add(fakens.Config{Name: "ns1.new.net.", Origin: "example.com.", Zone: movingNew, Declared: "192.0.2.9"})

	previous := carried
	t.Cleanup(func() { carried = previous })
	carried = func(inner transport.Transport) transport.Transport { return hierarchy.Transport(inner) }
}

func TestRunZoneFile(t *testing.T) {
	tests := map[string]struct {
		file   string
		args   []string
		want   int
		lines  []string
		stderr string
	}{
		"a file the servers have drifted from": {
			file: filedZone, args: []string{"example.com"}, want: exitAnswer,
			lines: []string{
				"against its servers: 6 names, 8 questions; not asked: 1 wildcard",
				"example.com. SOA same",
				"example.com. NS same",
				"www.example.com. A same",
				"example.com. MX ttl 3600 in the file, 300 at the servers",
				"old.example.com. TXT nxdomain at the servers",
				"promo.example.com. A same; dangling alias: gone.com. is missing",
				"sub.example.com. NS same",
				"6 the same, 2 differ, 1 dangling | serials are not compared",
			},
		},
		"a file held against the servers a zone is moving to": {
			file: "$ORIGIN example.com.\n@ 300 IN SOA ns hostmaster 1 7200 3600 1209600 300\nwww 300 IN A 192.0.2.10\n@ 300 IN MX 10 mail\n",
			args: []string{"--try-ns", "example.com=ns1.new.net@192.0.2.9"}, want: exitAnswer,
			lines: []string{
				"www.example.com. A same",
				"example.com. MX ttl 300 in the file, 86400 at the servers",
				"example.com. SOA only in the file: SOA ns.example.com. hostmaster.example.com. - 7200 3600 1209600 300; only at the servers: SOA ns1.new.net. hostmaster.example.com. - 7200 3600 1209600 300",
			},
		},
		"held to the same, and found otherwise": {
			file: "$ORIGIN example.com.\n" + strings.Join(slices.DeleteFunc(strings.Split(filedZone, "\n"), func(line string) bool {
				return strings.HasPrefix(line, "old") || strings.HasPrefix(line, "promo")
			}), "\n"),
			args: []string{"--expect", "same"}, want: exitExpect,
			stderr: "expected same, got 1 of 6 questions served otherwise than the file says",
		},
		"held to the same, and found it": {
			file: "$ORIGIN example.com.\n@ 300 IN SOA ns hostmaster 1 7200 3600 1209600 300\nwww 300 IN A 192.0.2.10\n",
			args: []string{"--expect", "same"}, want: exitAnswer,
			lines: []string{"www.example.com. A same", "2 the same, 0 differ | serials are not compared"},
		},
		"a file with relative names and no zone named": {
			file: filedZone, want: exitUsage, stderr: "name the zone after --zone-file",
		},
		"a file that is not a zone": {
			file: "www.example.com. 300 IN A 192.0.2.10\n", want: exitUsage, stderr: "no SOA record",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			filing(t)
			path := filepath.Join(t.TempDir(), "db.example")
			if err := os.WriteFile(path, []byte(test.file), 0o600); err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			args := slices.Concat([]string{"--root", "a.root-servers.net.@192.0.2.1", "--timeout", "500ms",
				"--format", "ascii", "--color", "never", "--zone-file", path}, test.args)
			code := run(t.Context(), args, &stdout, &stderr)
			if code != test.want {
				t.Fatalf("got exit %d, want %d:\n%s%s", code, test.want, stdout.String(), stderr.String())
			}
			var got []string
			for line := range strings.Lines(stdout.String()) {
				got = append(got, strings.Join(strings.Fields(line), " "))
			}
			for _, line := range test.lines {
				if !slices.ContainsFunc(got, func(have string) bool { return strings.HasSuffix(have, line) }) {
					t.Errorf("got\n%s\nwant a line %q", stdout.String(), line)
				}
			}
			if !strings.Contains(stderr.String(), test.stderr) {
				t.Errorf("got %q on stderr, want %q", stderr.String(), test.stderr)
			}
		})
	}
}
