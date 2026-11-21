package resolver_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
)

func TestReadZoneFile(t *testing.T) {
	const soa = "@ 3600 IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n"
	cases := map[string]struct {
		origin, text string
		want         []string // NAME TYPE: RECORD | RECORD
		wildcards    int
		escaped      int
		unaskable    int
		err          string
		notErr       string
	}{
		"relative names start at the origin given": {
			origin: "example.com", text: soa + "www 300 A 192.0.2.1\n",
			want: []string{
				"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
				"www.example.com. A: www.example.com. 300 A 192.0.2.1",
			},
		},
		"the file's own $ORIGIN needs no origin given": {
			text: "$ORIGIN example.com.\n" + soa + "@ NS ns1\n",
			want: []string{
				"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
				"example.com. NS: example.com. 3600 NS ns1.example.com.",
			},
		},
		"a relative name with no origin asks for the zone to be named": {
			text: soa, err: "name the zone after --zone-file",
		},
		"a relative name in the data with no origin asks for it too": {
			text: "example.com. 3600 IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n", err: "name the zone after --zone-file",
		},
		"a record over several lines is one record": {
			origin: "example.com", text: "@ IN SOA ns1 hostmaster (\n 2 ; serial\n 7200 3600\n 1209600 300 )\n",
			want: []string{"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 2 7200 3600 1209600 300"},
		},
		"the records of one set are one question": {
			origin: "example.com", text: soa + "www A 192.0.2.1\nwww A 192.0.2.2\nwww AAAA 2001:db8::1\n",
			want: []string{
				"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
				"www.example.com. A: www.example.com. 3600 A 192.0.2.1 | www.example.com. 3600 A 192.0.2.2",
				"www.example.com. AAAA: www.example.com. 3600 AAAA 2001:db8::1",
			},
		},
		"an alias is asked as A, so the walk follows it": {
			origin: "example.com", text: soa + "promo CNAME gone.example.net.\n",
			want: []string{
				"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
				"promo.example.com. A: promo.example.com. 3600 CNAME gone.example.net.",
			},
		},
		"a wildcard is counted and not asked": {
			origin: "example.com", text: soa + "* A 192.0.2.1\n*.x A 192.0.2.1\n*.x TXT hi\n",
			want:      []string{"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"},
			wildcards: 2,
		},
		"signatures and denials are left to the signer": {
			origin: "example.com", text: soa +
				"@ RRSIG SOA 13 2 3600 20261201000000 20261101000000 12345 example.com. dGVzdA==\n" +
				"@ NSEC www.example.com. SOA RRSIG NSEC\n",
			want: []string{"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"},
		},
		"a cut keeps its NS and DS and loses its glue": {
			origin: "example.com", text: soa +
				"sub NS ns.sub\nsub DS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n" +
				"ns.sub A 192.0.2.53\nsub A 192.0.2.54\n",
			want: []string{
				"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
				"sub.example.com. NS: sub.example.com. 3600 NS ns.sub.example.com.",
				"sub.example.com. DS: sub.example.com. 3600 DS 12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			},
		},
		"a cut below a cut is the child's to make": {
			origin: "example.com", text: soa + "x.sub NS ns.x.sub\nsub NS ns.sub\n",
			want: []string{
				"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
				"sub.example.com. NS: sub.example.com. 3600 NS ns.sub.example.com.",
			},
		},
		"a private type a signer keeps its state in is counted and not asked": {
			origin: "example.com", text: soa + "@ TYPE65534 \\# 5 0d12340001\n",
			want:      []string{"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"},
			unaskable: 1,
		},
		"a record out of the zone is skipped": {
			origin: "example.com", text: soa + "www.example.net. A 192.0.2.1\n",
			want: []string{"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"},
		},
		"a name with an escape is counted and not asked": {
			origin: "example.com", text: soa + "a\\032b A 192.0.2.1\n",
			want:    []string{"example.com. SOA: example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"},
			escaped: 1,
		},
		"$INCLUDE is refused": {
			origin: "example.com", text: soa + "$INCLUDE other.zone\n", err: "$INCLUDE",
		},
		"$INCLUDE with no origin given is not taken for a relative name": {
			text: "$ORIGIN example.com.\n" + soa + "$INCLUDE other.zone\n", err: "copy what it includes", notErr: "name the zone",
		},
		"a file without a SOA is not a zone": {
			origin: "example.com", text: "www A 192.0.2.1\n", err: "no SOA record",
		},
		"two SOA records are two zones": {
			text: "example.com. SOA ns1.example.com. h.example.com. 1 2 3 4 5\nexample.net. SOA ns1.example.net. h.example.net. 1 2 3 4 5\n",
			err:  "two SOA records",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			file, err := resolver.ReadZoneFile(strings.NewReader(c.text), c.origin, "db.example")
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("got %v, want an error with %q", err, c.err)
				}
				if c.notErr != "" && strings.Contains(err.Error(), c.notErr) {
					t.Fatalf("got %v, want no %q in it", err, c.notErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, q := range file.Questions {
				var records []string
				for _, rr := range q.Records {
					records = append(records, strings.Join([]string{rr.Name, strconv.FormatUint(uint64(rr.TTL), 10), rr.Type, rr.Data}, " "))
				}
				got = append(got, q.Name+" "+q.Type+": "+strings.Join(records, " | "))
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("questions:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
			if file.Zone != "example.com." || file.Wildcards != c.wildcards || file.Escaped != c.escaped || file.Unaskable != c.unaskable {
				t.Errorf("zone %s, %d wildcards, %d escaped, %d unaskable; want example.com., %d, %d and %d",
					file.Zone, file.Wildcards, file.Escaped, file.Unaskable, c.wildcards, c.escaped, c.unaskable)
			}
		})
	}
}

// FuzzReadZoneFile holds what --zone-file asks to the zone the file names:
// whatever a file says, every question is in its zone, none is a wildcard, an
// escape or a signature, and each carries the records it is about.
func FuzzReadZoneFile(f *testing.F) {
	f.Add("@ SOA ns1 h 1 2 3 4 5\nwww A 192.0.2.1\n*.x A 192.0.2.1\nsub NS ns.sub\nns.sub A 192.0.2.2\n")
	f.Add("@ SOA ns1 h ( 1 2\n3 4 5 )\n$ORIGIN x.example.com.\na\\032b TXT \"\\200\"\nc CNAME d\n")
	f.Add("$GENERATE 1-3 h$ A 192.0.2.$\n@ SOA ns1 h 1 2 3 4 5\n@ RRSIG A 13 2 3600 20261201000000 20261101000000 1 example.com. dGVzdA==\n")
	f.Fuzz(func(t *testing.T, text string) {
		file, err := resolver.ReadZoneFile(strings.NewReader(text), "example.com", "fuzz")
		if err != nil {
			return
		}
		zone := strings.ToLower(file.Zone)
		for _, q := range file.Questions {
			if len(q.Records) == 0 {
				t.Fatalf("%s %s carries no records", q.Name, q.Type)
			}
			for _, rr := range q.Records {
				owner := strings.ToLower(rr.Name)
				if owner != zone && !strings.HasSuffix(owner, "."+zone) && zone != "." {
					t.Fatalf("%s is asked, outside %s", rr.Name, zone)
				}
				if strings.HasPrefix(owner, "*.") || strings.Contains(owner, "\\") {
					t.Fatalf("%s is asked, a wildcard or an escape", rr.Name)
				}
				switch rr.Type {
				case "RRSIG", "NSEC", "NSEC3":
					t.Fatalf("%s %s is asked", rr.Name, rr.Type)
				}
			}
		}
	})
}
