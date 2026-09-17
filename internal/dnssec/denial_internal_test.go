package dnssec

import (
	"testing"

	"codeberg.org/miekg/dns/dnsutil"
)

// The hashed owner names of RFC 5155 Appendix A, in the order a zone sorts
// them. They are the fixed point this package's arithmetic is checked against:
// a covering test that agrees with a hashing bug of its own would pass anything.
const (
	hashExample = "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM" // example.
	hashNS1     = "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR" // ns1.example.
	hashXYW     = "2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S" // x.y.w.example.
	hashA       = "35MTHGPGCU1QG68FAB165KLNSNK3DPVL" // a.example.
	hashNS2     = "Q04JKCEVQVMU85R014C7DKBA38O0JI5R" // ns2.example.
	hashWild    = "R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN" // *.w.example.
	hashXX      = "T644EBQK9BIBCNA874GIVR6JOJ62MLHV" // xx.example.
)

// TestNSEC3NameMatchesTheRFC pins the hashing to the published vectors, so that
// a change of parameters here cannot quietly start agreeing with itself.
func TestNSEC3NameMatchesTheRFC(t *testing.T) {
	for name, want := range map[string]string{
		"example.":     hashExample,
		"ns1.example.": hashNS1,
		"a.example.":   hashA,
		"ns2.example.": hashNS2,
		"*.w.example.": hashWild,
		"xx.example.":  hashXX,
	} {
		if got := dnsutil.NSEC3Name(dnsutil.Canonical(name), "aabbccdd", 12); got != want {
			t.Errorf("%s hashed to %s, want %s", name, got, want)
		}
	}
}

func TestCovers(t *testing.T) {
	tests := map[string]struct {
		from, to, target string
		want             bool
	}{
		"inside the range": {
			from: hashExample, to: hashA, target: hashNS1, want: true,
		},
		"the other one inside the range": {
			from: hashExample, to: hashA, target: hashXYW, want: true,
		},
		"above the range": {
			from: hashExample, to: hashNS1, target: hashA, want: false,
		},
		"below the range": {
			from: hashA, to: hashNS2, target: hashNS1, want: false,
		},
		"the owner itself is not covered": {
			from: hashExample, to: hashA, target: hashExample, want: false,
		},
		"the next one is not covered": {
			from: hashExample, to: hashA, target: hashA, want: false,
		},
		// The last NSEC3 of a zone wraps past the end of the ordering back to
		// the first, and covers both ends at once.
		// V is the last character of the base32hex alphabet, so this is the
		// highest hash there is.
		"wrapping, above the last": {
			from: hashXX, to: hashExample, target: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", want: true,
		},
		"wrapping, below the first": {
			from: hashXX, to: hashExample, target: "00000000000000000000000000000000", want: true,
		},
		"wrapping, in the part it does not reach": {
			from: hashXX, to: hashExample, target: hashNS2, want: false,
		},
		"nonsense is covered by nothing": {
			from: hashExample, to: hashA, target: "not base32", want: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := covers(test.from, test.to, test.target); got != test.want {
				t.Errorf("covers(%s, %s, %s) = %v, want %v",
					test.from, test.to, test.target, got, test.want)
			}
		})
	}
}

func TestOwnerHash(t *testing.T) {
	tests := map[string]string{
		hashExample + ".example.":                   hashExample,
		"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.": hashExample, // names are case insensitive
		"example.": "EXAMPLE",
		".":        "",
		"":         "",
	}
	for owner, want := range tests {
		if got := ownerHash(owner); got != want {
			t.Errorf("ownerHash(%q) = %q, want %q", owner, got, want)
		}
	}
}

func TestHasType(t *testing.T) {
	bitmap := []uint16{2, 46, 47}
	for _, present := range []uint16{2, 46, 47} {
		if !hasType(bitmap, present) {
			t.Errorf("hasType(%v, %d) = false, want true", bitmap, present)
		}
	}
	for _, absent := range []uint16{1, 43, 6} {
		if hasType(bitmap, absent) {
			t.Errorf("hasType(%v, %d) = true, want false", bitmap, absent)
		}
	}
}
