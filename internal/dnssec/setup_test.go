package dnssec_test

import (
	"crypto"
	"slices"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// rsaZone is a zone signed with an RSA key of this many bits.
func rsaZone(tb testing.TB, name string, bits int) *zone {
	tb.Helper()

	key := &dns.DNSKEY{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}}
	key.Flags, key.Protocol, key.Algorithm = dns.FlagZONE|dns.FlagSEP, 3, dns.RSASHA256
	private, err := key.Generate(bits)
	if err != nil {
		tb.Fatalf("generating a key: %v", err)
	}
	return &zone{name: name, key: key, private: private.(crypto.Signer)}
}

// standby is a second key for z, which it publishes and signs nothing with.
func standby(tb testing.TB, z *zone, flags uint16) *dns.DNSKEY {
	tb.Helper()

	key := &dns.DNSKEY{Hdr: dns.Header{Name: z.name, Class: dns.ClassINET, TTL: 3600}}
	key.Flags, key.Protocol, key.Algorithm = flags, 3, dns.ECDSAP256SHA256
	if _, err := key.Generate(256); err != nil {
		tb.Fatalf("generating a key: %v", err)
	}
	return key
}

// TestSetupIsRecorded covers what --explain holds against the current advice:
// the keys a secure zone publishes and the DS its parent signed for it, each
// as the walk saw it, and nothing on a verdict that did not hold.
func TestSetupIsRecorded(t *testing.T) {
	tests := map[string]struct {
		child func(testing.TB) *zone
		// ds is what the parent publishes for the child; keys what the child
		// publishes beside its own signing key, which signs the set.
		ds    func(testing.TB, *zone) []dns.RR
		keys  func(testing.TB, *zone) []dns.RR
		state trace.DNSSECState
		want  func(z *zone, ds, keys []dns.RR) ([]trace.Key, []trace.DS)
	}{
		"a zone with one key, and the DS that points at it": {
			child: func(tb testing.TB) *zone { return newZone(tb, "example.") },
			ds:    func(_ testing.TB, z *zone) []dns.RR { return []dns.RR{z.ds()} },
			state: trace.Secure,
			want: func(z *zone, _, _ []dns.RR) ([]trace.Key, []trace.DS) {
				return []trace.Key{{Tag: z.key.KeyTag(), Algorithm: "ECDSAP256SHA256", SEP: true, Pointed: true, Signs: true}},
					[]trace.DS{{Tag: z.key.KeyTag(), Algorithm: "ECDSAP256SHA256", Digest: "SHA256", Match: trace.DSMatched}}
			},
		},
		"a key published and not yet used is neither pointed at nor signing": {
			child: func(tb testing.TB) *zone { return newZone(tb, "example.") },
			ds:    func(_ testing.TB, z *zone) []dns.RR { return []dns.RR{z.ds()} },
			keys: func(tb testing.TB, z *zone) []dns.RR {
				return []dns.RR{standby(tb, z, dns.FlagZONE|dns.FlagSEP), standby(tb, z, dns.FlagSEP)}
			},
			state: trace.Secure,
			want: func(z *zone, _, keys []dns.RR) ([]trace.Key, []trace.DS) {
				return []trace.Key{{Tag: z.key.KeyTag(), Algorithm: "ECDSAP256SHA256", SEP: true, Pointed: true, Signs: true},
						{Tag: keys[0].(*dns.DNSKEY).KeyTag(), Algorithm: "ECDSAP256SHA256", SEP: true}},
					[]trace.DS{{Tag: z.key.KeyTag(), Algorithm: "ECDSAP256SHA256", Digest: "SHA256", Match: trace.DSMatched}}
			},
		},
		"a SHA-1 DS, a DS for no key and one nothing here can digest are each recorded": {
			child: func(tb testing.TB) *zone { return newZone(tb, "example.") },
			ds: func(tb testing.TB, z *zone) []dns.RR {
				gone := newZone(tb, "example.").ds()
				unknown := z.ds()
				unknown.DigestType = 99
				return []dns.RR{z.ds(), z.key.ToDS(dns.SHA1), gone, unknown}
			},
			state: trace.Secure,
			want: func(z *zone, ds, _ []dns.RR) ([]trace.Key, []trace.DS) {
				tag := z.key.KeyTag()
				return []trace.Key{{Tag: tag, Algorithm: "ECDSAP256SHA256", SEP: true, Pointed: true, Signs: true}},
					[]trace.DS{
						{Tag: tag, Algorithm: "ECDSAP256SHA256", Digest: "SHA256", Match: trace.DSMatched},
						{Tag: tag, Algorithm: "ECDSAP256SHA256", Digest: "SHA1", Match: trace.DSMatched},
						{Tag: ds[2].(*dns.DS).KeyTag, Algorithm: "ECDSAP256SHA256", Digest: "SHA256", Match: trace.DSUnmatched},
						{Tag: tag, Algorithm: "ECDSAP256SHA256", Digest: "digest 99", Match: trace.DSUnchecked},
					}
			},
		},
		"an RSA key carries the length of its modulus": {
			child: func(tb testing.TB) *zone { return rsaZone(tb, "example.", 1024) },
			ds:    func(_ testing.TB, z *zone) []dns.RR { return []dns.RR{z.ds()} },
			state: trace.Secure,
			want: func(z *zone, _, _ []dns.RR) ([]trace.Key, []trace.DS) {
				return []trace.Key{{Tag: z.key.KeyTag(), Algorithm: "RSASHA256", SEP: true, Bits: 1024, Pointed: true, Signs: true}},
					[]trace.DS{{Tag: z.key.KeyTag(), Algorithm: "RSASHA256", Digest: "SHA256", Match: trace.DSMatched}}
			},
		},
		"a zone whose DS points at no key records nothing": {
			child: func(tb testing.TB) *zone { return newZone(tb, "example.") },
			ds:    func(tb testing.TB, _ *zone) []dns.RR { return []dns.RR{newZone(tb, "example.").ds()} },
			state: trace.Bogus,
			want:  func(*zone, []dns.RR, []dns.RR) ([]trace.Key, []trace.DS) { return nil, nil },
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root, child := newZone(t, "."), test.child(t)
			chain := dnssec.New(root.anchors(t, dns.SHA256))
			if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
				t.Fatalf("got %+v entering the root, want it secure", status)
			}

			delegated := test.ds(t, child)
			// Signing puts the set in canonical order, and the cases name their
			// records by where they put them.
			authority := append(slices.Clone(delegated), root.sign(t, slices.Clone(delegated), time.Now().Add(time.Hour)))
			var extra []dns.RR
			if test.keys != nil {
				extra = test.keys(t, child)
			}
			keys := append([]dns.RR{child.key}, extra...)
			dnskeys := append(slices.Clone(keys), child.sign(t, slices.Clone(keys), time.Now().Add(time.Hour)))

			status := chain.Enter("example.", authority, dnskeys)
			if status.State != test.state {
				t.Fatalf("got %+v, want %s", status, test.state)
			}

			// The order is the chain's to choose, so long as it is always the
			// same one, whatever order the server sent the records in.
			wantKeys, wantDS := test.want(child, delegated, extra)
			if !sameSet(status.Keys, wantKeys) {
				t.Errorf("got keys %+v, want %+v", status.Keys, wantKeys)
			}
			if !sameSet(status.DS, wantDS) {
				t.Errorf("got DS %+v, want %+v", status.DS, wantDS)
			}
			if !slices.IsSortedFunc(status.Keys, func(a, b trace.Key) int { return int(a.Tag) - int(b.Tag) }) {
				t.Errorf("got keys %+v, want them in order of their tags", status.Keys)
			}
			if !slices.IsSortedFunc(status.DS, func(a, b trace.DS) int { return int(a.Tag) - int(b.Tag) }) {
				t.Errorf("got DS %+v, want them in order of their tags", status.DS)
			}
		})
	}
}

func sameSet[T comparable](got, want []T) bool {
	if len(got) != len(want) {
		return false
	}
	for _, item := range want {
		if !slices.Contains(got, item) {
			return false
		}
	}
	return true
}

// TestSetupOfTheRoot covers the zone whose DS are the trust anchors: its keys
// are recorded, and no DS is, since nothing above it published one.
func TestSetupOfTheRoot(t *testing.T) {
	root := newZone(t, ".")
	status := dnssec.New(root.anchors(t, dns.SHA256)).Enter(".", nil, root.dnskeys(t))
	if status.State != trace.Secure {
		t.Fatalf("got %+v, want the root secure", status)
	}
	if len(status.Keys) != 1 || !status.Keys[0].Pointed {
		t.Errorf("got keys %+v, want the root's key, pointed at by the anchor", status.Keys)
	}
	if status.DS != nil {
		t.Errorf("got DS %+v, want none for the root", status.DS)
	}
}
