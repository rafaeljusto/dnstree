package dnssec_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

const (
	denialSalt = "aabbccdd"
	denialIter = 12
)

var b32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// nsec3 builds one NSEC3 of this zone, spanning from one hash to the next.
func (z *zone) nsec3(tb testing.TB, from, to []byte, flags uint8, bitmap []uint16) *dns.NSEC3 {
	tb.Helper()

	owner := b32.EncodeToString(from) + "." + strings.TrimPrefix(z.name, ".")
	rr := &dns.NSEC3{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: 3600}}
	rr.Hash, rr.Flags, rr.Iterations = 1, flags, denialIter
	rr.Salt, rr.SaltLength = denialSalt, uint8(len(denialSalt)/2)
	rr.HashLength = 20
	rr.NextDomain = b32.EncodeToString(to)
	rr.TypeBitMap = bitmap
	return rr
}

// hashOf is the NSEC3 owner hash of a name under this zone's parameters.
func hashOf(tb testing.TB, name string) []byte {
	tb.Helper()

	raw, err := b32.DecodeString(dnsutil.NSEC3Name(dnsutil.Canonical(name), denialSalt, denialIter))
	if err != nil {
		tb.Fatalf("hashing %s: %v", name, err)
	}
	return raw
}

// step is the hash either side of this one, which is what a range covering
// exactly one name is built from.
func step(hash []byte, by int) []byte {
	out := append([]byte(nil), hash...)
	for i := len(out) - 1; i >= 0; i-- {
		if by > 0 {
			out[i]++
			if out[i] != 0 {
				break
			}
			continue
		}
		if out[i] != 0 {
			out[i]--
			break
		}
		out[i] = 0xff
	}
	return out
}

// entered is the verdict on a zone with no DS, given whatever the parent said
// about it.
func entered(tb testing.TB, authority func(*zone) []dns.RR) *trace.DNSSECStatus {
	tb.Helper()

	root := newZone(tb, ".")
	chain := dnssec.New(root.anchors(tb, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(tb)); status.State != trace.Secure {
		tb.Fatalf("got %+v entering the root, want it secure", status)
	}
	return chain.Enter("example.", authority(root), root.dnskeys(tb))
}

// signedBy is the RRset plus the signature of a zone over it.
func signedBy(tb testing.TB, z *zone, rrset ...dns.RR) []dns.RR {
	tb.Helper()
	return append(rrset, z.sign(tb, rrset, time.Now().Add(time.Hour)))
}

// TestNoDSNeedsAProof is the rule this whole file is about. A delegation with
// no DS is the parent saying the child is unsigned, and anyone able to drop
// records from a referral can say it too. Without the parent's signature over
// the claim, the chain has not gone insecure, it has stopped being checkable.
func TestNoDSNeedsAProof(t *testing.T) {
	status := entered(t, func(*zone) []dns.RR { return nil })
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want a stripped DS not to read as an unsigned zone", status)
	}
	if status.State != trace.Bogus {
		t.Errorf("got %s, want bogus", status.State)
	}
	if !strings.Contains(status.Reason, "no proof") {
		t.Errorf("got reason %q, want it to say the proof is missing", status.Reason)
	}
}

// TestNoDSProvenByNSEC covers the small-zone shape: an NSEC owned by the
// delegation, saying it is a delegation and carries no DS.
func TestNoDSProvenByNSEC(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		nsec := &dns.NSEC{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 3600}}
		nsec.NextDomain = z.name
		nsec.TypeBitMap = []uint16{dns.TypeNS, dns.TypeRRSIG}
		return signedBy(t, z, nsec)
	})
	if status.State != trace.Insecure {
		t.Fatalf("got %+v, want a proven insecure delegation", status)
	}
}

// TestNoDSProvenByNSEC3 covers an NSEC3 naming the delegation outright.
func TestNoDSProvenByNSEC3(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		return signedBy(t, z, z.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeNS, dns.TypeRRSIG}))
	})
	if status.State != trace.Insecure {
		t.Fatalf("got %+v, want a proven insecure delegation", status)
	}
}

// TestNoDSProvenByOptOut covers what com. and net. actually publish: the NSEC3
// of the apex as the closest encloser, and an NSEC3 covering the delegation
// without naming it, with the opt-out flag set.
func TestNoDSProvenByOptOut(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		apex, hash := hashOf(t, "."), hashOf(t, "example.")
		return append(
			signedBy(t, z, z.nsec3(t, apex, step(apex, +1), 1, []uint16{dns.TypeNS, dns.TypeSOA})),
			signedBy(t, z, z.nsec3(t, step(hash, -1), step(hash, +1), 1, []uint16{dns.TypeNS}))...)
	})
	if status.State != trace.Insecure {
		t.Fatalf("got %+v, want an opt-out delegation to read insecure", status)
	}
}

// TestOptOutNeedsTheClosestEncloser covers the span alone. Without the closest
// encloser a referral can name a cut several labels down, below a signed
// delegation, and a real opt-out span over its hash would take it off the
// secure path. RFC 5155 section 8.9.
func TestOptOutNeedsTheClosestEncloser(t *testing.T) {
	root := newZone(t, ".")
	chain := dnssec.New(root.anchors(t, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %+v entering the root, want it secure", status)
	}

	hash := hashOf(t, "www.example.")
	span := signedBy(t, root, root.nsec3(t, step(hash, -1), step(hash, +1), 1, []uint16{dns.TypeNS}))
	if status := chain.Enter("www.example.", span, nil); status.State == trace.Insecure {
		t.Errorf("got %s (%s), want a span with no closest encloser refused", status.State, status.Reason)
	}
}

// TestOptOutBelowASignedCut is the same claim with the proof filled in as far
// as it goes: the closest encloser the parent can show is a delegation that
// has a DS, and a cut is never the closest encloser.
func TestOptOutBelowASignedCut(t *testing.T) {
	root := newZone(t, ".")
	chain := dnssec.New(root.anchors(t, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %+v entering the root, want it secure", status)
	}

	apex, cut, hash := hashOf(t, "."), hashOf(t, "example."), hashOf(t, "www.example.")
	var authority []dns.RR
	for _, nsec3 := range []*dns.NSEC3{
		root.nsec3(t, apex, step(apex, +1), 1, []uint16{dns.TypeNS, dns.TypeSOA}),
		root.nsec3(t, cut, step(cut, +1), 1, []uint16{dns.TypeNS, dns.TypeDS}),
		root.nsec3(t, step(hash, -1), step(hash, +1), 1, []uint16{dns.TypeNS}),
	} {
		authority = append(authority, signedBy(t, root, nsec3)...)
	}
	if status := chain.Enter("www.example.", authority, nil); status.State == trace.Insecure {
		t.Errorf("got %s (%s), want a signed cut refused as the closest encloser", status.State, status.Reason)
	}
}

// TestDenialMustBeSigned covers the proof arriving unsigned, which is the same
// as it not arriving: anyone can write an NSEC3.
func TestDenialMustBeSigned(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		return []dns.RR{z.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeNS})}
	})
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want an unsigned denial refused", status)
	}
}

// TestDenialSignedByAnotherZone covers a proof carrying a signature that does
// not belong to the parent.
func TestDenialSignedByAnotherZone(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		elsewhere := newZone(t, ".")
		hash := hashOf(t, "example.")
		return signedBy(t, elsewhere, z.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeNS}))
	})
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want a denial signed by a stranger refused", status)
	}
}

// TestCoveringWithoutOptOut covers the flag that makes a covering NSEC3 mean
// anything. Without it, covering a delegation says nothing about its DS.
func TestCoveringWithoutOptOut(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		return signedBy(t, z, z.nsec3(t, step(hash, -1), step(hash, +1), 0, []uint16{dns.TypeNS}))
	})
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want a covering NSEC3 with no opt-out refused", status)
	}
}

// TestDenialForAnotherName covers a genuine, properly signed NSEC3 of the same
// zone that simply has nothing to do with this delegation: replaying one must
// not prove anything about another name.
func TestDenialForAnotherName(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "unrelated.")
		return signedBy(t, z, z.nsec3(t, step(hash, -1), step(hash, +1), 1, []uint16{dns.TypeNS}))
	})
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want a denial about another name refused", status)
	}
}

// TestDenialClaimingADS covers a proof that contradicts the referral it came
// with, by saying the delegation does have a DS.
func TestDenialClaimingADS(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		return signedBy(t, z, z.nsec3(t, hash, step(hash, +1), 0,
			[]uint16{dns.TypeNS, dns.TypeDS}))
	})
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want a denial that names a DS refused", status)
	}
}

// TestDenialFromTheChild covers a proof taken from below the cut. The SOA bit
// is what says the record belongs to the child, whose word about its own DS is
// worth nothing.
func TestDenialFromTheChild(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		return signedBy(t, z, z.nsec3(t, hash, step(hash, +1), 0,
			[]uint16{dns.TypeNS, dns.TypeSOA}))
	})
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want a denial from the child refused", status)
	}
}

// TestDenialNotADelegation covers a proof about a name that is not a delegation
// at all, which proves nothing about a zone cut.
func TestDenialNotADelegation(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		return signedBy(t, z, z.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeA}))
	})
	if status.State == trace.Insecure {
		t.Fatalf("got %+v, want a denial that is not about a delegation refused", status)
	}
}

// TestUnsupportedNSEC3Hash covers a hash algorithm this build cannot compute,
// which is a link it could not check rather than one that failed.
func TestUnsupportedNSEC3Hash(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		nsec3 := z.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeNS})
		nsec3.Hash = 2 // nothing defines one
		return signedBy(t, z, nsec3)
	})
	if status.State != trace.Indeterminate {
		t.Fatalf("got %+v, want a hash nothing here computes to read indeterminate", status)
	}
}

// TestNSEC3IterationsAreCapped covers a referral asking the validator to hash
// tens of thousands of times per record. Grinding through it is work an
// attacker gets for the price of one packet, so the link is left unchecked
// rather than checked at any cost.
func TestNSEC3IterationsAreCapped(t *testing.T) {
	root := newZone(t, ".")
	chain := dnssec.New(root.anchors(t, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %+v entering the root, want it secure", status)
	}

	hash := hashOf(t, "example.")
	nsec3 := root.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeNS})
	nsec3.Iterations = 65535

	started := time.Now()
	status := chain.Enter("example.", signedBy(t, root, nsec3), root.dnskeys(t))
	if status.State != trace.Indeterminate {
		t.Fatalf("got %+v, want a refusal to grind to read indeterminate", status)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("took %v, want the iterations rejected rather than run", elapsed)
	}
}

// TestNSEC3HashingIsRecorded covers what --explain holds against RFC 9276: how
// the zone that denied hashes its names, and only once its signature held.
func TestNSEC3HashingIsRecorded(t *testing.T) {
	tests := map[string]struct {
		authority func(testing.TB, *zone) []dns.RR
		want      *trace.NSEC3
	}{
		"a signed NSEC3 is recorded against the parent that signed it": {
			authority: func(tb testing.TB, z *zone) []dns.RR {
				hash := hashOf(tb, "example.")
				return signedBy(tb, z, z.nsec3(tb, hash, step(hash, +1), 0, []uint16{dns.TypeNS, dns.TypeRRSIG}))
			},
			want: &trace.NSEC3{Zone: ".", Iterations: denialIter, Salt: denialSalt},
		},
		"an unsigned NSEC3 is anybody's and recorded as nobody's": {
			authority: func(tb testing.TB, z *zone) []dns.RR {
				hash := hashOf(tb, "example.")
				return []dns.RR{z.nsec3(tb, hash, step(hash, +1), 0, []uint16{dns.TypeNS})}
			},
		},
		"iterations under a hash nothing defines are not SHA-1 rounds": {
			authority: func(tb testing.TB, z *zone) []dns.RR {
				hash := hashOf(tb, "example.")
				nsec3 := z.nsec3(tb, hash, step(hash, +1), 0, []uint16{dns.TypeNS})
				nsec3.Hash = 2
				return signedBy(tb, z, nsec3)
			},
		},
		"a proof that uses no NSEC3 records none": {
			authority: func(tb testing.TB, z *zone) []dns.RR {
				nsec := &dns.NSEC{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 3600}}
				nsec.NextDomain = z.name
				nsec.TypeBitMap = []uint16{dns.TypeNS, dns.TypeRRSIG}
				return signedBy(tb, z, nsec)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := entered(t, func(z *zone) []dns.RR { return test.authority(t, z) }).NSEC3
			switch {
			case test.want == nil && got != nil:
				t.Errorf("got %+v, want no hashing recorded", got)
			case test.want != nil && (got == nil || *got != *test.want):
				t.Errorf("got %+v, want %+v", got, test.want)
			}
		})
	}
}

// TestNSEC3HashingOfADenial covers the other way a denial is checked: an empty
// answer, proven by the zone the chain is in rather than by a parent.
func TestNSEC3HashingOfADenial(t *testing.T) {
	chain, child := secured(t)
	hash := hashOf(t, "there.example.")
	authority := signedBy(t, child, child.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeA, dns.TypeRRSIG}))

	status := chain.Verify(nil, authority, dns.RcodeSuccess, "there.example.", dns.TypeTXT)
	if status.State != trace.Secure {
		t.Fatalf("got %+v, want a proven NODATA", status)
	}
	want := trace.NSEC3{Zone: "example.", Iterations: denialIter, Salt: denialSalt}
	if status.NSEC3 == nil || *status.NSEC3 != want {
		t.Errorf("got %+v, want %+v", status.NSEC3, want)
	}
}

// TestNSEC3HashingTooCostlyIsStillRecorded covers the zone most worth telling:
// one whose iterations are past what the chain will hash, so the link is left
// unchecked, but whose signature over them held.
func TestNSEC3HashingTooCostlyIsStillRecorded(t *testing.T) {
	status := entered(t, func(z *zone) []dns.RR {
		hash := hashOf(t, "example.")
		nsec3 := z.nsec3(t, hash, step(hash, +1), 0, []uint16{dns.TypeNS})
		nsec3.Iterations = 500
		return signedBy(t, z, nsec3)
	})
	if status.State != trace.Indeterminate {
		t.Fatalf("got %+v, want too many iterations to read indeterminate", status)
	}
	if status.NSEC3 == nil || status.NSEC3.Iterations != 500 {
		t.Errorf("got %+v, want the 500 iterations recorded", status.NSEC3)
	}
}
