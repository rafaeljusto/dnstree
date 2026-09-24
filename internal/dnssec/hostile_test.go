package dnssec_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/dnssec"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// record is one record in presentation format, the way the other tests here
// build them.
func record(tb testing.TB, s string) dns.RR {
	tb.Helper()

	rr, err := dns.New(s)
	if err != nil {
		tb.Fatalf("reading %q: %v", s, err)
	}
	return rr
}

// TestStrayKeyDoesNotSpoilTheKeySet covers a server answering a DNSKEY query
// with the zone's own key set and one key belonging to somebody else. The codec
// signs whatever set it is handed and does not check that a set is a set, so a
// key set read without looking at the owners no longer matches the signature
// the zone made, and a sound zone reads as bogus.
func TestStrayKeyDoesNotSpoilTheKeySet(t *testing.T) {
	root := newZone(t, ".")
	elsewhere := newZone(t, "attacker.example.")
	chain := dnssec.New(root.anchors(t, dns.SHA256))

	dnskeys := append(root.dnskeys(t), elsewhere.key)

	status := chain.Enter(".", nil, dnskeys)
	if status.State != trace.Secure {
		t.Fatalf("got %s (%s), want the stray key ignored and the zone secure",
			status.State, status.Reason)
	}
	if chain.State() != trace.Secure {
		t.Errorf("got chain state %s, want secure", chain.State())
	}
}

// TestStrayKeyIsNotTrusted is the other half of the same rule: a key that
// arrived in the key set but that no DS vouches for must not verify anything.
func TestStrayKeyIsNotTrusted(t *testing.T) {
	root := newZone(t, ".")
	elsewhere := newZone(t, "attacker.example.")
	chain := dnssec.New(root.anchors(t, dns.SHA256))

	if status := chain.Enter(".", nil, append(root.dnskeys(t), elsewhere.key)); status.State != trace.Secure {
		t.Fatalf("got %s (%s), want secure", status.State, status.Reason)
	}

	answer := []dns.RR{record(t, `example. 3600 IN TXT "forged"`)}
	answer = append(answer, elsewhere.sign(t, answer, time.Now()))

	if status := chain.Verify(answer, nil, dns.RcodeSuccess, "example.", dns.TypeTXT); status.State == trace.Secure {
		t.Errorf("got %+v, want an answer signed by a key nobody vouched for refused", status)
	}
}

// TestVerifyNamesTheKeyThatSigned covers a zone mid rollover, where an RRset
// carries more than one signature. The verdict has to name the key that held,
// not whichever signature came first in the message.
func TestVerifyNamesTheKeyThatSigned(t *testing.T) {
	root := newZone(t, ".")
	retired := newZone(t, ".")
	chain := dnssec.New(root.anchors(t, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %s (%s), want secure", status.State, status.Reason)
	}

	rrset := []dns.RR{record(t, `example. 3600 IN TXT "hello"`)}

	// The retired key signs first, so it is the one a report reading
	// signatures[0] would name.
	answer := append([]dns.RR{}, rrset...)
	answer = append(answer, retired.sign(t, rrset, time.Now()))
	answer = append(answer, root.sign(t, rrset, time.Now()))

	status := chain.Verify(answer, nil, dns.RcodeSuccess, "example.", dns.TypeTXT)
	if status.State != trace.Secure {
		t.Fatalf("got %s (%s), want secure", status.State, status.Reason)
	}
	if len(status.KeyTags) != 1 || status.KeyTags[0] != root.key.KeyTag() {
		t.Errorf("got key tags %v, want the key that actually signed (%d)",
			status.KeyTags, root.key.KeyTag())
	}
}

// TestUnusableNSEC3ProvesNothing covers a spoofed NXDOMAIN whose only denial is
// an unsigned NSEC3 nothing here can hash. Such a record is ignored, not taken
// as a reason to stop checking (RFC 5155 section 8.1), so the NXDOMAIN is left
// with no proof at all.
func TestUnusableNSEC3ProvesNothing(t *testing.T) {
	for name, text := range map[string]string{
		"an unknown hash algorithm":        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.example. 3600 IN NSEC3 2 0 0 - BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		"more iterations than worth doing": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.example. 3600 IN NSEC3 1 0 101 - BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	} {
		t.Run(name, func(t *testing.T) {
			chain, _ := secured(t)
			status := chain.Verify(nil, []dns.RR{record(t, text)}, dns.RcodeNameError, "www.example.", dns.TypeA)
			if status.State != trace.Bogus {
				t.Errorf("got %s (%s), want bogus", status.State, status.Reason)
			}
		})
	}
}

// TestUnsignedOptOutIsNoExcuse covers a wildcard answer stretched over a name,
// excused by an opt-out NSEC3 the zone never signed.
func TestUnsignedOptOutIsNoExcuse(t *testing.T) {
	chain, z := secured(t)
	answer := wildcardAnswer(t, z, "*.example.", "www.example.")
	hash := hashOf(t, "www.example.")
	optout := z.nsec3(t, step(hash, -1), step(hash, +1), 1, nil)

	status := chain.Verify(answer, []dns.RR{optout}, dns.RcodeSuccess, "www.example.", dns.TypeTXT)
	if status.State != trace.Bogus {
		t.Errorf("got %s (%s), want bogus", status.State, status.Reason)
	}
}

// TestParentDenialSpeaksOnlyForTheDS covers the NSEC a parent signs at a
// delegation, replayed for names it knows nothing about: RFC 6840 section 4.1.
// The names below the cut are the child's, and so is every type at the cut but
// the DS.
func TestParentDenialSpeaksOnlyForTheDS(t *testing.T) {
	tests := map[string]struct {
		rcode  uint16
		qname  string
		qtype  uint16
		secure bool
	}{
		"a name below the cut is not denied":    {dns.RcodeNameError, "www.sub.example.", dns.TypeA, false},
		"a type at the cut is not denied":       {dns.RcodeSuccess, "sub.example.", dns.TypeA, false},
		"the DS at the cut is the parent's own": {dns.RcodeSuccess, "sub.example.", dns.TypeDS, true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chain, z := secured(t)
			authority := z.nsec(t, "sub.example.", "zzz.example.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
			// The apex gap holds every wildcard, so only the cut is in question.
			authority = append(authority, z.nsec(t, "example.", "sub.example.", dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC)...)

			status := chain.Verify(nil, authority, test.rcode, test.qname, test.qtype)
			if (status.State == trace.Secure) != test.secure {
				t.Errorf("got %s (%s), want secure=%v", status.State, status.Reason, test.secure)
			}
		})
	}
}

// TestParentNSEC3IsNoClosestEncloser is the same replay with NSEC3: the record
// matching the delegation cannot be the closest encloser of a name below it.
func TestParentNSEC3IsNoClosestEncloser(t *testing.T) {
	chain, z := secured(t)

	cut := z.nsec3(t, hashOf(t, "sub.example."), step(hashOf(t, "sub.example."), +1), 0,
		[]uint16{dns.TypeNS, dns.TypeRRSIG})
	authority := signedBy(t, z, cut)
	for _, name := range []string{"www.sub.example.", "*.sub.example."} {
		hash := hashOf(t, name)
		authority = append(authority, signedBy(t, z, z.nsec3(t, step(hash, -1), step(hash, +1), 0, nil))...)
	}

	status := chain.Verify(nil, authority, dns.RcodeNameError, "www.sub.example.", dns.TypeA)
	if status.State == trace.Secure {
		t.Errorf("got %s (%s), want a delegation refused as the closest encloser", status.State, status.Reason)
	}
}

// TestUnimplementedAlgorithmIsIndeterminate covers a zone signed with an
// algorithm this build cannot verify. The signature did not fail, it went
// unchecked, and bogus has to keep meaning a signature that failed.
func TestUnimplementedAlgorithmIsIndeterminate(t *testing.T) {
	root := newZone(t, ".")
	chain := dnssec.New(root.anchors(t, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %+v entering the root, want it secure", status)
	}

	key := &dns.DNSKEY{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 3600}}
	key.Flags, key.Protocol, key.Algorithm = 257, 3, 200
	key.PublicKey = "AwEAAbWkWQ3LgGHvnKjDq0U3ZuaO5w=="
	signature := record(t, fmt.Sprintf(
		"example. 3600 IN RRSIG DNSKEY 200 1 3600 20300101000000 20200101000000 %d example. AAECAwQFBgcICQ==", key.KeyTag()))
	ds := key.ToDS(dns.SHA256)
	authority := []dns.RR{ds, root.sign(t, []dns.RR{ds}, time.Now().Add(time.Hour))}

	status := chain.Enter("example.", authority, []dns.RR{key, signature})
	if status.State != trace.Indeterminate {
		t.Errorf("got %s (%s), want indeterminate", status.State, status.Reason)
	}
}

// TestStandbyKeyListedFirst covers a DS set naming a key that is published but
// not yet signing, ahead of the one that is. That is how every KSK rollover
// starts, the root's included, so every key the DS points at has to be tried.
func TestStandbyKeyListedFirst(t *testing.T) {
	root := newZone(t, ".")
	chain := dnssec.New(root.anchors(t, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %+v entering the root, want it secure", status)
	}

	active, standby := newZone(t, "example."), newZone(t, "example.")
	dsset := []dns.RR{standby.ds(), active.ds()}
	authority := append(append([]dns.RR{}, dsset...), root.sign(t, dsset, time.Now().Add(time.Hour)))
	keyset := []dns.RR{standby.key, active.key}
	dnskeys := append(append([]dns.RR{}, keyset...), active.sign(t, keyset, time.Now().Add(time.Hour)))

	status := chain.Enter("example.", authority, dnskeys)
	if status.State != trace.Secure {
		t.Fatalf("got %s (%s), want secure", status.State, status.Reason)
	}
	if len(status.KeyTags) != 1 || status.KeyTags[0] != active.key.KeyTag() {
		t.Errorf("got key tags %v, want the key that signed, %d", status.KeyTags, active.key.KeyTag())
	}
}

// TestDNAMESynthesis covers the CNAME a DNAME makes, which nobody signs. The
// signed DNAME vouches for it, but only for the CNAME it would make itself.
func TestDNAMESynthesis(t *testing.T) {
	tests := map[string]struct {
		target string
		signed bool
		want   trace.DNSSECState
	}{
		"the CNAME is what the DNAME makes": {"www.new.example.", true, trace.Secure},
		"the CNAME points somewhere else":   {"www.elsewhere.test.", true, trace.Bogus},
		"the DNAME is not signed either":    {"www.new.example.", false, trace.Bogus},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chain, z := secured(t)
			dname := record(t, "old.example. 3600 IN DNAME new.example.")
			answer := []dns.RR{dname}
			if test.signed {
				answer = append(answer, z.sign(t, []dns.RR{dname}, time.Now().Add(time.Hour)))
			}
			answer = append(answer, record(t, "www.old.example. 3600 IN CNAME "+test.target))

			status := chain.Verify(answer, nil, dns.RcodeSuccess, "www.old.example.", dns.TypeA)
			if status.State != test.want {
				t.Errorf("got %s (%s), want %s", status.State, status.Reason, test.want)
			}
		})
	}
}

// TestOptOutDenialIsInsecure covers the denials that rest on an opt-out range.
// The range leaves unsigned delegations out of the chain, so all it proves is
// that the name is outside the signed part of the zone: RFC 5155 sections 8.6
// and 9.2.
func TestOptOutDenialIsInsecure(t *testing.T) {
	tests := map[string]struct {
		rcode uint16
		qname string
		qtype uint16
	}{
		"a name error":                    {dns.RcodeNameError, "www.example.", dns.TypeA},
		"no DS at an unlisted delegation": {dns.RcodeSuccess, "www.example.", dns.TypeDS},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chain, z := secured(t)
			apex, next, wild := hashOf(t, "example."), hashOf(t, "www.example."), hashOf(t, "*.example.")
			var authority []dns.RR
			authority = append(authority, signedBy(t, z, z.nsec3(t, apex, step(apex, +1), 1, []uint16{dns.TypeSOA, dns.TypeNS}))...)
			authority = append(authority, signedBy(t, z, z.nsec3(t, step(next, -1), step(next, +1), 1, nil))...)
			authority = append(authority, signedBy(t, z, z.nsec3(t, step(wild, -1), step(wild, +1), 1, nil))...)

			status := chain.Verify(nil, authority, test.rcode, test.qname, test.qtype)
			if status.State != trace.Insecure {
				t.Errorf("got %s (%s), want insecure", status.State, status.Reason)
			}
		})
	}
}

// TestTooManyNSEC3 covers a response stuffed with NSEC3 records at the
// iteration cap, for a name as long as a name gets. Each record is hashed
// against each label, so the count is capped before any hashing starts.
func TestTooManyNSEC3(t *testing.T) {
	chain, z := secured(t)
	qname := strings.Repeat("a.", 120) + "example."

	var authority []dns.RR
	for i := range 900 {
		hash := make([]byte, 20)
		hash[18], hash[19] = byte(i>>8), byte(i)
		nsec3 := z.nsec3(t, hash, step(hash, +1), 0, nil)
		nsec3.Iterations = 100
		authority = append(authority, nsec3)
	}

	status := chain.Verify(nil, authority, dns.RcodeNameError, qname, dns.TypeA)
	if status.State != trace.Bogus || !strings.Contains(status.Reason, "more than any proof needs") {
		t.Errorf("got %s (%s), want bogus for the count alone", status.State, status.Reason)
	}
}

// relabelled is the zone's signed NSEC for its wildcard, moved onto another
// owner and not signed again. The signature covers one label fewer than the
// owner has, so the codec rebuilds the wildcard and the maths still holds.
func relabelled(tb testing.TB, z *zone, owner string) []dns.RR {
	tb.Helper()

	rrs := z.nsec(tb, "*.example.", "mail.example.", dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)
	rrs[0].Header().Name, rrs[1].Header().Name = owner, owner
	return rrs
}

// TestWildcardDenialCannotBeMoved covers a replay of the NSEC a zone signs for
// its wildcard, under a name the zone signed no denial for: RFC 4035 section
// 5.3.4. The record is the zone's, the owner is the attacker's.
func TestWildcardDenialCannotBeMoved(t *testing.T) {
	for name, tc := range map[string]struct {
		answer func(*zone) []dns.RR
		owner  string
		qname  string
		qtype  uint16
		rcode  uint16
	}{
		"a NODATA for a name that exists": {
			owner: "www.example.", qname: "www.example.", qtype: dns.TypeA, rcode: dns.RcodeSuccess,
		},
		"an NXDOMAIN for a name inside the span": {
			owner: "!.example.", qname: "foo.example.", qtype: dns.TypeA, rcode: dns.RcodeNameError,
		},
		"a wildcard stretched over a name inside the span": {
			answer: func(z *zone) []dns.RR { return wildcardAnswer(t, z, "*.example.", "foo.example.") },
			owner:  "!.example.", qname: "foo.example.", qtype: dns.TypeTXT, rcode: dns.RcodeSuccess,
		},
	} {
		t.Run(name, func(t *testing.T) {
			chain, z := secured(t)
			var answer []dns.RR
			if tc.answer != nil {
				answer = tc.answer(z)
			}
			status := chain.Verify(answer, relabelled(t, z, tc.owner), tc.rcode, tc.qname, tc.qtype)
			if status.State != trace.Bogus {
				t.Errorf("got %s (%s), want bogus", status.State, status.Reason)
			}
		})
	}
}

// TestWildcardDenialAtItsOwnName is the same record where it belongs: a
// wildcard answering for a name, without the type asked for.
func TestWildcardDenialAtItsOwnName(t *testing.T) {
	chain, z := secured(t)

	authority := z.nsec(t, "*.example.", "mail.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(nil, authority, dns.RcodeSuccess, "foo.example.", dns.TypeTXT)
	if status.State != trace.Secure {
		t.Errorf("got %s (%s), want the wildcard's own denial accepted", status.State, status.Reason)
	}
}

// TestUnsignedClosestEncloser covers an NSEC3 nobody signed, naming an
// ancestor that does not exist. Taken at its word it moves the closest
// encloser below the wildcard that answers for the name, and the zone's own
// signed gaps then deny everything the proof still asks about.
func TestUnsignedClosestEncloser(t *testing.T) {
	chain, z := secured(t)

	covering := func(name string) []dns.RR {
		hash := hashOf(t, name)
		return signedBy(t, z, z.nsec3(t, step(hash, -1), step(hash, +1), 0, nil))
	}
	fake := hashOf(t, "b.example.")
	authority := []dns.RR{z.nsec3(t, fake, step(fake, +1), 0, []uint16{dns.TypeTXT})}
	authority = append(authority, covering("a.b.example.")...)
	authority = append(authority, covering("*.b.example.")...)

	status := chain.Verify(nil, authority, dns.RcodeNameError, "a.b.example.", dns.TypeA)
	if status.State != trace.Bogus {
		t.Errorf("got %s (%s), want an unsigned closest encloser refused", status.State, status.Reason)
	}
}

// TestUnusableNSEC3AreCounted covers a response stuffed with NSEC3 records this
// build will not read, sharing an owner and each carrying a signature by the
// zone's key over something else. Checking them one by one packs the whole set
// against every signature, so they count against the cap like any other.
func TestUnusableNSEC3AreCounted(t *testing.T) {
	chain, z := secured(t)
	owner := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.example."

	var authority []dns.RR
	for i := range 40 {
		hash := make([]byte, 20)
		hash[19] = byte(i)
		nsec3 := z.nsec3(t, hash, step(hash, +1), 0, nil)
		nsec3.Hdr.Name, nsec3.Iterations = owner, 101
		signature := z.sign(t, []dns.RR{record(t, `x.example. 3600 IN TXT "x"`)}, time.Now().Add(time.Hour))
		rrsig, ok := signature.(*dns.RRSIG)
		if !ok {
			t.Fatalf("signing did not produce an RRSIG")
		}
		rrsig.Hdr.Name, rrsig.TypeCovered = owner, dns.TypeNSEC3
		authority = append(authority, nsec3, rrsig)
	}

	status := chain.Verify(nil, authority, dns.RcodeNameError, "www.example.", dns.TypeA)
	if status.State != trace.Bogus || !strings.Contains(status.Reason, "more than any proof needs") {
		t.Errorf("got %s (%s), want bogus for the count alone", status.State, status.Reason)
	}
}
