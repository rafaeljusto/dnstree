package dnssec_test

import (
	"crypto"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/dnssec"
	"github.com/rafaeljusto/dnstree/internal/roothints"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// zone is a signed root, the smallest thing a chain can start from.
type zone struct {
	key     *dns.DNSKEY
	private crypto.Signer
}

func newZone(tb testing.TB) *zone {
	tb.Helper()

	key := &dns.DNSKEY{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 3600}}
	key.Flags, key.Protocol, key.Algorithm = dns.FlagZONE|dns.FlagSEP, 3, dns.ECDSAP256SHA256

	private, err := key.Generate(256)
	if err != nil {
		tb.Fatalf("generating a key: %v", err)
	}
	return &zone{key: key, private: private.(crypto.Signer)}
}

// anchors is the trust anchor for this zone, optionally with a digest type
// nothing can compute.
func (z *zone) anchors(tb testing.TB, digestType uint8) roothints.Anchors {
	tb.Helper()

	ds := z.key.ToDS(dns.SHA256)
	digest, err := hex.DecodeString(ds.Digest)
	if err != nil {
		tb.Fatalf("decoding the digest: %v", err)
	}
	return roothints.Anchors{{
		KeyTag:     ds.KeyTag,
		Algorithm:  ds.Algorithm,
		DigestType: digestType,
		Digest:     digest,
	}}
}

// dnskeys is what a DNSKEY query would answer.
func (z *zone) dnskeys(tb testing.TB) []dns.RR {
	tb.Helper()

	keys := []dns.RR{z.key}
	return append(keys, z.sign(tb, keys, time.Now()))
}

func (z *zone) sign(tb testing.TB, rrset []dns.RR, expiry time.Time) dns.RR {
	tb.Helper()

	signature := dns.NewRRSIG(".", z.key.Algorithm, z.key.KeyTag(),
		uint32(expiry.Add(-14*24*time.Hour).Unix()), uint32(expiry.Unix()))
	if err := signature.Sign(z.private, rrset, &dns.SignOption{}); err != nil {
		tb.Fatalf("signing: %v", err)
	}
	return signature
}

// TestUnsupportedDigest covers the difference the blueprint insists on: a link
// nothing here can check is not a link that failed.
func TestUnsupportedDigest(t *testing.T) {
	zone := newZone(t)
	chain := dnssec.New(zone.anchors(t, 99))

	status := chain.Enter(".", nil, zone.dnskeys(t))
	if status.State != trace.Indeterminate {
		t.Fatalf("got %+v, want indeterminate rather than bogus", status)
	}
	if !strings.Contains(status.Reason, "digest type 99") {
		t.Errorf("got reason %q, want it to name the digest type", status.Reason)
	}
	if status.Digest != "digest 99" {
		t.Errorf("got digest %q, want the unknown one named anyway", status.Digest)
	}
}

func TestExpiredSignature(t *testing.T) {
	zone := newZone(t)
	chain := dnssec.New(zone.anchors(t, dns.SHA256))

	if status := chain.Enter(".", nil, zone.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %+v entering the root, want it secure", status)
	}

	record, err := dns.New("example. 3600 IN TXT \"hello\"")
	if err != nil {
		t.Fatalf("building a record: %v", err)
	}
	answer := []dns.RR{record, zone.sign(t, []dns.RR{record}, time.Now().Add(-time.Hour))}

	status := chain.Verify(answer, "example.", dns.TypeTXT)
	if status.State != trace.Bogus {
		t.Fatalf("got %+v, want an expired signature to be bogus", status)
	}
	if !strings.Contains(status.Reason, "validity period") {
		t.Errorf("got reason %q, want it to say the signature is out of date", status.Reason)
	}
}

// TestInsecureIsFinal covers the rule that makes the chain a chain: without a
// DS to hang it on, nothing below can be secure again.
func TestInsecureIsFinal(t *testing.T) {
	zone := newZone(t)
	chain := dnssec.New(zone.anchors(t, dns.SHA256))

	if status := chain.Enter(".", nil, zone.dnskeys(t)); status.State != trace.Secure {
		t.Fatalf("got %+v entering the root, want it secure", status)
	}
	if status := chain.Enter("example.", nil, zone.dnskeys(t)); status.State != trace.Insecure {
		t.Fatalf("got %+v for a zone with no DS, want it insecure", status)
	}
	if chain.State() != trace.Insecure {
		t.Fatalf("got chain state %s, want insecure", chain.State())
	}

	// Even a perfectly signed answer below the gap cannot be trusted.
	record, err := dns.New("example. 3600 IN TXT \"hello\"")
	if err != nil {
		t.Fatalf("building a record: %v", err)
	}
	answer := []dns.RR{record, zone.sign(t, []dns.RR{record}, time.Now().Add(time.Hour))}
	if status := chain.Verify(answer, "example.", dns.TypeTXT); status.State != trace.Insecure {
		t.Errorf("got %+v, want insecure carried down", status)
	}
}

// TestUnsignedAnswer covers a zone that says it is signed and then hands out
// records with no signature at all.
func TestUnsignedAnswer(t *testing.T) {
	zone := newZone(t)
	chain := dnssec.New(zone.anchors(t, dns.SHA256))
	chain.Enter(".", nil, zone.dnskeys(t))

	record, err := dns.New("example. 3600 IN TXT \"hello\"")
	if err != nil {
		t.Fatalf("building a record: %v", err)
	}

	status := chain.Verify([]dns.RR{record}, "example.", dns.TypeTXT)
	if status.State != trace.Bogus {
		t.Fatalf("got %+v, want bogus", status)
	}
	if !strings.Contains(status.Reason, "no signature") {
		t.Errorf("got reason %q, want it to say the answer is unsigned", status.Reason)
	}
}
