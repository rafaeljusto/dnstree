package fakens

import (
	"crypto"
	"encoding/hex"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/roothints"
)

// signer holds the keys of a signed zone: a key signing key the parent's DS
// points at, and a zone signing key for everything else. ECDSA P-256 keeps the
// keys quick to make and the signatures small enough to fit in a datagram.
type signer struct {
	zone string

	// mu serializes signing: the library caches a key's tag on the key and
	// canonicalises the records it signs, so two handlers signing at once would
	// be writing to the same records.
	mu sync.Mutex

	ksk     *dns.DNSKEY
	kskPriv crypto.Signer
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer

	// stray is a key no DS covers, served in place of the real one when the
	// zone is meant to look tampered with.
	stray     *dns.DNSKEY
	strayPriv crypto.Signer

	// bad corrupts the signatures over ordinary RRsets, badKeys the one over
	// the key set itself. They break different links of the same chain.
	bad     bool
	badKeys bool
}

func newSigner(tb testing.TB, zone string, behaviour Behaviour) *signer {
	tb.Helper()

	signer := &signer{zone: zone, bad: behaviour.BadSignature, badKeys: behaviour.BadKeySignature}
	signer.ksk, signer.kskPriv = generate(tb, zone, dns.FlagZONE|dns.FlagSEP)
	signer.zsk, signer.zskPriv = generate(tb, zone, dns.FlagZONE)
	if behaviour.StrayDNSKEY {
		signer.stray, signer.strayPriv = generate(tb, zone, dns.FlagZONE|dns.FlagSEP)
	}
	return signer
}

func generate(tb testing.TB, zone string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	tb.Helper()

	key := &dns.DNSKEY{Hdr: dns.Header{Name: zone, Class: dns.ClassINET, TTL: 3600}}
	key.Flags, key.Protocol, key.Algorithm = flags, 3, dns.ECDSAP256SHA256

	private, err := key.Generate(256)
	if err != nil {
		tb.Fatalf("fakens: generating a key for %s: %v", zone, err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		tb.Fatalf("fakens: the key for %s cannot sign", zone)
	}
	return key, signer
}

// ds is what the parent publishes to vouch for this zone.
func (s *signer) ds() *dns.DS {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ksk.ToDS(dns.SHA256)
}

// dnskeys is the answer to a DNSKEY query: the key set of the zone, signed by
// the key signing key.
func (s *signer) dnskeys() []dns.RR {
	s.mu.Lock()
	defer s.mu.Unlock()

	ksk, priv := s.ksk, s.kskPriv
	if s.stray != nil {
		ksk, priv = s.stray, s.strayPriv // the DS points at a key nobody serves
	}

	keys := []dns.RR{ksk, s.zsk}
	return append(keys, s.sign(keys, ksk, priv, s.badKeys))
}

// signRRset signs anything else with the zone signing key.
func (s *signer) signRRset(rrset []dns.RR) dns.RR {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sign(rrset, s.zsk, s.zskPriv, s.bad)
}

// sign expects the signer to be locked already.
func (s *signer) sign(rrset []dns.RR, key *dns.DNSKEY, private crypto.Signer, spoil bool) dns.RR {
	signature := dns.NewRRSIG(s.zone, key.Algorithm, key.KeyTag())
	if err := signature.Sign(private, rrset, &dns.SignOption{}); err != nil {
		return nil
	}
	if spoil {
		signature.Signature = corrupt(signature.Signature)
	}
	return signature
}

// corrupt changes a signature while keeping it valid base64, so that it fails
// where it should: on the maths, not on the parsing.
func corrupt(signature string) string {
	if signature == "" {
		return signature
	}
	first := byte('A')
	if signature[0] == 'A' {
		first = 'B'
	}
	return string(first) + signature[1:]
}

// Anchors is the trust anchor a test starts a chain from, which for a fake root
// is the only way to trust anything below it.
func (s *Server) Anchors(tb testing.TB) roothints.Anchors {
	tb.Helper()

	if s.signer == nil {
		tb.Fatalf("fakens: the %s server is not signed", s.origin)
	}
	ds := s.signer.ds()
	digest, err := hex.DecodeString(ds.Digest)
	if err != nil {
		tb.Fatalf("fakens: the digest of %s is not hex: %v", s.origin, err)
	}
	return roothints.Anchors{{
		KeyTag:     ds.KeyTag,
		Algorithm:  ds.Algorithm,
		DigestType: ds.DigestType,
		Digest:     digest,
	}}
}

// rrsets groups records the way signatures cover them: one per owner and type.
func rrsets(records []dns.RR) [][]dns.RR {
	var (
		sets  [][]dns.RR
		index = map[string]int{}
	)
	for _, rr := range records {
		key := rr.Header().Name + "\x00" + dns.TypeToString[dns.RRToType(rr)]
		if at, seen := index[key]; seen {
			sets[at] = append(sets[at], rr)
			continue
		}
		index[key] = len(sets)
		sets = append(sets, []dns.RR{rr})
	}
	return sets
}
