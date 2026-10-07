package fakens

import (
	"cmp"
	"crypto"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/roothints"
)

// signer holds the keys of a signed zone: a key signing key the parent's DS
// points at, and a zone signing key for everything else. ECDSA P-256 keeps the
// keys quick to make and the signatures small enough to fit in a datagram.
type signer struct {
	zone string

	// mu serializes signing, because the library caches a key's tag on the key.
	// The records are another matter: see sign.
	mu sync.Mutex

	ksk     *dns.DNSKEY
	kskPriv crypto.Signer
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer

	// stray is a key no DS covers, served in place of the real one when the
	// zone is meant to look tampered with.
	stray     *dns.DNSKEY
	strayPriv crypto.Signer

	// cosigners are the zone signing keys of other servers of the same zone,
	// published beside this one's own, the way every provider of a zone signed
	// by several publishes the keys of all of them (RFC 8901).
	cosigners []*dns.DNSKEY

	// bad corrupts the signatures over ordinary RRsets, badKeys the one over
	// the key set itself. They break different links of the same chain.
	bad     bool
	badKeys bool

	// left and life are how long a signature runs from now and how long it
	// was made to last; a zero left leaves both to the library.
	left, life time.Duration
}

func newSigner(tb testing.TB, zone string, behaviour Behaviour) *signer {
	tb.Helper()

	signer := &signer{zone: zone, bad: behaviour.BadSignature, badKeys: behaviour.BadKeySignature,
		left: behaviour.SignatureLeft, life: cmp.Or(behaviour.SignatureLife, 14*24*time.Hour)}
	signer.ksk, signer.kskPriv = generate(tb, zone, dns.FlagZONE|dns.FlagSEP)
	signer.zsk, signer.zskPriv = generate(tb, zone, dns.FlagZONE)
	if behaviour.StrayDNSKEY {
		signer.stray, signer.strayPriv = generate(tb, zone, dns.FlagZONE|dns.FlagSEP)
	}
	return signer
}

func generate(tb testing.TB, zone string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	tb.Helper()

	// The library refuses to sign with a key whose tag is 0, which one random
	// key in 65536 has, so such a key is drawn again.
	var (
		key     *dns.DNSKEY
		private crypto.PrivateKey
	)
	for key == nil || key.KeyTag() == 0 {
		key = &dns.DNSKEY{Hdr: dns.Header{Name: zone, Class: dns.ClassINET, TTL: 3600}}
		key.Flags, key.Protocol, key.Algorithm = flags, 3, dns.ECDSAP256SHA256

		var err error
		if private, err = key.Generate(256); err != nil {
			tb.Fatalf("fakens: generating a key for %s: %v", zone, err)
		}
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		tb.Fatalf("fakens: the key for %s cannot sign", zone)
	}
	return key, signer
}

// signals is the CDS and CDNSKEY records of the request the zone makes of its
// parent, in presentation format. A key of the next rollover is made for the
// purpose and never signs anything: it only has to be a key the parent does not
// yet vouch for.
func (s *signer) signals(tb testing.TB, which CDS) string {
	tb.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	next := func() *dns.DNSKEY {
		key, _ := generate(tb, s.zone, dns.FlagZONE|dns.FlagSEP)
		return key
	}
	switch which {
	case CDSCurrent:
		return cds("@", s.ksk) + cdnskey("@", s.ksk)
	case CDSNext:
		key := next()
		return cds("@", key) + cdnskey("@", key)
	case CDSDelete:
		return "@ IN CDS 0 0 0 00\n@ IN CDNSKEY 0 3 0 AA==\n"
	case CDSMismatched:
		return cds("@", s.ksk) + cdnskey("@", next())
	}
	return ""
}

func cds(owner string, key *dns.DNSKEY) string {
	ds := key.ToDS(dns.SHA256)
	return fmt.Sprintf("%s IN CDS %d %d %d %s\n", owner, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
}

func cdnskey(owner string, key *dns.DNSKEY) string {
	return fmt.Sprintf("%s IN CDNSKEY %d %d %d %s\n", owner, key.Flags, key.Protocol, key.Algorithm, key.PublicKey)
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
	for _, key := range s.cosigners {
		keys = append(keys, key)
	}
	return append(keys, s.sign(keys, ksk, priv, s.badKeys))
}

// signRRset signs anything else with the zone signing key.
func (s *signer) signRRset(rrset []dns.RR) dns.RR {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sign(rrset, s.zsk, s.zskPriv, s.bad)
}

// sign expects the signer to be locked already. The library writes to the
// records it signs: it lowercases their names, resets their TTLs and, for a
// wildcard, swaps the owner for a moment. They are the zone's own records,
// which other handlers are packing into replies with no lock held, so it is
// handed copies.
func (s *signer) sign(rrset []dns.RR, key *dns.DNSKEY, private crypto.Signer, spoil bool) dns.RR {
	copies := make([]dns.RR, len(rrset))
	for i, rr := range rrset {
		copies[i] = rr.Clone()
		// The codec sorts the values that end CAA, URI and NULL records
		// shortest first, TXT by how many strings it holds, text by its
		// escaped form and CSYNC by the types it lists, rather than by their
		// octets (RFC 4034 6.3); the
		// generic form is sorted the way a real signer sorts them, and packs
		// to the same wire for types that hold no name.
		switch dns.RRToType(rr) {
		case dns.TypeCAA, dns.TypeURI, dns.TypeNULL, dns.TypeTXT, dns.TypeSPF,
			dns.TypeHINFO, dns.TypeISDN, dns.TypeX25, dns.TypeGPOS, dns.TypeUINFO, dns.TypeNINFO,
			dns.TypeAVC, dns.TypeRESINFO, dns.TypeWALLET, dns.TypeCLA, dns.TypeCSYNC:
			raw := new(dns.RFC3597)
			if err := raw.ToRFC3597(rr); err == nil {
				copies[i] = raw
			}
		}
	}
	signature := dns.NewRRSIG(s.zone, key.Algorithm, key.KeyTag())
	if s.left != 0 {
		expiration := time.Now().Add(s.left)
		signature.Inception = uint32(expiration.Add(-s.life).Unix())
		signature.Expiration = uint32(expiration.Unix())
	}
	if err := signature.Sign(private, copies, &dns.SignOption{}); err != nil {
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

// Cosign makes the server publish the zone signing key of other, a server of
// the same zone signing it with keys of its own: the multi-signer setup of RFC
// 8901, in which every provider publishes the keys of every other. Without it
// each serves only its own, which validates against whichever server a
// resolver took the keys from and fails against the rest.
func (s *Server) Cosign(tb testing.TB, other *Server) {
	tb.Helper()

	if s.signer == nil || other.signer == nil || !dns.EqualName(s.origin, other.origin) {
		tb.Fatalf("fakens: %s and %s are not two signed servers of one zone", s.origin, other.origin)
	}
	other.signer.mu.Lock()
	key := other.signer.zsk.Clone().(*dns.DNSKEY)
	other.signer.mu.Unlock()

	s.signer.mu.Lock()
	defer s.signer.mu.Unlock()
	s.signer.cosigners = append(s.signer.cosigners, key)
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
