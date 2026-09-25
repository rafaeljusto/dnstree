package dnssec_test

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// secured is a chain standing in example., a zone the root vouches for. The
// walk has to be a zone below the root for the names in it to have a label to
// spare: a wildcard directly under the root is not a thing that happens.
func secured(tb testing.TB) (*dnssec.Chain, *zone) {
	tb.Helper()

	root := newZone(tb, ".")
	child := newZone(tb, "example.")

	chain := dnssec.New(root.anchors(tb, dns.SHA256))
	if status := chain.Enter(".", nil, root.dnskeys(tb)); status.State != trace.Secure {
		tb.Fatalf("got %+v entering the root, want it secure", status)
	}
	ds := child.ds()
	authority := []dns.RR{ds, root.sign(tb, []dns.RR{ds}, time.Now().Add(time.Hour))}
	if status := chain.Enter("example.", authority, child.dnskeys(tb)); status.State != trace.Secure {
		tb.Fatalf("got %+v entering example., want it secure", status)
	}
	return chain, child
}

// nsec is one link of a chain: the gap between two names, and what the first of
// them holds.
func (z *zone) nsec(tb testing.TB, owner, next string, types ...uint16) []dns.RR {
	tb.Helper()

	rr := &dns.NSEC{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: 3600}}
	rr.NextDomain = next
	rr.TypeBitMap = types

	rrset := []dns.RR{rr}
	return append(rrset, z.sign(tb, rrset, time.Now().Add(time.Hour)))
}

// wildcardAnswer is what a zone sends when a wildcard answers for a name: the
// records carry the name asked for, while the signature was made over the
// wildcard and says so by covering fewer labels.
func wildcardAnswer(tb testing.TB, z *zone, wildcard, asked string) []dns.RR {
	tb.Helper()

	signed := []dns.RR{record(tb, wildcard+` 3600 IN TXT "wild"`)}
	signature := z.sign(tb, signed, time.Now().Add(time.Hour))

	// On the wire the signature is sent under the name that was asked for; the
	// label count is the only thing left saying a wildcard made it.
	rrsig, ok := signature.(*dns.RRSIG)
	if !ok {
		tb.Fatalf("signing did not produce an RRSIG")
	}
	rrsig.Hdr.Name = asked
	return []dns.RR{record(tb, asked+` 3600 IN TXT "wild"`), rrsig}
}

// TestWildcardAnswerIsProved covers a wildcard answering for a name, with the
// zone showing that there was nothing closer to answer with.
func TestWildcardAnswerIsProved(t *testing.T) {
	chain, root := secured(t)

	answer := wildcardAnswer(t, root, "*.example.", "anything.example.")
	// Nothing exists between the apex and the name the wildcard answered for.
	authority := root.nsec(t, "a.example.", "z.example.", dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(answer, authority, dns.RcodeSuccess, "anything.example.", dns.TypeTXT)
	if status.State != trace.Secure {
		t.Fatalf("got %+v, want a wildcard answer with its proof accepted", status)
	}
	if status.Reason != "answered by a wildcard" {
		t.Errorf("got reason %q, want the wildcard named", status.Reason)
	}
}

// TestWildcardAnswerWithoutProof covers the same answer with nothing to say the
// name was not there to begin with. Without it a wildcard can be spread over a
// name the zone answers for itself.
func TestWildcardAnswerWithoutProof(t *testing.T) {
	chain, root := secured(t)

	answer := wildcardAnswer(t, root, "*.example.", "anything.example.")

	status := chain.Verify(answer, nil, dns.RcodeSuccess, "anything.example.", dns.TypeTXT)
	if status.State == trace.Secure {
		t.Fatalf("got %+v, want a wildcard with no proof refused", status)
	}
	if status.State != trace.Bogus {
		t.Errorf("got %s, want bogus", status.State)
	}
}

// TestWildcardStretchedOverAName covers a denial that does not reach the name
// the wildcard answered for, which proves nothing about it.
func TestWildcardStretchedOverAName(t *testing.T) {
	chain, root := secured(t)

	answer := wildcardAnswer(t, root, "*.example.", "anything.example.")
	// A gap somewhere else entirely.
	authority := root.nsec(t, "x.example.", "z.example.", dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(answer, authority, dns.RcodeSuccess, "anything.example.", dns.TypeTXT)
	if status.State == trace.Secure {
		t.Fatalf("got %+v, want a wildcard stretched over a name refused", status)
	}
}

// TestWildcardOverAnEmptyNonTerminal covers a wildcard answer replayed for a
// name under an empty non-terminal, which blocks the wildcard. The gap covers
// the next closer name but ends below it, so that name is there.
func TestWildcardOverAnEmptyNonTerminal(t *testing.T) {
	chain, root := secured(t)

	answer := wildcardAnswer(t, root, "*.example.", "x.c.example.")
	authority := root.nsec(t, "*.example.", "a.b.c.example.", dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(answer, authority, dns.RcodeSuccess, "x.c.example.", dns.TypeTXT)
	if status.State == trace.Secure {
		t.Fatalf("got %+v, want a wildcard over an empty non-terminal refused", status)
	}
}

// TestNoDataNamesTheTypesItHolds covers the ordinary NODATA: the record naming
// the name says which types it has, and the one asked for is not among them.
func TestNoDataNamesTheTypesItHolds(t *testing.T) {
	chain, root := secured(t)

	authority := root.nsec(t, "there.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(nil, authority, dns.RcodeSuccess, "there.example.", dns.TypeTXT)
	if status.State != trace.Secure {
		t.Fatalf("got %+v, want the missing type proved", status)
	}
}

// TestNoDataContradictedByItsOwnProof covers a zone denying a type its own
// record says it holds.
func TestNoDataContradictedByItsOwnProof(t *testing.T) {
	chain, root := secured(t)

	authority := root.nsec(t, "there.example.", "z.example.", dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(nil, authority, dns.RcodeSuccess, "there.example.", dns.TypeTXT)
	if status.State == trace.Secure {
		t.Fatalf("got %+v, want a denial of a type it says it holds refused", status)
	}
}

// TestNoDataOwedAnAlias covers a name the proof says is an alias. The server
// owed us the alias, so an empty answer is not what the zone would have sent.
func TestNoDataOwedAnAlias(t *testing.T) {
	chain, root := secured(t)

	authority := root.nsec(t, "there.example.", "z.example.", dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(nil, authority, dns.RcodeSuccess, "there.example.", dns.TypeTXT)
	if status.State == trace.Secure {
		t.Fatalf("got %+v, want an empty answer for an alias refused", status)
	}
}

// TestNameErrorNeedsTheWildcardDenied covers the half of an NXDOMAIN that is
// easy to forget: the name falls in a gap, but so must the wildcard that would
// otherwise have answered for it.
func TestNameErrorNeedsTheWildcardDenied(t *testing.T) {
	chain, root := secured(t)

	// One gap, holding the name but not the wildcard, which sorts below it.
	authority := root.nsec(t, "m.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)

	status := chain.Verify(nil, authority, dns.RcodeNameError, "nothing.example.", dns.TypeA)
	if status.State == trace.Secure {
		t.Fatalf("got %+v, want an NXDOMAIN with no word on the wildcard refused", status)
	}
}

// TestNameErrorProved covers both halves arriving: the gap that holds the name,
// and the gap that holds the wildcard.
func TestNameErrorProved(t *testing.T) {
	chain, root := secured(t)

	authority := root.nsec(t, "m.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
	// "*." sorts before any letter, so the apex gap is the one that holds it.
	authority = append(authority, root.nsec(t, "example.", "m.example.", dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC)...)

	status := chain.Verify(nil, authority, dns.RcodeNameError, "nothing.example.", dns.TypeA)
	if status.State != trace.Secure {
		t.Fatalf("got %+v, want the absence proved", status)
	}
}

// TestDenialMustBeSignedToDenyAnything covers an unsigned proof, which anybody
// can write.
func TestDenialMustBeSignedToDenyAnything(t *testing.T) {
	chain, root := secured(t)

	unsigned := root.nsec(t, "there.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)[:1]

	status := chain.Verify(nil, unsigned, dns.RcodeSuccess, "there.example.", dns.TypeTXT)
	if status.State == trace.Secure {
		t.Fatalf("got %+v, want an unsigned denial refused", status)
	}
}
