package dnssec_test

import (
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
