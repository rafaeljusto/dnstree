package dnssec_test

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// asCDS is the request a zone makes for a DS, written as its parent holds one.
func asCDS(ds *dns.DS) dns.RR { return &dns.CDS{DS: *ds} }

func asCDNSKEY(key *dns.DNSKEY) dns.RR { return &dns.CDNSKEY{DNSKEY: *key} }

func TestSignal(t *testing.T) {
	current, next := newZone(t, "example."), newZone(t, "example.")
	sha1 := current.key.ToDS(dns.SHA1)
	forged := current.ds()
	forged.Digest = next.ds().Digest

	tests := map[string]struct {
		held    []dns.RR
		cds     []dns.RR
		cdnskey []dns.RR
		want    trace.SignalState
	}{
		"nothing asked for": {
			held: []dns.RR{current.ds()},
			want: trace.SignalNone,
		},
		"the key the parent holds": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(current.ds())},
			cdnskey: []dns.RR{asCDNSKEY(current.key)},
			want:    trace.SignalMatch,
		},
		"only a CDNSKEY, for the key the parent holds": {
			held: []dns.RR{current.ds()}, cdnskey: []dns.RR{asCDNSKEY(current.key)},
			want: trace.SignalMatch,
		},
		"a parent holding a SHA-1 digest beside the SHA-256 one asked for": {
			held: []dns.RR{sha1, current.ds()}, cds: []dns.RR{asCDS(current.ds())},
			want: trace.SignalMatch,
		},
		"a key the parent does not hold": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(next.ds())},
			want: trace.SignalPending,
		},
		"another key under the same tag": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(forged)},
			want: trace.SignalPending,
		},
		"a rollover asking for both keys while the parent holds one": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(current.ds()), asCDS(next.ds())},
			want: trace.SignalPending,
		},
		"a request to remove the DS": {
			held: []dns.RR{current.ds()},
			cds:  []dns.RR{&dns.CDS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}},
			want: trace.SignalDelete,
		},
		"a request to remove the DS beside a request for a key": {
			held: []dns.RR{current.ds()},
			cds: []dns.RR{asCDS(current.ds()),
				&dns.CDS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}},
			want: trace.SignalInconsistent,
		},
		"a request to remove the DS in the CDS, and a key in the CDNSKEY": {
			held:    []dns.RR{current.ds()},
			cds:     []dns.RR{&dns.CDS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}},
			cdnskey: []dns.RR{asCDNSKEY(current.key)},
			want:    trace.SignalInconsistent,
		},
		"a key in the CDS, and a request to remove the DS in the CDNSKEY": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(current.ds())},
			cdnskey: []dns.RR{&dns.CDNSKEY{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}},
			want:    trace.SignalInconsistent,
		},
		"a request to remove the DS in both": {
			held:    []dns.RR{current.ds()},
			cds:     []dns.RR{&dns.CDS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}},
			cdnskey: []dns.RR{&dns.CDNSKEY{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}},
			want:    trace.SignalDelete,
		},
		"a CDS and a CDNSKEY for two different keys": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(current.ds())},
			cdnskey: []dns.RR{asCDNSKEY(next.key)},
			want:    trace.SignalInconsistent,
		},
		"a CDS for another zone is no request of this one's": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(newZone(t, "other.").ds())},
			want: trace.SignalNone,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := dnssec.Signal(test.held, "example.", test.cds, test.cdnskey)
			if got.State != test.want {
				t.Errorf("got %+v, want %s", got, test.want)
			}
		})
	}
}

// TestRequested covers the form two servers' requests are held against each
// other in (RFC 9975 3.1): a key counts once however it is named, and a CDS
// counts only with the SHA-256 digest every parent computes.
func TestRequested(t *testing.T) {
	current, next := newZone(t, "example."), newZone(t, "example.")
	sha1 := current.key.ToDS(dns.SHA1)
	removal := &dns.CDS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}

	tests := map[string]struct {
		cds, cdnskey []dns.RR
		same         []dns.RR // another server's CDS, asking for what this one should
		sameKeys     []dns.RR // and its CDNSKEY
		delete       bool
		inconsistent bool
	}{
		"a CDS and a CDNSKEY name the key a CDNSKEY alone names": {
			cds: []dns.RR{asCDS(current.ds())}, cdnskey: []dns.RR{asCDNSKEY(current.key)},
			sameKeys: []dns.RR{asCDNSKEY(current.key)},
		},
		"a CDS alone names the key a CDNSKEY alone names": {
			cds:      []dns.RR{asCDS(current.ds())},
			sameKeys: []dns.RR{asCDNSKEY(current.key)},
		},
		"a SHA-1 CDS beside the SHA-256 one is left out": {
			cds:  []dns.RR{asCDS(sha1), asCDS(current.ds())},
			same: []dns.RR{asCDS(current.ds())},
		},
		"two keys in either order": {
			cds:  []dns.RR{asCDS(current.ds()), asCDS(next.ds())},
			same: []dns.RR{asCDS(next.ds()), asCDS(current.ds())},
		},
		"a request to remove the DS": {
			cds: []dns.RR{removal}, delete: true,
		},
		"a CDS and a CDNSKEY for two different keys": {
			cds: []dns.RR{asCDS(current.ds())}, cdnskey: []dns.RR{asCDNSKEY(next.key)}, inconsistent: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := dnssec.Requested("example.", test.cds, test.cdnskey)
			if got.Delete != test.delete || (got.Inconsistent != "") != test.inconsistent {
				t.Fatalf("got %+v, want delete %v and inconsistent %v", got, test.delete, test.inconsistent)
			}
			if test.same == nil && test.sameKeys == nil {
				return
			}
			other := dnssec.Requested("example.", test.same, test.sameKeys)
			if len(got.Keys) == 0 || !slices.Equal(got.Keys, other.Keys) {
				t.Errorf("got %q and %q, want the same keys", got.Keys, other.Keys)
			}
		})
	}

	if a, b := dnssec.Requested("example.", []dns.RR{asCDS(current.ds())}, nil), dnssec.Requested("example.", []dns.RR{asCDS(next.ds())}, nil); slices.Equal(a.Keys, b.Keys) {
		t.Errorf("got %q for two different keys, want them apart", a.Keys)
	}
}
