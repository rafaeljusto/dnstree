package dnssec_test

import (
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
			cds:  []dns.RR{&dns.CDS{DS: dns.DS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}},
			want: trace.SignalDelete,
		},
		"a request to remove the DS beside a request for a key": {
			held: []dns.RR{current.ds()},
			cds: []dns.RR{asCDS(current.ds()),
				&dns.CDS{DS: dns.DS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}},
			want: trace.SignalInconsistent,
		},
		"a request to remove the DS in the CDS, and a key in the CDNSKEY": {
			held:    []dns.RR{current.ds()},
			cds:     []dns.RR{&dns.CDS{DS: dns.DS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}},
			cdnskey: []dns.RR{asCDNSKEY(current.key)},
			want:    trace.SignalInconsistent,
		},
		"a key in the CDS, and a request to remove the DS in the CDNSKEY": {
			held: []dns.RR{current.ds()}, cds: []dns.RR{asCDS(current.ds())},
			cdnskey: []dns.RR{&dns.CDNSKEY{DNSKEY: dns.DNSKEY{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}},
			want:    trace.SignalInconsistent,
		},
		"a request to remove the DS in both": {
			held:    []dns.RR{current.ds()},
			cds:     []dns.RR{&dns.CDS{DS: dns.DS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}},
			cdnskey: []dns.RR{&dns.CDNSKEY{DNSKEY: dns.DNSKEY{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}},
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
