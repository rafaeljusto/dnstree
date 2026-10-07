package dane_test

import (
	"cmp"
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/dane"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakemx"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

var walked = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func record(usage, selector, matching uint8, cert *x509.Certificate) trace.TLSARecord {
	return trace.TLSARecord{Usage: usage, Selector: selector, Matching: matching,
		Data: fakemx.Digest(cert, selector, matching), Usable: usage == 2 || usage == 3}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	ca := fakemx.Issue(t, nil, true, walked.AddDate(-1, 0, 0), walked.AddDate(5, 0, 0))
	leaf := fakemx.Issue(t, &ca, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "mx.example.com")
	stray := fakemx.Issue(t, &ca, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "elsewhere.example.net")
	wild := fakemx.Issue(t, &ca, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "*.example.com")
	expired := fakemx.Issue(t, &ca, false, walked.AddDate(0, -6, 0), walked.AddDate(0, 0, -1), "mx.example.com")
	shared := fakemx.Issue(t, &ca, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "tlsa201._dane.example.com")
	old := fakemx.Issue(t, nil, false, walked.AddDate(-1, 0, 0), walked.AddDate(1, 0, 0), "mx.example.com")

	tests := []struct {
		name     string
		how      fakemx.Mode
		served   fakemx.Issued
		records  []trace.TLSARecord
		dane     trace.DANEState
		want     trace.PresentedState
		matched  []int
		why      string
		warned   string
		alias    string // where the TLSA set of the host is an alias to
		unasked  bool
		refusing bool
	}{
		{name: "a DANE-EE record of the leaf's key matches", served: leaf,
			records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)}, want: trace.PresentedMatch, matched: []int{0}},
		{name: "a DANE-EE record of the whole leaf under SHA-512 matches", served: leaf,
			records: []trace.TLSARecord{record(3, 0, 2, leaf.Cert)}, want: trace.PresentedMatch, matched: []int{0}},
		{name: "a DANE-EE record matches whatever the leaf names and however old it is", served: expired,
			records: []trace.TLSARecord{record(3, 1, 0, expired.Cert)}, want: trace.PresentedMatch, matched: []int{0}},
		{name: "a DANE-EE record of a key the server no longer has matches nothing", served: leaf,
			records: []trace.TLSARecord{record(3, 1, 1, old.Cert)}, want: trace.PresentedMismatch, why: "no TLSA record matches",
			warned: "mx.example.com. at 192.0.2.25 presents a certificate issued 2026-09-24 that no TLSA record of its matches"},
		{name: "the new record of a rollover matches beside the old", served: leaf,
			records: []trace.TLSARecord{record(3, 1, 1, old.Cert), record(3, 1, 1, leaf.Cert)}, want: trace.PresentedMatch, matched: []int{1}},
		{name: "a DANE-TA record of the issuer matches a leaf that names the host", served: leaf,
			records: []trace.TLSARecord{record(2, 0, 1, ca.Cert)}, want: trace.PresentedMatch, matched: []int{0}},
		{name: "a DANE-TA record matches a wildcard over the host's first label", served: wild,
			records: []trace.TLSARecord{record(2, 1, 1, ca.Cert)}, want: trace.PresentedMatch, matched: []int{0}},
		{name: "a DANE-TA record does not vouch for a leaf that names another server", served: stray,
			records: []trace.TLSARecord{record(2, 0, 1, ca.Cert)}, want: trace.PresentedMismatch, why: "names none of mx.example.com",
			warned: "a sender that checks DANE does not deliver to mx.example.com. at 192.0.2.25: a DANE-TA record matches, but"},
		{name: "a DANE-TA record does not vouch for a leaf expired when the walk was made", served: expired,
			records: []trace.TLSARecord{record(2, 0, 1, ca.Cert)}, want: trace.PresentedMismatch, why: "the chain does not hold",
			warned: "the chain does not hold"},
		{name: "a DANE-TA record does not vouch for the name an alias of the TLSA set leads to", served: shared, alias: "tlsa201._dane.example.com.",
			records: []trace.TLSARecord{record(2, 0, 1, ca.Cert)}, want: trace.PresentedMismatch, why: "names none of mx.example.com",
			warned: "names none of mx.example.com"},
		{name: "a server that refuses EHLO could not be checked, rather than read as one without STARTTLS", how: fakemx.Picky, served: leaf,
			records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)}, want: trace.PresentedUnreached, why: "EHLO: 550",
			warned: "--tlsa could not check any of the mail servers"},
		{name: "a PKIX record is not one a mail sender uses", served: leaf,
			records: []trace.TLSARecord{{Usage: 1, Selector: 1, Matching: 1, Data: fakemx.Digest(leaf.Cert, 1, 1)}},
			want:    trace.PresentedMismatch, why: "no TLSA record matches", warned: "no TLSA record of its matches"},
		{name: "a server without STARTTLS is one a sender does not deliver to", how: fakemx.Plain, served: leaf,
			records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)}, want: trace.PresentedMismatch, why: "does not offer STARTTLS",
			warned: "does not offer STARTTLS"},
		{name: "a server that never greets could not be checked", how: fakemx.Stall, served: leaf,
			records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)}, want: trace.PresentedUnreached, why: "could not be checked from here",
			warned: "--tlsa could not check any of the mail servers"},
		{name: "a server that greets without end is cut off", how: fakemx.Flood, served: leaf,
			records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)}, want: trace.PresentedUnreached, why: "more than 256 KiB",
			warned: "more than 256 KiB); port 25 may be blocked"},
		{name: "an address that refuses the connection could not be checked", served: leaf, refusing: true,
			records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)}, want: trace.PresentedUnreached, why: "could not be checked from here",
			warned: "connection refused"},
		{name: "a host DANE does not cover is not connected to", served: leaf, dane: trace.DANEInsecure, unasked: true,
			records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			addr := fakemx.Serve(t, tt.how, tt.served.Key, tt.served.Cert, ca.Cert)
			if tt.refusing {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr = netip.MustParseAddrPort(listener.Addr().String())
				_ = listener.Close()
			}
			m := &trace.Mail{Name: "example.com.", Hosts: []trace.MailHost{{
				Name: "mx.example.com.", DANE: cmp.Or(tt.dane, trace.DANEVerified), Records: tt.records,
				TLSA:  &trace.Lookup{Name: "_25._tcp.mx.example.com.", Alias: tt.alias},
				Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.25")},
			}}}
			tr := &trace.Trace{Started: walked, Mail: m}
			dane.Check(context.Background(), tr, dane.Config{
				Timeout: time.Second, Port: 25,
				Dial: func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
					if to != netip.MustParseAddrPort("192.0.2.25:25") {
						t.Errorf("dialled %s, want 192.0.2.25:25", to)
					}
					var dialer net.Dialer
					return dialer.DialContext(ctx, "tcp", addr.String())
				},
			})

			warned := strings.Join(tr.Warnings, "\n")
			if tt.warned == "" && warned != "" || !strings.Contains(warned, tt.warned) {
				t.Errorf("warnings = %q, want %q", warned, tt.warned)
			}
			presented := m.Hosts[0].Presented
			if tt.unasked {
				if presented != nil {
					t.Fatalf("presented = %+v, want nothing asked", presented)
				}
				return
			}
			if len(presented) != 1 {
				t.Fatalf("presented = %+v, want one address", presented)
			}
			got := presented[0]
			if got.State != tt.want || !strings.Contains(got.Why, tt.why) {
				t.Errorf("got %s (%s), want %s with %q", got.State, got.Why, tt.want, tt.why)
			}
			if !slices.Equal(got.Matched, tt.matched) {
				t.Errorf("matched = %v, want %v", got.Matched, tt.matched)
			}
			if tt.how == fakemx.Honest && !tt.refusing && !got.Since.Equal(tt.served.Cert.NotBefore) {
				t.Errorf("since = %s, want %s", got.Since, tt.served.Cert.NotBefore)
			}
		})
	}
}

// TestCheckBounded covers a host with more addresses than the check connects
// to: it checks as many as it may and says how many it left.
func TestCheckBounded(t *testing.T) {
	t.Parallel()

	leaf := fakemx.Issue(t, nil, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "mx.example.com")
	addr := fakemx.Serve(t, fakemx.Honest, leaf.Key, leaf.Cert)
	var addrs []netip.Addr
	for i := range 6 {
		addrs = append(addrs, netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}))
	}
	tr := &trace.Trace{Started: walked, Mail: &trace.Mail{Name: "example.com.", Hosts: []trace.MailHost{{
		Name: "mx.example.com.", DANE: trace.DANEVerified, Records: []trace.TLSARecord{record(3, 1, 1, leaf.Cert)},
		TLSA: &trace.Lookup{Name: "_25._tcp.mx.example.com."}, Addrs: addrs,
	}}}}
	dane.Check(context.Background(), tr, dane.Config{Timeout: time.Second,
		Dial: func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", addr.String())
		}})

	if got := len(tr.Mail.Hosts[0].Presented); got != 4 {
		t.Errorf("checked %d addresses, want 4", got)
	}
	if want := "--tlsa left 2 mail server addresses unchecked"; !strings.Contains(strings.Join(tr.Warnings, "\n"), want) {
		t.Errorf("warnings = %q, want %q", tr.Warnings, want)
	}
}
