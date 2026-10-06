package tree_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderMail(t *testing.T) {
	secure := &trace.DNSSECStatus{State: trace.Secure}
	for name, tt := range map[string]struct {
		mail *trace.Mail
		want []string
	}{
		"hosts covered in part, and the policies": {
			mail: &trace.Mail{Name: "test.", MX: trace.MailLookup{Name: "test."},
				Hosts: []trace.MailHost{
					{Name: "mx.test.", Preference: 10, DANE: trace.DANEVerified, Why: "a sender has to see a certificate that matches",
						Records: []trace.TLSARecord{{Usage: 3, Selector: 1, Matching: 1, Data: "ab", Usable: true}}},
					{Name: "backup.example.", Preference: 20, DANE: trace.DANEInsecure, Why: "its addresses are not signed"},
				},
				MTASTS: &trace.MailPolicy{Found: trace.PolicyPublished, Tags: []trace.PolicyTag{{Name: "id", Value: "1"}}},
				TLSRPT: &trace.MailPolicy{Found: trace.PolicyNone},
				DMARC: &trace.MailPolicy{Name: "_dmarc.example.", Found: trace.PolicyPublished,
					Tags: []trace.PolicyTag{{Name: "p", Value: "reject"}}},
			},
			want: []string{
				"mail: 2 MX hosts for test.",
				"mail:   10 mx.test. dane (1 TLSA record): a sender has to see a certificate that matches",
				"mail:   20 backup.example. insecure: its addresses are not signed",
				"mail: mta-sts id=1; no tls-rpt; dmarc p=reject (from example.)",
				"mail: dane covers 1 of 2 MX hosts",
			},
		},
		"every host covered under a signed MX set": {
			mail: &trace.Mail{Name: "test.", MX: trace.MailLookup{Name: "test.", DNSSEC: secure},
				Hosts: []trace.MailHost{{Name: "mx.test.", Preference: 0, DANE: trace.DANEVerified, Why: "ok"}}},
			want: []string{"mail: 1 MX host for test. [secure]", "mail:   0 mx.test. dane: ok", "mail: dane covers 1 of 1 MX host"},
		},
		"a null MX": {
			mail: &trace.Mail{Name: "test.", Null: true, DMARC: &trace.MailPolicy{Found: trace.PolicyInvalid}},
			want: []string{"mail: test. takes no mail (null MX)", "mail: dmarc invalid"},
		},
		"no MX set": {
			mail: &trace.Mail{Name: "test.", Implicit: true,
				Hosts: []trace.MailHost{{Name: "test.", DANE: trace.DANEUnchecked, Why: "nothing was checked without --dnssec"}}},
			want: []string{
				"mail: test. has no MX set, so mail goes to test. itself",
				"mail:   test. unchecked: nothing was checked without --dnssec",
				"mail: dane not checked: add --dnssec",
			},
		},
		"a DMARC policy from the organisational domain is read by its sp": {
			mail: &trace.Mail{Name: "www.test.", Null: true, DMARC: &trace.MailPolicy{Name: "_dmarc.test.", Found: trace.PolicyPublished,
				Tags: []trace.PolicyTag{{Name: "p", Value: "reject"}, {Name: "sp", Value: "none"}}}},
			want: []string{"mail: www.test. takes no mail (null MX)", "mail: dmarc sp=none (from test.)"},
		},
		"no MX set and, from a crafted file, no host": {
			mail: &trace.Mail{Name: "test.", Implicit: true},
			want: nil,
		},
		"a check the budget cut short decides nothing": {
			mail: &trace.Mail{Name: "test.", Cut: true, Stopped: "the budget ran out before every lookup was made",
				Hosts: []trace.MailHost{{Name: "mx.test.", Preference: 10, DANE: trace.DANEIndeterminate, Why: "the budget ran out before it was looked at"}}},
			want: []string{
				"mail: 1 MX host for test.",
				"mail:   10 mx.test. indeterminate: the budget ran out before it was looked at",
				"mail: stopped: the budget ran out before every lookup was made",
				"mail: dane not decided: the budget ran out",
			},
		},
		"a check that stopped": {
			mail: &trace.Mail{Name: "test.", Stopped: "the MX lookup failed: SERVFAIL"},
			want: []string{"mail: stopped: the MX lookup failed: SERVFAIL"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.Mail = tt.mail
			var got []string
			for line := range strings.Lines(draw(t, tr)) {
				if strings.HasPrefix(line, "mail: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
