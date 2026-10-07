package explain_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestDelivery(t *testing.T) {
	secure := &trace.DNSSECStatus{State: trace.Secure}
	insecure := &trace.DNSSECStatus{State: trace.Insecure}
	host := func(name string, state trace.DANEState) trace.MailHost {
		return trace.MailHost{Name: name, Preference: 10, DANE: state}
	}
	for name, tt := range map[string]struct {
		mail *trace.Mail
		want string
	}{
		"every host covered under a signed MX set": {
			mail: &trace.Mail{Name: "test.", MX: trace.Lookup{DNSSEC: secure},
				Hosts: []trace.MailHost{host("mx.test.", trace.DANEVerified)}},
			want: "DANE covers every MX host of test., so a sender that checks it delivers only over TLS",
		},
		"every host covered under an unsigned MX set": {
			mail: &trace.Mail{Name: "test.", MX: trace.Lookup{DNSSEC: insecure},
				Hosts: []trace.MailHost{host("mx.test.", trace.DANEVerified)}},
			want: "but its MX set is not signed, so a forged one can send the mail elsewhere",
		},
		"one host of two covered": {
			mail: &trace.Mail{Name: "test.", MX: trace.Lookup{DNSSEC: secure},
				Hosts: []trace.MailHost{host("mx.test.", trace.DANEVerified), host("backup.test.", trace.DANEInsecure)}},
			want: "DANE covers 1 of the 2 MX hosts of test., so a sender may deliver to the others unverified",
		},
		"a host whose TLSA lookup failed": {
			mail: &trace.Mail{Name: "test.", MX: trace.Lookup{DNSSEC: secure},
				Hosts: []trace.MailHost{host("mx.test.", trace.DANEFailed)}},
			want: "a sender that checks DANE holds mail for test. rather than deliver it to mx.test.",
		},
		"no host covered, and MTA-STS published": {
			mail: &trace.Mail{Name: "test.", Hosts: []trace.MailHost{host("mx.test.", trace.DANEInsecure)},
				MTASTS: &trace.MailPolicy{Found: trace.PolicyPublished}},
			want: "it publishes MTA-STS instead",
		},
		"a check made without --dnssec": {
			mail: &trace.Mail{Name: "test.", Hosts: []trace.MailHost{host("mx.test.", trace.DANEUnchecked)}},
			want: "whether DANE protects mail to test. takes --dnssec to say",
		},
		"a check the budget cut short": {
			mail: &trace.Mail{Name: "test.", Cut: true, MX: trace.Lookup{DNSSEC: secure},
				Hosts: []trace.MailHost{host("mx.test.", trace.DANEVerified), host("mx2.test.", trace.DANEIndeterminate)}},
			want: "so how much DANE covers is not known",
		},
		"a null MX": {
			mail: &trace.Mail{Name: "test.", Null: true},
			want: "test. says it takes no mail (RFC 7505)",
		},
		"a DMARC policy that rejects": {
			mail: &trace.Mail{Name: "test.", Null: true, DMARC: &trace.MailPolicy{Name: "_dmarc.test.", Found: trace.PolicyPublished,
				Tags: []trace.PolicyTag{{Name: "v", Value: "DMARC1"}, {Name: "p", Value: "reject"}}}},
			want: "the DMARC policy at _dmarc.test. asks receivers to reject mail sent as test.",
		},
		"no DMARC policy": {
			mail: &trace.Mail{Name: "test.", Null: true, DMARC: &trace.MailPolicy{Name: "_dmarc.test.", Found: trace.PolicyNone}},
			want: "test. publishes no DMARC policy",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := walk(answered(300))
			tr.Mail = tt.mail
			if got := said(tr); !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want it to say %q", got, tt.want)
			}
		})
	}
	if got := said(walk(answered(300))); strings.Contains(got, "DANE") || strings.Contains(got, "DMARC") {
		t.Errorf("got %q, want nothing said of mail a walk did not look up", got)
	}
}
