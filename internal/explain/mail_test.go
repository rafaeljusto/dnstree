package explain_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func dkimMail(key trace.DKIMKey) *trace.Mail {
	return &trace.Mail{Name: "test.", Null: true, DKIM: []trace.DKIMKey{key}}
}

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
		"a covered host whose certificate does not match": {
			mail: &trace.Mail{Name: "test.", MX: trace.Lookup{DNSSEC: secure},
				Hosts: []trace.MailHost{{Name: "mx.test.", DANE: trace.DANEVerified,
					Presented: []trace.Presented{{State: trace.PresentedMatch}, {State: trace.PresentedMismatch}}}}},
			want: "a sender that checks DANE does not deliver mail for test. to mx.test., which presents a certificate its TLSA set does not match",
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
		"a usable DKIM key": {
			mail: dkimMail(trace.DKIMKey{Selector: "s1", Found: trace.PolicyPublished, Type: "rsa", Bits: 2048, State: trace.DKIMUsable}),
			want: "the DKIM key for selector s1 is a 2048 bit rsa key a receiver verifies with",
		},
		"a DKIM key shorter than signers are asked for, still testing": {
			mail: dkimMail(trace.DKIMKey{Selector: "s1", Found: trace.PolicyPublished, Type: "rsa", Bits: 1024, State: trace.DKIMUsable, Testing: true}),
			want: "though shorter than the 2048 bits RFC 8301 asks signers for; it is marked t=y",
		},
		"an ed25519 DKIM key": {
			mail: dkimMail(trace.DKIMKey{Selector: "s1", Found: trace.PolicyPublished, Type: "ed25519", State: trace.DKIMUsable}),
			want: "the DKIM key for selector s1 is an ed25519 key a receiver verifies with",
		},
		"a withdrawn DKIM key": {
			mail: dkimMail(trace.DKIMKey{Selector: "old", Found: trace.PolicyPublished, Type: "rsa", State: trace.DKIMRevoked}),
			want: "the DKIM key for selector old is withdrawn, so mail still signed with it fails DKIM; that is how a key is retired",
		},
		"a DKIM key receivers refuse": {
			mail: dkimMail(trace.DKIMKey{Selector: "s1", Found: trace.PolicyPublished, Type: "rsa", Bits: 512, State: trace.DKIMWeak, Why: "512 bits"}),
			want: "receivers do not verify with the DKIM key for selector s1 (512 bits)",
		},
		"a DKIM key that is missing": {
			mail: dkimMail(trace.DKIMKey{Selector: "s1", Found: trace.PolicyNone, Why: "no key is published there"}),
			want: "there is no DKIM key for selector s1 (no key is published there), so mail signed with it fails DKIM",
		},
		"a DKIM key that does not parse": {
			mail: dkimMail(trace.DKIMKey{Selector: "s1", Found: trace.PolicyInvalid, Why: "it has no p="}),
			want: "the DKIM key for selector s1 is no key to a receiver: it has no p=",
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
