package openmetrics_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderMail(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		Mail: &trace.Mail{Name: "www.test.", Hosts: []trace.MailHost{
			{Name: "mx1.test.", DANE: trace.DANEVerified},
			{Name: "mx2.test.", DANE: trace.DANEInsecure},
			{Name: "gone.test.", DANE: trace.DANEUnreachable},
		}, DMARC: &trace.MailPolicy{Found: trace.PolicyInvalid}},
	}
	out := render(t, tr)
	valid(t, out)
	for _, want := range []string{
		`dnstree_mail_hosts{name="www.test.",type="A"} 2`,
		`dnstree_mail_dane_hosts{name="www.test.",type="A"} 1`,
		`dnstree_mail_policy{name="www.test.",type="A",policy="dmarc",found="invalid"} 1`,
		`dnstree_mail_policy{name="www.test.",type="A",policy="dmarc",found="published"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got\n%s\nwant %s", out, want)
		}
	}
	if strings.Contains(out, `policy="mta-sts"`) {
		t.Errorf("got\n%s\nwant nothing of a policy the check never asked", out)
	}

	tr.Mail.Hosts = []trace.MailHost{{Name: "mx1.test.", DANE: trace.DANEVerified}}
	tr.Mail.Cut = true
	if out := render(t, tr); strings.Contains(out, "dnstree_mail_dane_hosts") {
		t.Errorf("got\n%s\nwant no count of hosts the budget left unchecked", out)
	}

	tr.Mail.Cut = false
	tr.Mail.Hosts = []trace.MailHost{{Name: "mx1.test.", DANE: trace.DANEUnchecked}}
	if out := render(t, tr); strings.Contains(out, "dnstree_mail_dane_hosts") {
		t.Errorf("got\n%s\nwant no count of what --dnssec was not there to check", out)
	}

	tr.Mail = nil
	if out := render(t, tr); strings.Contains(out, "dnstree_mail") {
		t.Errorf("got\n%s\nwant no mail family", out)
	}
}
