package explain

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// delivery is what --mail found about how mail to the name travels: whether
// DANE authenticates its MX hosts, and what its DMARC policy asks of
// receivers.
func delivery(tr *trace.Trace) []Finding {
	m := tr.Mail
	if m == nil {
		return nil
	}
	var findings []Finding
	if finding, ok := dane(m); ok {
		findings = append(findings, finding)
	}
	if m.DMARC != nil {
		switch m.DMARC.Found {
		case trace.PolicyPublished:
			findings = append(findings, Finding{Topic: Mail, Level: Note, Text: fmt.Sprintf(
				"the DMARC policy at %s asks receivers to %s mail sent as %s that neither SPF nor DKIM vouches for",
				m.DMARC.Name, dmarcAction(m.DMARCPolicy()), m.Name)})
		case trace.PolicyNone:
			findings = append(findings, Finding{Topic: Mail, Level: Note, Text: fmt.Sprintf(
				"%s publishes no DMARC policy, so a receiver decides alone what to do with mail forged as it", m.Name)})
		}
	}
	return findings
}

// dane is the finding about the MX hosts, where there are any to speak of.
func dane(m *trace.Mail) (Finding, bool) {
	switch {
	case m.Null:
		return Finding{Topic: Mail, Level: Note, Text: fmt.Sprintf(
			"%s says it takes no mail (RFC 7505), so a sender returns mail for it at once", m.Name)}, true
	case len(m.Hosts) == 0 && m.Stopped != "":
		return Finding{Topic: Mail, Level: Warn, Text: fmt.Sprintf("the mail check of %s stopped: %s", m.Name, m.Stopped)}, true
	case m.Cut:
		return Finding{Topic: Mail, Level: Warn, Text: fmt.Sprintf(
			"the mail check of %s ran out of budget before every MX host was looked at, so how much DANE covers is not known", m.Name)}, true
	}

	var failed []string
	for _, host := range m.Hosts {
		switch host.DANE {
		case trace.DANEUnchecked:
			return Finding{Topic: Mail, Level: Note, Text: fmt.Sprintf(
				"whether DANE protects mail to %s takes --dnssec to say", m.Name)}, true
		case trace.DANEFailed:
			failed = append(failed, host.Name)
		}
	}
	if len(failed) > 0 {
		return Finding{Topic: Mail, Level: Warn, Text: fmt.Sprintf(
			"a sender that checks DANE holds mail for %s rather than deliver it to %s, whose addresses do not validate, or whose TLSA set failed to look up or validate",
			m.Name, strings.Join(failed, ", "))}, true
	}

	covered, hosts := m.Covered()
	unsigned := m.MX.DNSSEC != nil && m.MX.DNSSEC.State == trace.Insecure
	switch {
	case hosts == 0:
		return Finding{}, false
	case covered == 0:
		text := fmt.Sprintf("no MX host of %s has a signed TLSA set, so a sender encrypts mail to it only where nobody in the way stops it", m.Name)
		if m.MTASTS != nil && m.MTASTS.Found == trace.PolicyPublished {
			text = fmt.Sprintf("no MX host of %s has a signed TLSA set; it publishes MTA-STS instead, which asks senders that know it for verified TLS", m.Name)
		}
		return Finding{Topic: Mail, Level: Note, Text: text}, true
	case covered < hosts:
		return Finding{Topic: Mail, Level: Warn, Text: fmt.Sprintf(
			"DANE covers %d of the %d MX hosts of %s, so a sender may deliver to the others unverified", covered, hosts, m.Name)}, true
	case unsigned:
		return Finding{Topic: Mail, Level: Warn, Text: fmt.Sprintf(
			"DANE covers every MX host of %s, but its MX set is not signed, so a forged one can send the mail elsewhere", m.Name)}, true
	}
	reachable := ""
	if hosts < len(m.Hosts) {
		reachable = " that can be reached"
	}
	return Finding{Topic: Mail, Level: Note, Text: fmt.Sprintf(
		"DANE covers every MX host of %s%s, so a sender that checks it delivers only over TLS, to a server whose certificate matches",
		m.Name, reachable)}, true
}

// dmarcAction is what a DMARC policy asks a receiver to do.
func dmarcAction(p string) string {
	switch p {
	case "reject":
		return "reject"
	case "quarantine":
		return "quarantine"
	}
	return "do nothing different with"
}
