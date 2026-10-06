package trace

import (
	"cmp"
	"slices"
)

// Mail is how mail to a domain is delivered, as a sending server finds out: the
// MX hosts it would try, whether each can be authenticated with DANE (RFC
// 7672), and the policies published beside them.
type Mail struct {
	Name string

	// MX is the lookup of the exchangers. Null is a domain that says it takes
	// no mail (RFC 7505), and Implicit one with no MX set, whose own name is
	// its only host (RFC 5321 5.1).
	MX       MailLookup
	Null     bool
	Implicit bool

	// Hosts are the exchangers by preference, best first.
	Hosts []MailHost

	// MTASTS, TLSRPT and DMARC are the TXT policies, nil where the check
	// stopped before asking.
	MTASTS *MailPolicy
	TLSRPT *MailPolicy
	DMARC  *MailPolicy

	// Stopped is why the check made fewer lookups than it set out to: the MX
	// set could not be had, or a budget of the run ran out.
	Stopped string

	// Cut is a check whose host lookups a budget cut short, which leaves how
	// much DANE covers unknown.
	Cut bool
}

// MailLookup is one name the check looked up, with a walk of its own.
type MailLookup struct {
	Name string

	// Alias is the name the answer came from, where Name is an alias.
	Alias string

	// Err is why the lookup failed, empty where it was answered.
	Err string

	// DNSSEC is the first verdict on the way that is not secure, the aliases
	// included, or else the answer's. Nil where no signatures were checked.
	DNSSEC *DNSSECStatus
}

// MailHost is one MX host, and what a sender that checks DANE makes of it.
type MailHost struct {
	Name       string
	Preference uint16

	// Address is the lookup of its addresses, and TLSA that of its TLSA set,
	// nil where it was not asked.
	Address *MailLookup
	TLSA    *MailLookup

	Records []TLSARecord
	DANE    DANEState

	// Why is what made the state so, in a few words.
	Why string
}

// DANEState is what DANE does for mail to one host.
type DANEState string

// What a host can come to.
const (
	// DANEVerified is a signed TLSA set with a record a sender can use: the
	// server's certificate has to match it.
	DANEVerified DANEState = "dane"

	// DANEUnusable is a signed TLSA set with no record a sender can use, which
	// still makes it insist on TLS.
	DANEUnusable DANEState = "unusable"

	// DANENone is a signed denial of any TLSA set, and DANEInsecure a host
	// whose addresses or TLSA set nothing signed: DANE does not apply to
	// either.
	DANENone     DANEState = "none"
	DANEInsecure DANEState = "insecure"

	// DANEFailed is a TLSA lookup that failed or did not validate, which makes
	// a sender that checks DANE treat the host as unreachable.
	DANEFailed DANEState = "failed"

	// DANEUnreachable is a host with no address to deliver to.
	DANEUnreachable DANEState = "unreachable"

	// DANELiteral is an address written where a host name belongs, which DANE
	// does not apply to.
	DANELiteral DANEState = "literal"

	// DANEUnchecked is a TLSA set looked up without --dnssec, which says
	// nothing about whether a sender may rely on it.
	DANEUnchecked DANEState = "unchecked"

	// DANEIndeterminate is a host whose addresses or TLSA set could not be
	// checked: an algorithm or a denial this build cannot check, which a
	// validator reads as unsigned, or a budget of the run that ran out first.
	DANEIndeterminate DANEState = "indeterminate"
)

// TLSARecord is one record of a TLSA set (RFC 6698), its data in hex.
type TLSARecord struct {
	Usage    uint8
	Selector uint8
	Matching uint8
	Data     string

	// Usable is whether a mail sender may authenticate with it (RFC 7672
	// 3.1): a trust anchor or end entity certificate, under a selector and
	// matching type it knows.
	Usable bool
}

// MailPolicy is one TXT policy published for mail to the domain.
type MailPolicy struct {
	// Name is where it was asked, and Lookup how that went.
	Name   string
	Lookup MailLookup

	Found PolicyFound

	// Record is the policy as published, and Tags its tags in order.
	Record string
	Tags   []PolicyTag

	// Why is what made it invalid or failed.
	Why string
}

// PolicyFound is what the lookup of a policy came to.
type PolicyFound string

// What a policy lookup can come to.
const (
	PolicyPublished PolicyFound = "published"
	PolicyNone      PolicyFound = "none"
	PolicyInvalid   PolicyFound = "invalid"
	PolicyFailed    PolicyFound = "failed"
)

// PolicyTag is one tag=value pair of a policy.
type PolicyTag struct {
	Name  string
	Value string
}

// Tag is the value of the named tag, empty where the policy has none.
func (p *MailPolicy) Tag(name string) string {
	if p == nil {
		return ""
	}
	for _, tag := range p.Tags {
		if tag.Name == name {
			return tag.Value
		}
	}
	return ""
}

// DMARCPolicy is what the DMARC policy asks of mail sent as the name: p, or
// for a policy found at the organisational domain, sp where it says one (RFC
// 7489 6.3). Empty where none was published.
func (m *Mail) DMARCPolicy() string {
	if m.DMARC == nil || m.DMARC.Found != PolicyPublished {
		return ""
	}
	if m.DMARC.Name != "_dmarc."+m.Name {
		return cmp.Or(m.DMARC.Tag("sp"), m.DMARC.Tag("p"))
	}
	return m.DMARC.Tag("p")
}

// Covered is how many hosts DANE authenticates, out of how many mail may go
// to.
func (m *Mail) Covered() (dane, hosts int) {
	for _, host := range m.Hosts {
		if host.DANE == DANEUnreachable {
			continue
		}
		hosts++
		if host.DANE == DANEVerified {
			dane++
		}
	}
	return dane, hosts
}

// Shown is the mail path with every name and text the zones wrote escaped.
func (m *Mail) Shown() *Mail {
	if m == nil {
		return nil
	}
	shown := *m
	shown.Name, shown.Stopped = Shown(m.Name), Shown(m.Stopped)
	shown.MX = m.MX.shown()
	shown.Hosts = slices.Clone(m.Hosts)
	for i := range shown.Hosts {
		host := &shown.Hosts[i]
		host.Name, host.Why = Shown(host.Name), Shown(host.Why)
		host.DANE = DANEState(Shown(string(host.DANE)))
		host.Address, host.TLSA = host.Address.shownRef(), host.TLSA.shownRef()
		host.Records = slices.Clone(host.Records)
		for j := range host.Records {
			host.Records[j].Data = Shown(host.Records[j].Data)
		}
	}
	shown.MTASTS, shown.TLSRPT, shown.DMARC = m.MTASTS.shown(), m.TLSRPT.shown(), m.DMARC.shown()
	return &shown
}

func (l MailLookup) shown() MailLookup {
	l.Name, l.Alias, l.Err = Shown(l.Name), Shown(l.Alias), Shown(l.Err)
	l.DNSSEC = l.DNSSEC.shown()
	return l
}

func (l *MailLookup) shownRef() *MailLookup {
	if l == nil {
		return nil
	}
	shown := l.shown()
	return &shown
}

func (p *MailPolicy) shown() *MailPolicy {
	if p == nil {
		return nil
	}
	shown := *p
	shown.Name, shown.Record, shown.Why = Shown(p.Name), Shown(p.Record), Shown(p.Why)
	shown.Found = PolicyFound(Shown(string(p.Found)))
	shown.Lookup = p.Lookup.shown()
	shown.Tags = slices.Clone(p.Tags)
	for i := range shown.Tags {
		shown.Tags[i].Name, shown.Tags[i].Value = Shown(shown.Tags[i].Name), Shown(shown.Tags[i].Value)
	}
	return &shown
}
