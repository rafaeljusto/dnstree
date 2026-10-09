package jsonout

import (
	"fmt"
	"net/netip"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// mail is how mail to the name is delivered, as a sending server that checks
// DANE finds out (RFC 7672).
type mail struct {
	Name     string      `json:"name"`
	MX       lookup      `json:"mx"`
	Null     bool        `json:"null,omitempty"`
	Implicit bool        `json:"implicit,omitempty"`
	Absent   bool        `json:"absent,omitempty"`
	Hosts    []mailHost  `json:"hosts,omitempty"`
	MTASTS   *mailPolicy `json:"mta_sts,omitempty"`
	TLSRPT   *mailPolicy `json:"tls_rpt,omitempty"`
	DMARC    *mailPolicy `json:"dmarc,omitempty"`
	Stopped  string      `json:"stopped,omitempty"`
	Cut      bool        `json:"cut,omitempty"`
}

type lookup struct {
	Name   string  `json:"name"`
	Alias  string  `json:"alias,omitempty"`
	Error  string  `json:"error,omitempty"`
	DNSSEC *dnssec `json:"dnssec,omitempty"`
}

type mailHost struct {
	Name       string       `json:"name"`
	Preference uint16       `json:"preference"`
	Address    *lookup      `json:"address,omitempty"`
	TLSA       *lookup      `json:"tlsa,omitempty"`
	Records    []tlsaRecord `json:"records,omitempty"`
	DANE       string       `json:"dane"`
	Why        string       `json:"why,omitempty"`
	Addresses  []string     `json:"addresses,omitempty"`
	Presented  []presented  `json:"presented,omitempty"`
}

type presented struct {
	Address string `json:"address"`
	State   string `json:"state"`
	Subject string `json:"subject,omitempty"`
	Since   string `json:"since,omitempty"`
	Matched []int  `json:"matched,omitempty"`
	Why     string `json:"why,omitempty"`
}

type tlsaRecord struct {
	Usage    uint8  `json:"usage"`
	Selector uint8  `json:"selector"`
	Matching uint8  `json:"matching"`
	Data     string `json:"data"`
	Usable   bool   `json:"usable,omitempty"`
}

type mailPolicy struct {
	Name   string      `json:"name"`
	Lookup lookup      `json:"lookup"`
	Found  string      `json:"found"`
	Record string      `json:"record,omitempty"`
	Tags   []policyTag `json:"tags,omitempty"`
	Why    string      `json:"why,omitempty"`
}

type policyTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func convertMail(from *trace.Mail) *mail {
	if from == nil {
		return nil
	}
	to := &mail{
		Name: from.Name, MX: convertLookup(from.MX), Null: from.Null, Implicit: from.Implicit, Absent: from.Absent,
		MTASTS: convertPolicy(from.MTASTS), TLSRPT: convertPolicy(from.TLSRPT), DMARC: convertPolicy(from.DMARC),
		Stopped: from.Stopped, Cut: from.Cut,
	}
	for _, host := range from.Hosts {
		h := mailHost{Name: host.Name, Preference: host.Preference, DANE: string(host.DANE), Why: host.Why,
			Addresses: texts(host.Addrs)}
		for _, p := range host.Presented {
			h.Presented = append(h.Presented, presented{Address: p.Addr.String(), State: string(p.State),
				Subject: p.Subject, Since: timestamp(p.Since), Matched: p.Matched, Why: p.Why})
		}
		if host.Address != nil {
			h.Address = new(convertLookup(*host.Address))
		}
		if host.TLSA != nil {
			h.TLSA = new(convertLookup(*host.TLSA))
		}
		for _, record := range host.Records {
			h.Records = append(h.Records, tlsaRecord{
				Usage: record.Usage, Selector: record.Selector, Matching: record.Matching,
				Data: record.Data, Usable: record.Usable,
			})
		}
		to.Hosts = append(to.Hosts, h)
	}
	return to
}

func convertLookup(from trace.Lookup) lookup {
	return lookup{Name: from.Name, Alias: from.Alias, Error: from.Err, DNSSEC: convertDNSSEC(from.DNSSEC)}
}

func convertPolicy(from *trace.MailPolicy) *mailPolicy {
	if from == nil {
		return nil
	}
	to := &mailPolicy{Name: from.Name, Lookup: convertLookup(from.Lookup), Found: string(from.Found),
		Record: from.Record, Why: from.Why}
	for _, tag := range from.Tags {
		to.Tags = append(to.Tags, policyTag(tag))
	}
	return to
}

// readMail reads the mail path back. The metrics and the explanation are read
// from what each host and policy came to, so those have to be ones this build
// knows.
func readMail(from *mail) (*trace.Mail, error) {
	if from == nil {
		return nil, nil
	}
	mx, err := readLookup(from.MX)
	if err != nil {
		return nil, err
	}
	switch {
	case from.Implicit && len(from.Hosts) != 1:
		return nil, fmt.Errorf("jsonout: a mail path with no MX set has its name as its one host, not %d", len(from.Hosts))
	case from.Null && len(from.Hosts) > 0:
		return nil, fmt.Errorf("jsonout: a mail path with a null MX has no hosts, not %d", len(from.Hosts))
	}
	to := &trace.Mail{Name: from.Name, MX: mx, Null: from.Null, Implicit: from.Implicit, Absent: from.Absent,
		Stopped: from.Stopped, Cut: from.Cut}
	for _, host := range from.Hosts {
		state := trace.DANEState(host.DANE)
		switch state {
		case trace.DANEVerified, trace.DANEUnusable, trace.DANENone, trace.DANEInsecure, trace.DANEFailed,
			trace.DANEUnreachable, trace.DANELiteral, trace.DANEUnchecked, trace.DANEIndeterminate:
		default:
			return nil, fmt.Errorf("jsonout: %q is not what DANE can do for a host", host.DANE)
		}
		h := trace.MailHost{Name: host.Name, Preference: host.Preference, DANE: state, Why: host.Why}
		if h.Address, err = readLookupRef(host.Address); err != nil {
			return nil, err
		}
		if h.TLSA, err = readLookupRef(host.TLSA); err != nil {
			return nil, err
		}
		for _, record := range host.Records {
			h.Records = append(h.Records, trace.TLSARecord{
				Usage: record.Usage, Selector: record.Selector, Matching: record.Matching,
				Data: record.Data, Usable: record.Usable,
			})
		}
		if h.Addrs, err = parseAddrs("addresses", host.Addresses); err != nil {
			return nil, err
		}
		if h.Presented, err = readPresented(host.Presented, len(h.Records)); err != nil {
			return nil, err
		}
		to.Hosts = append(to.Hosts, h)
	}
	if to.MTASTS, err = readPolicy(from.MTASTS); err != nil {
		return nil, err
	}
	if to.TLSRPT, err = readPolicy(from.TLSRPT); err != nil {
		return nil, err
	}
	if to.DMARC, err = readPolicy(from.DMARC); err != nil {
		return nil, err
	}
	return to, nil
}

// readPresented reads what each address showed --tlsa. A match has to name
// records the host has, since that is what it is drawn by.
func readPresented(from []presented, records int) ([]trace.Presented, error) {
	var to []trace.Presented
	for _, p := range from {
		state := trace.PresentedState(p.State)
		switch state {
		case trace.PresentedMatch, trace.PresentedMismatch, trace.PresentedUnreached:
		default:
			return nil, fmt.Errorf("jsonout: %q is not what checking an address can come to", p.State)
		}
		addr, err := netip.ParseAddr(p.Address)
		if err != nil {
			return nil, fmt.Errorf("jsonout: presented: %w", err)
		}
		since, err := moment(p.Since)
		if err != nil {
			return nil, fmt.Errorf("jsonout: presented since: %w", err)
		}
		for _, i := range p.Matched {
			if i < 0 || i >= records {
				return nil, fmt.Errorf("jsonout: presented matches record %d of a set of %d", i, records)
			}
		}
		to = append(to, trace.Presented{Addr: addr, State: state, Subject: p.Subject, Since: since, Matched: p.Matched, Why: p.Why})
	}
	return to, nil
}

func readLookup(from lookup) (trace.Lookup, error) {
	status, err := readDNSSEC(from.DNSSEC)
	if err != nil {
		return trace.Lookup{}, err
	}
	return trace.Lookup{Name: from.Name, Alias: from.Alias, Err: from.Error, DNSSEC: status}, nil
}

func readLookupRef(from *lookup) (*trace.Lookup, error) {
	if from == nil {
		return nil, nil
	}
	read, err := readLookup(*from)
	if err != nil {
		return nil, err
	}
	return &read, nil
}

func readPolicy(from *mailPolicy) (*trace.MailPolicy, error) {
	if from == nil {
		return nil, nil
	}
	found := trace.PolicyFound(from.Found)
	switch found {
	case trace.PolicyPublished, trace.PolicyNone, trace.PolicyInvalid, trace.PolicyFailed:
	default:
		return nil, fmt.Errorf("jsonout: %q is not what a mail policy lookup can come to", from.Found)
	}
	read, err := readLookup(from.Lookup)
	if err != nil {
		return nil, err
	}
	to := &trace.MailPolicy{Name: from.Name, Lookup: read, Found: found, Record: from.Record, Why: from.Why}
	for _, tag := range from.Tags {
		to.Tags = append(to.Tags, trace.PolicyTag(tag))
	}
	return to, nil
}
