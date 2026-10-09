package resolver

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// mail looks up the name's mail path the way a sending server that checks DANE
// does (RFC 7672 2.2): its MX hosts by preference, the addresses of each, and
// the TLSA set of each whose addresses are signed. Then the policies published
// beside them. Every lookup is a walk of its own, drawn as an aside under
// under.
func (r *run) mail(ctx context.Context, under *trace.Step) {
	name := r.trace.Question.Name
	if dnsutil.Labels(name) == 0 {
		return
	}

	r.aside = true
	defer func() { r.aside = false }()

	m := &trace.Mail{Name: name}
	r.trace.Mail = m

	if r.exchangers(ctx, under, m) {
		for i := range m.Hosts {
			if r.counters.spent() {
				m.Hosts[i].DANE, m.Hosts[i].Why = trace.DANEIndeterminate, "the budget ran out before it was looked at"
				m.Cut = true
				continue
			}
			r.host(ctx, under, &m.Hosts[i])
			m.Cut = m.Cut || r.asideStopped
		}
	}
	if !r.counters.spent() {
		m.MTASTS = r.policy(ctx, under, "_mta-sts."+name, "v=STSv1", "sender", mtaSTS)
	}
	if !r.counters.spent() {
		m.TLSRPT = r.policy(ctx, under, "_smtp._tls."+name, "v=TLSRPTv1", "sender", tlsRPT)
	}
	if !r.counters.spent() {
		m.DMARC = r.dmarc(ctx, under, name)
	}

	if r.counters.spent() || r.asideStopped {
		r.asideStopped = true
		if m.Stopped == "" {
			m.Stopped = "the budget ran out before every lookup was made"
		}
		r.warnf("", "the mail check of %s ran out of budget before every lookup was made; raise the budget that ran out", name)
	}
	r.warnMail(m)
}

// exchangers looks up the MX set and fills in the hosts it names. It reports
// whether there are any to look at.
func (r *run) exchangers(ctx context.Context, under *trace.Step, m *trace.Mail) bool {
	result, lookup, stopped := r.look(ctx, under, m.Name, dns.TypeMX, "mail")
	m.MX = lookup
	switch {
	case stopped:
		m.Stopped = "the budget ran out before the MX lookup was answered"
		return false
	case lookup.Err != "":
		m.Stopped = "the MX lookup failed: " + lookup.Err
		r.warnf(trace.AreaMail, "the MX lookup of %s failed (%s), so mail to it waits until it answers; fix the servers of its zone", m.Name, lookup.Err)
		return false
	case r.cfg.DNSSEC && lookup.DNSSEC != nil && lookup.DNSSEC.State == trace.Bogus:
		// A sender that validates gets no MX set at all, and holds the mail
		// (RFC 7672 2.2.1); the hosts it names are nobody's word.
		m.Stopped = "the MX set does not validate: " + lookup.DNSSEC.Reason
		r.warnf(trace.AreaMail, "the MX set of %s does not validate (%s), so a sender that validates holds all mail for it; fix the signatures of its zone",
			m.Name, lookup.DNSSEC.Reason)
		return false
	case result.Kind == trace.KindNXDomain:
		m.Stopped = cmp.Or(lookup.Alias, m.Name) + " does not exist, so no mail is delivered to it"
		// An alias that leads nowhere is still a name that exists.
		m.Absent = lookup.Alias == ""
		return false
	}

	owner := result.Asked.Name
	var hosts []trace.MailHost
	null := false
	for _, record := range result.Records {
		if record.Type != "MX" || !dns.EqualName(record.Name, owner) {
			continue
		}
		preference, host, ok := strings.Cut(record.Data, " ")
		n, err := strconv.ParseUint(preference, 10, 16)
		if !ok || err != nil {
			continue
		}
		if host == "." {
			null = true
			continue
		}
		hosts = append(hosts, trace.MailHost{Name: dnsutil.Fqdn(host), Preference: uint16(n)})
	}

	switch {
	case len(hosts) == 0 && null:
		m.Null = true
		return false
	case len(hosts) == 0:
		// No MX set makes the name its own host (RFC 5321 5.1).
		m.Implicit = true
		hosts = []trace.MailHost{{Name: owner}}
	case null:
		r.warnf(trace.AreaMail, "%s has a null MX beside other MX records, which RFC 7505 forbids; remove the one or the others", owner)
	}

	// Hosts of one preference are tried in any order, and drawn in one, so
	// that two walks of the same set read the same.
	slices.SortFunc(hosts, func(a, b trace.MailHost) int {
		return cmp.Or(cmp.Compare(a.Preference, b.Preference), dns.CompareName(a.Name, b.Name))
	})
	m.Hosts = slices.CompactFunc(hosts, func(a, b trace.MailHost) bool { return dns.EqualName(a.Name, b.Name) })
	return true
}

// host decides what DANE does for mail to one host. Its addresses are looked
// up first, and its TLSA set only where they are signed: zones that are not
// signed are where servers mishandle TLSA queries (RFC 7672 2.2.2).
func (r *run) host(ctx context.Context, under *trace.Step, host *trace.MailHost) {
	if addressShaped(host.Name) {
		host.DANE, host.Why = trace.DANELiteral, "it is an address where a host name belongs, which DANE does not apply to"
		return
	}

	qtype := dns.TypeA
	if r.cfg.Family == 6 {
		qtype = dns.TypeAAAA
	}
	result, lookup, stopped := r.look(ctx, under, host.Name, qtype, "mail")
	if !stopped && lookup.Err == "" && result.Kind == trace.KindNoData && r.cfg.Family == 0 {
		qtype = dns.TypeAAAA
		result, lookup, stopped = r.look(ctx, under, host.Name, qtype, "mail")
	}
	host.Address = &lookup
	switch {
	case stopped:
		host.DANE, host.Why = trace.DANEIndeterminate, "the budget ran out before its addresses were looked up"
		return
	case lookup.Err != "":
		host.DANE, host.Why = trace.DANEUnreachable, "its addresses could not be looked up: "+lookup.Err
		return
	case result.Kind == trace.KindNXDomain:
		host.DANE, host.Why = trace.DANEUnreachable, "it does not exist"
		return
	case result.Kind != trace.KindAnswer:
		host.DANE, host.Why = trace.DANEUnreachable, "it has no address"
		return
	}
	host.Addrs = addresses(result.Records, result.Asked.Name, qtype)

	status := lookup.DNSSEC
	if r.cfg.DNSSEC && status != nil {
		switch status.State {
		case trace.Insecure:
			host.DANE, host.Why = trace.DANEInsecure, "its addresses are not signed, so its TLSA set is not asked for"
			return
		case trace.Bogus:
			host.DANE, host.Why = trace.DANEFailed, "its addresses do not validate: "+status.Reason
			return
		case trace.Indeterminate:
			host.DANE, host.Why = trace.DANEIndeterminate, "its addresses could not be checked: "+status.Reason
			return
		}
	}

	// A host that is a signed alias is looked for under the name it ends on
	// first, and then under its own where that finds no signed set (RFC 7672
	// 2.2.3).
	bases := []string{host.Name}
	if lookup.Alias != "" && (status == nil || status.State == trace.Secure) {
		bases = []string{lookup.Alias, host.Name}
	}
	for _, base := range bases {
		r.tlsa(ctx, under, host, "_25._tcp."+base)
		if host.DANE != trace.DANENone && host.DANE != trace.DANEInsecure || r.asideStopped {
			return
		}
	}
}

// tlsa looks up the TLSA set at name for host and decides by it.
func (r *run) tlsa(ctx context.Context, under *trace.Step, host *trace.MailHost, name string) {
	result, lookup, stopped := r.look(ctx, under, name, dns.TypeTLSA, "mail")
	host.TLSA = &lookup
	host.Records = nil
	if lookup.Err == "" {
		host.Records = tlsaRecords(result.Records, result.Asked.Name)
	}

	status := lookup.DNSSEC
	switch {
	case stopped:
		host.DANE, host.Why = trace.DANEIndeterminate, "the budget ran out before its TLSA set was looked up"
	case !r.cfg.DNSSEC || status == nil && lookup.Err == "":
		host.DANE, host.Why = trace.DANEUnchecked, "nothing was checked without --dnssec"
		if lookup.Err != "" {
			host.Why = "the TLSA lookup failed: " + lookup.Err
		}
	case lookup.Err != "":
		host.DANE, host.Why = trace.DANEFailed, "the TLSA lookup failed: "+lookup.Err
	case status.State == trace.Bogus:
		host.DANE, host.Why = trace.DANEFailed, "its TLSA set does not validate: "+status.Reason
	case status.State == trace.Indeterminate:
		// A validator reads what it cannot check as unsigned, and delivers.
		host.DANE, host.Why = trace.DANEIndeterminate, "its TLSA set could not be checked: "+status.Reason
	case status.State == trace.Insecure:
		host.DANE, host.Why = trace.DANEInsecure, "its TLSA set is not signed"
	case len(host.Records) == 0:
		host.DANE, host.Why = trace.DANENone, "its zone proves there is no TLSA set"
	case slices.ContainsFunc(host.Records, func(t trace.TLSARecord) bool { return t.Usable }):
		host.DANE, host.Why = trace.DANEVerified, "a sender has to see a certificate that matches"
	default:
		host.DANE, host.Why = trace.DANEUnusable, "none of its TLSA records is one a mail sender may use, so it only insists on TLS"
	}
}

// tlsaRecords are the TLSA records owner owns. A sender may use a trust anchor
// or end entity record, never a PKIX one (RFC 7672 3.1.3), and only under a
// selector and matching type it knows (RFC 6698 4.1), and with data a
// certificate could match: a digest of the wrong length matches none.
func tlsaRecords(records []trace.RR, owner string) []trace.TLSARecord {
	var found []trace.TLSARecord
	for _, record := range records {
		if record.Type != "TLSA" || !dns.EqualName(record.Name, owner) {
			continue
		}
		rr, err := dns.New(". IN TLSA " + record.Data)
		parsed, ok := rr.(*dns.TLSA)
		if err != nil || !ok {
			continue
		}
		found = append(found, trace.TLSARecord{
			Usage: parsed.Usage, Selector: parsed.Selector, Matching: parsed.MatchingType,
			Data:   strings.ToLower(parsed.Certificate),
			Usable: (parsed.Usage == 2 || parsed.Usage == 3) && parsed.Selector <= 1 && matches(parsed),
		})
	}
	return found
}

// matches reports whether a certificate could match the record: its data is
// as long as its matching type makes it, the hex of a whole certificate or key
// for 0.
func matches(tlsa *dns.TLSA) bool {
	switch tlsa.MatchingType {
	case 0:
		return tlsa.Certificate != ""
	case 1:
		return len(tlsa.Certificate) == 2*sha256.Size
	case 2:
		return len(tlsa.Certificate) == 2*sha512.Size
	}
	return false
}

// policy looks up a TXT policy that has to be the only record at name to begin
// with version, as MTA-STS (RFC 8461 3.1) and TLS-RPT (RFC 8460 3) both do:
// more than one, or one that does not parse, is no policy at all to the reader
// it is for. check says what is wrong with one that is there, empty for
// nothing.
func (r *run) policy(ctx context.Context, under *trace.Step, name, version, reader string, check func(*trace.MailPolicy) string) *trace.MailPolicy {
	p := &trace.MailPolicy{Name: name}
	result, lookup, stopped := r.look(ctx, under, name, dns.TypeTXT, "mail")
	p.Lookup = lookup
	if stopped {
		// A policy the budget left unasked is no failure of the zone's.
		return nil
	}
	if lookup.Err != "" {
		p.Found, p.Why = trace.PolicyFailed, "the TXT lookup failed: "+lookup.Err
		return p
	}

	var versioned []string
	for _, text := range texts(result.Records, result.Asked.Name) {
		if tagged(text, version) {
			versioned = append(versioned, text)
		}
	}
	switch len(versioned) {
	case 0:
		p.Found = trace.PolicyNone
		return p
	case 1:
	default:
		p.Found, p.Why = trace.PolicyInvalid, strconv.Itoa(len(versioned))+" records begin "+version+", and a "+reader+" reads that as none"
		return p
	}

	p.Record, p.Tags = versioned[0], tags(versioned[0])
	p.Found = trace.PolicyPublished
	if why := check(p); why != "" {
		p.Found, p.Why = trace.PolicyInvalid, why
	}
	return p
}

// mtaSTS is what is wrong with an MTA-STS record: it has to name the policy it
// stands for with an id of up to 32 letters and digits.
func mtaSTS(p *trace.MailPolicy) string {
	id := p.Tag("id")
	if id == "" || len(id) > 32 || strings.TrimFunc(id, isAlnum) != "" {
		return "it has no id of 1 to 32 letters and digits"
	}
	return ""
}

// tlsRPT is what is wrong with a TLS-RPT record: it has to say where the
// reports go.
func tlsRPT(p *trace.MailPolicy) string {
	if p.Tag("rua") == "" {
		return "it says nowhere to send the reports (rua)"
	}
	return ""
}

// dmarc looks up the DMARC policy of name, and where it has none, walks up the
// tree for the one that applies to it (RFC 9989 4.10.1). Nil where the budget
// ran out before the walk could say.
func (r *run) dmarc(ctx context.Context, under *trace.Step, name string) *trace.MailPolicy {
	own := r.policy(ctx, under, "_dmarc."+name, "v=DMARC1", "receiver", dmarcPolicy)
	if own == nil || own.Found != trace.PolicyNone {
		return own
	}
	var found []*trace.MailPolicy
	for _, above := range treeWalk(name) {
		p := r.policy(ctx, under, "_dmarc."+above, "v=DMARC1", "receiver", dmarcPolicy)
		switch {
		case p == nil:
			return nil
		case p.Found == trace.PolicyFailed:
			// Whether a policy further up applies cannot be said.
			return p
		case p.Record == "":
			// None, or several, which a receiver discards alike.
			continue
		}
		found = append(found, p)
		if psd := strings.ToLower(p.Tag("psd")); psd == "y" || psd == "n" {
			break
		}
	}
	if len(found) == 0 {
		return own
	}
	return applied(found)
}

// treeWalk are the names a DMARC tree walk asks above name, its parent first
// and its top-level domain last. A name of eight labels or more skips to the
// seven nearest the root, so that a long name costs no more lookups (RFC 9989
// 4.10).
func treeWalk(name string) []string {
	labels := dnsutil.Labels(name)
	skip := 1
	if labels >= 8 {
		skip = labels - 7
	}
	var names []string
	for i, end := 0, false; !end; i, end = dnsutil.Next(name, i) {
		if skip > 0 {
			skip--
			continue
		}
		names = append(names, name[i:])
	}
	return names
}

// applied is the policy a tree walk found, nearest the name first: a psd=n
// marks the organisational domain, and a psd=y a public suffix whose own
// policy applies only where the domain one label below it publishes none.
// Without either, the policy nearest the root applies (RFC 9989 4.10.2).
func applied(found []*trace.MailPolicy) *trace.MailPolicy {
	last := found[len(found)-1]
	if len(found) > 1 && strings.EqualFold(last.Tag("psd"), "y") {
		if below := found[len(found)-2]; dnsutil.Labels(below.Name) == dnsutil.Labels(last.Name)+1 {
			return below
		}
	}
	return last
}

// dmarcPolicy is what is wrong with a DMARC record. One without a valid p, or
// with an sp or np that is not valid, is read as p=none where it says where
// reports go, and as nothing otherwise (RFC 9989 4.10.1).
func dmarcPolicy(p *trace.MailPolicy) string {
	wrong := ""
	if !dmarcAction(p.Tag("p")) {
		wrong = "it has no valid p"
	}
	for _, tag := range []string{"sp", "np"} {
		named := slices.ContainsFunc(p.Tags, func(t trace.PolicyTag) bool { return t.Name == tag })
		if wrong == "" && named && !dmarcAction(p.Tag(tag)) {
			wrong = "its " + tag + " is not valid"
		}
	}
	switch {
	case wrong == "":
		return ""
	case p.Tag("rua") != "":
		p.Why = wrong + ", so a receiver acts as though it said p=none"
		return ""
	}
	return wrong + ", and says nowhere to send reports, so a receiver applies no policy"
}

// dmarcAction reports whether a DMARC policy tag says something a receiver
// can do.
func dmarcAction(value string) bool {
	return value == "none" || value == "quarantine" || value == "reject"
}

// texts are the TXT records owner owns, each one's strings joined the way a
// policy is read.
func texts(records []trace.RR, owner string) []string {
	var found []string
	for _, record := range records {
		if record.Type != "TXT" || !dns.EqualName(record.Name, owner) {
			continue
		}
		rr, err := dns.New(". IN TXT " + record.Data)
		if parsed, ok := rr.(*dns.TXT); err == nil && ok {
			found = append(found, strings.Join(parsed.Txt, ""))
		}
	}
	return found
}

// tagged reports whether a policy begins with version as its first tag.
func tagged(text, version string) bool {
	first, _, _ := strings.Cut(text, ";")
	name, value, _ := strings.Cut(version, "=")
	tagName, tagValue, ok := strings.Cut(first, "=")
	return ok && strings.TrimSpace(tagName) == name && strings.TrimSpace(tagValue) == value
}

// tags splits a policy into its tag=value pairs, the names lowercased.
func tags(text string) []trace.PolicyTag {
	var found []trace.PolicyTag
	for part := range strings.SplitSeq(text, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		found = append(found, trace.PolicyTag{Name: strings.ToLower(strings.TrimSpace(name)), Value: strings.TrimSpace(value)})
	}
	return found
}

func isAlnum(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// warnMail says what in the mail path stops mail or leaves it unprotected
// where its owner may think it is not.
func (r *run) warnMail(m *trace.Mail) {
	var uncovered []string
	for _, host := range m.Hosts {
		switch host.DANE {
		case trace.DANEFailed:
			r.warnf("", "a sender that checks DANE treats %s as unreachable, since %s; fix the servers of its zone", host.Name, host.Why)
		case trace.DANEInsecure:
			if len(host.Records) > 0 {
				r.warnf(trace.AreaMail, "%s has a TLSA set nothing signed, which senders ignore; sign the zone it is in",
					cmp.Or(host.TLSA.Alias, host.TLSA.Name))
			}
		}
		// A failed host is one a sender that checks DANE skips, not one it
		// delivers to unverified.
		switch host.DANE {
		case trace.DANEVerified, trace.DANEUnreachable, trace.DANEFailed:
		default:
			uncovered = append(uncovered, host.Name)
		}
	}
	// A check the budget cut short cannot say which hosts are covered.
	if dane, hosts := m.Covered(); dane > 0 && dane < hosts && len(uncovered) > 0 && !r.asideStopped {
		r.warnf("", "DANE covers %d of the %d MX hosts of %s, so a sender may deliver to %s unverified; publish TLSA for %s",
			dane, hosts, m.Name, orList(uncovered), verb(uncovered, "it", "them"))
	}
	for _, p := range []struct {
		policy *trace.MailPolicy
		reader string
	}{{m.MTASTS, "sender"}, {m.TLSRPT, "sender"}, {m.DMARC, "receiver"}} {
		if p.policy != nil && p.policy.Found == trace.PolicyInvalid {
			r.warnf(trace.AreaMail, "the policy at %s is no policy to a %s: %s; publish one record that parses", p.policy.Name, p.reader, p.policy.Why)
		}
	}
}
