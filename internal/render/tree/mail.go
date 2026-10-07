package tree

import (
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// mailPath draws what --mail found: the MX hosts, what DANE does for each, the
// policies beside them, and how much of the mail DANE covers. The lookups
// themselves are in the tree.
func (r *renderer) mailPath(m *trace.Mail) []string {
	if m == nil {
		return nil
	}
	mark := "mail: "
	if r.glyphs.icons {
		mark = spaced("✉️")
	}

	var lines []string
	head := ""
	switch {
	case m.Null:
		head = m.Name + " takes no mail (null MX)"
	case m.Implicit && len(m.Hosts) > 0:
		head = m.Name + " has no MX set, so mail goes to " + m.Hosts[0].Name + " itself"
	case len(m.Hosts) > 0:
		head = plural(len(m.Hosts), "MX host", "MX hosts") + " for " + m.Name
		if m.MX.Alias != "" {
			head += ", as an alias for " + m.MX.Alias
		}
	}
	if head != "" {
		line := r.paint.dim(mark + head)
		if verdict := r.dnssec(m.MX.DNSSEC); verdict != "" {
			line += " " + verdict
		}
		lines = append(lines, line)
	}

	for _, host := range m.Hosts {
		text := mark + "  " + host.Name
		if !m.Implicit {
			text = mark + "  " + strconv.Itoa(int(host.Preference)) + " " + host.Name
		}
		text += " " + string(host.DANE)
		if n := len(host.Records); n > 0 {
			text += " (" + plural(n, "TLSA record", "TLSA records") + ")"
		}
		text += ": " + host.Why
		switch host.DANE {
		case trace.DANEVerified:
			lines = append(lines, r.paint.paint(text, green))
		case trace.DANEFailed:
			lines = append(lines, r.paint.paint(text, red))
		case trace.DANEUnreachable:
			lines = append(lines, r.paint.paint(text, yellow))
		default:
			lines = append(lines, r.paint.dim(text))
		}
		for _, p := range host.Presented {
			lines = append(lines, r.presented(host, p, mark))
		}
	}

	if m.Stopped != "" {
		lines = append(lines, r.paint.paint(mark+"stopped: "+m.Stopped, yellow))
	}
	if line := r.mailPolicies(m, mark); line != "" {
		lines = append(lines, line)
	}
	if line := r.covered(m, mark); line != "" {
		lines = append(lines, line)
	}
	return lines
}

// presented is the line that says what one address of a host showed --tlsa.
func (r *renderer) presented(host trace.MailHost, p trace.Presented, mark string) string {
	text := mark + "    " + p.Addr.String() + " " + string(p.State) + ": "
	var matched []string
	for _, i := range p.Matched {
		if i < len(host.Records) {
			matched = append(matched, tlsaShort(host.Records[i]))
		}
	}
	switch {
	case len(matched) > 0:
		text += strings.Join(matched, ", ") + " matches"
	default:
		text += p.Why + ";"
	}
	if p.Subject != "" {
		text += " " + p.Subject + ", issued " + p.Since.Format(time.DateOnly)
	}
	text = strings.TrimSuffix(text, ";")
	switch p.State {
	case trace.PresentedMatch:
		return r.paint.paint(text, green)
	case trace.PresentedMismatch:
		return r.paint.paint(text, red)
	}
	return r.paint.dim(text)
}

// tlsaShort is a TLSA record with enough of its data to tell it from the
// others of its set.
func tlsaShort(t trace.TLSARecord) string {
	data := t.Data
	if len(data) > 8 {
		data = data[:8] + "..."
	}
	return strconv.Itoa(int(t.Usage)) + " " + strconv.Itoa(int(t.Selector)) + " " + strconv.Itoa(int(t.Matching)) + " " + data
}

// mailPolicies is the line that says which of the policies were published.
func (r *renderer) mailPolicies(m *trace.Mail, mark string) string {
	var said []string
	invalid := false
	for _, p := range []struct {
		name, tag string
		policy    *trace.MailPolicy
	}{
		{"mta-sts", "id", m.MTASTS}, {"tls-rpt", "rua", m.TLSRPT}, {"dmarc", "p", m.DMARC},
	} {
		if p.policy == nil {
			continue
		}
		switch p.policy.Found {
		case trace.PolicyPublished:
			// A policy found at the organisational domain applies its sp to
			// the name, where it has one.
			inherited := p.name == "dmarc" && p.policy.Name != "_dmarc."+m.Name
			tag := p.tag
			if inherited && p.policy.Tag("sp") != "" {
				tag = "sp"
			}
			text := p.name
			if value := p.policy.Tag(tag); value != "" {
				text += " " + tag + "=" + value
			}
			if inherited {
				text += " (from " + strings.TrimPrefix(p.policy.Name, "_dmarc.") + ")"
			}
			said = append(said, text)
		case trace.PolicyNone:
			said = append(said, "no "+p.name)
		case trace.PolicyInvalid:
			said, invalid = append(said, p.name+" invalid"), true
		case trace.PolicyFailed:
			said, invalid = append(said, p.name+" lookup failed"), true
		}
	}
	if len(said) == 0 {
		return ""
	}
	if invalid {
		return r.paint.paint(mark+strings.Join(said, "; "), yellow)
	}
	return r.paint.dim(mark + strings.Join(said, "; "))
}

// covered is the line that says how much of the mail DANE authenticates.
func (r *renderer) covered(m *trace.Mail, mark string) string {
	dane, hosts := m.Covered()
	if hosts == 0 {
		return ""
	}
	for _, host := range m.Hosts {
		if host.DANE == trace.DANEUnchecked {
			return r.paint.dim(mark + "dane not checked: add --dnssec")
		}
	}
	if m.Cut {
		return r.paint.paint(mark+"dane not decided: the budget ran out", yellow)
	}
	text := mark + "dane covers " + strconv.Itoa(dane) + " of " + plural(hosts, "MX host", "MX hosts")
	if left := len(m.Hosts) - hosts; left > 0 {
		text += ", not counting " + strconv.Itoa(left) + " that cannot be reached"
	}
	unsigned := m.MX.DNSSEC != nil && m.MX.DNSSEC.State == trace.Insecure
	if dane > 0 && unsigned {
		text += ", but the MX set is not signed, so it protects each host and not which hosts get the mail"
	}
	if refused := m.Mismatched(); len(refused) > 0 {
		return r.paint.paint(text+", but "+strings.Join(refused, ", ")+" presents what a sender that checks it refuses", red)
	}
	switch {
	case dane == 0:
		return r.paint.dim(text)
	case dane < hosts || unsigned:
		return r.paint.paint(text, yellow)
	}
	return r.paint.paint(text, green)
}
