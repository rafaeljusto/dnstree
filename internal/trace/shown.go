package trace

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Shown is text from the wire as it may be drawn: every byte outside printable
// ASCII as \DDD. The codec hands names over as the octets the server sent, so
// a name can carry an escape that moves the cursor. A backslash is left alone,
// because text rdata arrives escaped already and must not be escaped twice.
func Shown(text string) string {
	if !strings.ContainsFunc(text, func(r rune) bool { return r < ' ' || r > '~' }) {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if c := text[i]; c < ' ' || c > '~' {
			fmt.Fprintf(&b, "\\%03d", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Shown is a copy of the trace with every string that came off the wire made
// safe to draw. The walk keeps the octets, since they are what it queries and
// what TLS is checked against; what is written out for a reader is this. A
// trace read back with --from says whatever its file does, so the fields a
// walk fills with this build's own words are escaped too.
func (t *Trace) Shown() *Trace {
	if t == nil {
		return nil
	}
	shown := *t
	shown.Question = t.Question.Shown()
	shown.Root = t.Root.Shown()
	shown.Warnings = shownAll(t.Warnings)
	shown.Resolvers = nil
	for _, resolver := range t.Resolvers {
		if resolver == nil {
			shown.Resolvers = append(shown.Resolvers, nil)
			continue
		}
		r := *resolver
		r.Server = r.Server.Shown()
		r.Rcode, r.Err = Shown(r.Rcode), Shown(r.Err)
		r.Records = shownRecords(r.Records)
		r.Extended = shownExtended(r.Extended)
		shown.Resolvers = append(shown.Resolvers, &r)
	}
	return &shown
}

// Shown is the same copy of one step and everything below it.
func (s *Step) Shown() *Step {
	if s == nil {
		return nil
	}
	shown := *s
	shown.Zone = Shown(s.Zone)
	shown.Server = s.Server.Shown()
	shown.Proto, shown.Rcode = Shown(s.Proto), Shown(s.Rcode)
	shown.Asked = s.Asked.Shown()
	shown.Records = shownRecords(s.Records)
	shown.Extended = shownExtended(s.Extended)
	shown.Notes = shownAll(s.Notes)
	shown.NSID = Shown(s.NSID)
	shown.Err = Shown(s.Err)
	if s.Delegation != nil {
		d := *s.Delegation
		d.Zone = Shown(d.Zone)
		d.NS = shownAll(d.NS)
		d.GlueLess = shownAll(d.GlueLess)
		d.OutOfBailiwick = shownAll(d.OutOfBailiwick)
		if d.Glue != nil {
			d.Glue = make(map[string][]netip.Addr, len(s.Delegation.Glue))
			for name, addrs := range s.Delegation.Glue {
				d.Glue[Shown(name)] = addrs
			}
		}
		shown.Delegation = &d
	}
	if s.DNSSEC != nil {
		d := *s.DNSSEC
		d.Zone = Shown(d.Zone)
		d.Reason = Shown(d.Reason)
		d.Algorithm, d.Digest = Shown(d.Algorithm), Shown(d.Digest)
		if d.Signal != nil {
			signal := *d.Signal
			signal.Reason = Shown(signal.Reason)
			d.Signal = &signal
		}
		shown.DNSSEC = &d
	}
	shown.Children = nil
	for _, child := range s.Children {
		shown.Children = append(shown.Children, child.Shown())
	}
	return &shown
}

// Shown is the question safe to draw.
func (q Question) Shown() Question {
	q.Name, q.Type, q.Class = Shown(q.Name), Shown(q.Type), Shown(q.Class)
	return q
}

// Shown is the server with its name, and what the AS lookup said of it, safe
// to draw.
func (s Server) Shown() Server {
	s.Name = Shown(s.Name)
	if s.ASN != nil {
		asn := *s.ASN
		asn.Prefix = Shown(asn.Prefix)
		asn.CountryCode = Shown(asn.CountryCode)
		asn.Registry = Shown(asn.Registry)
		asn.Allocated = Shown(asn.Allocated)
		s.ASN = &asn
	}
	return s
}

func shownRecords(records []RR) []RR {
	if records == nil {
		return nil
	}
	shown := make([]RR, len(records))
	for i, rr := range records {
		rr.Name, rr.Type, rr.Data = Shown(rr.Name), Shown(rr.Type), Shown(rr.Data)
		if rr.Service != nil {
			service := *rr.Service
			service.Target = Shown(service.Target)
			service.ALPN = shownAll(service.ALPN)
			rr.Service = &service
		}
		shown[i] = rr
	}
	return shown
}

// shownExtended escapes the reason. The text is kept as the server sent it and
// escaped where it is drawn.
func shownExtended(extended []ExtendedError) []ExtendedError {
	if extended == nil {
		return nil
	}
	shown := slices.Clone(extended)
	for i := range shown {
		shown[i].Reason = Shown(shown[i].Reason)
	}
	return shown
}

func shownAll(texts []string) []string {
	if texts == nil {
		return nil
	}
	shown := make([]string, len(texts))
	for i, text := range texts {
		shown[i] = Shown(text)
	}
	return shown
}
