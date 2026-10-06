package resolver

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// knownTags are the CAA properties whose meaning is registered (RFC 8659,
// RFC 9495 and the CA/Browser Forum's contact tags). A critical property
// outside them is one an authority has to refuse to issue under.
var knownTags = []string{"issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone"}

// cut is a zone the walk for the question entered, with the servers it found
// for it and the chain of trust as it stood there.
type cut struct {
	zone    string
	servers []trace.Server
	chain   *dnssec.Chain
}

// record keeps a zone the walk entered for the CAA lookups, which ask each
// name of the climb of the zone it sits in rather than walking to it again.
func (r *run) record(zone string, servers []trace.Server, chain *dnssec.Chain) {
	r.cuts = append(r.cuts, cut{zone: zone, servers: servers, chain: chain.Clone()})
}

// cutOf is the deepest zone the walk entered that name sits in.
func (r *run) cutOf(name string) *cut {
	var found *cut
	for i := range r.cuts {
		c := &r.cuts[i]
		if dnsutil.IsBelow(c.zone, name) && (found == nil || dnsutil.Labels(c.zone) > dnsutil.Labels(found.zone)) {
			found = c
		}
	}
	return found
}

// climb finds the CAA set that decides who may issue for the name, the way an
// authority does (RFC 8659 3): at the name, then at each name above it short
// of the root, until one has a set. A lookup that fails stops the climb there,
// since an authority cannot tell what it would have found.
func (r *run) climb(ctx context.Context, under *trace.Step) {
	// Nothing to climb: the root is never asked, and a walk that entered no
	// zone has already said why.
	name := r.trace.Question.Name
	if len(r.cuts) == 0 || dnsutil.Labels(name) == 0 {
		return
	}

	r.climbing = true
	defer func() { r.climbing = false }()

	caa := &trace.CAA{}
	r.trace.CAA = caa

	// The verdict is the first on the way up that is not secure, or else the
	// last one the climb came to.
	var last *trace.DNSSECStatus
	defer func() {
		if caa.DNSSEC == nil {
			caa.DNSSEC = last
		}
	}()

	for labels := dnsutil.Labels(name); labels > 0; labels-- {
		asked := ancestor(name, labels)
		cnames := r.counters.cnames
		lookup, records, status, judge := r.lookupCAA(ctx, under, asked)
		caa.Asked = append(caa.Asked, lookup)
		if status != nil {
			last = status
			if status.State != trace.Secure && caa.DNSSEC == nil {
				caa.DNSSEC = status
			}
		}

		switch lookup.Found {
		case trace.CAAFailed:
			r.failed(caa, lookup, judge, r.counters.spentSince(cnames))
			return
		case trace.CAASet:
			caa.Owner = asked
			decide(caa, records)
			if caa.Refused != "" {
				r.warnf("", "%s, so no authority may issue for %s; remove it or ask the authority whether it knows it", caa.Refused, name)
			}
			return
		}
	}
}

// failed says what a lookup that stopped the climb leaves an authority to do.
// Only a zone with a chain of trust behind it makes every one refuse: where
// none vouches for it, an authority that retried may take the failure as leave
// to issue (CA/Browser Forum Baseline Requirements 3.2.2.8). c is the zone the
// failure is judged by, nil where the walk holds none for it; stopped is a
// budget that ran out on the way.
func (r *run) failed(caa *trace.CAA, lookup trace.CAALookup, c *cut, stopped bool) {
	name, why := r.trace.Question.Name, "the CAA lookup at "+lookup.Name+" failed: "+lookup.Err
	zone := "the zone of " + lookup.Name
	if c != nil {
		zone = c.zone
	}

	switch {
	case stopped:
		caa.Undecided = why
		r.warnf("", "the CAA lookup at %s was not made (%s), so who may issue for %s is not known; raise the budget that ran out",
			lookup.Name, lookup.Err, name)
	case c != nil && c.chain != nil && c.chain.State() == trace.Secure:
		caa.Refused = why
		r.warnf("", "the CAA lookup at %s failed (%s), and %s is signed, so every authority has to refuse to issue for %s; fix the servers of %s",
			lookup.Name, lookup.Err, zone, name, zone)
	default:
		caa.Undecided = why
		r.warnf("", "the CAA lookup at %s failed (%s), so an authority may refuse to issue for %s, and only one that finds no chain of trust to %s may take it as leave to; fix the servers of %s",
			lookup.Name, lookup.Err, name, zone, zone)
	}
}

// lookupCAA asks for the CAA set at one name of the climb, of the servers of
// the zone it sits in, trying them in turn the way the walk does. An alias is
// followed with a walk of its own, which is what an authority's lookup does.
// The zone it returns is the one a failure is judged by.
func (r *run) lookupCAA(ctx context.Context, under *trace.Step, name string) (trace.CAALookup, []trace.RR, *trace.DNSSECStatus, *cut) {
	lookup := trace.CAALookup{Name: name, Found: trace.CAAFailed}
	c := r.cutOf(name)
	if c == nil {
		lookup.Err = "the walk never reached a zone it is in"
		return lookup, nil, nil, nil
	}

	lookup.Err = "no server of " + c.zone + " could be asked"
	for _, server := range dedupe(c.servers) {
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		if r.cfg.Down != nil && r.cfg.Down(server) != "" {
			continue
		}
		if err := r.counters.query(); err != nil {
			r.fail(under, c.zone, err.Error())
			lookup.Err = err.Error()
			return lookup, nil, nil, c
		}

		hop := r.query(ctx, c.zone, server, name, dns.TypeCAA)
		hop.step.Aside = true
		hop.step.Notes = append(hop.step.Notes, "CAA of "+name)
		r.attach(under, hop.step)

		switch hop.step.Kind {
		case trace.KindAnswer, trace.KindNoData, trace.KindNXDomain:
			r.verifyIn(ctx, c, hop, name)
			records := owned(hop.step.Records, name)
			lookup.Found, lookup.Err = trace.CAANone, ""
			if len(records) > 0 {
				lookup.Found = trace.CAASet
			}
			return lookup, records, hop.step.DNSSEC, c
		case trace.KindCNAME:
			r.verifyIn(ctx, c, hop, name)
			lookup, records, status := r.aliasCAA(ctx, hop.step, name, lookup)
			return lookup, records, status, c
		case trace.KindReferral:
			// The name sits in a zone the walk never entered, whose chain of
			// trust, if it has one, the walk does not know.
			lookup.Err = "it is delegated below " + c.zone + ", where the walk never went"
			return lookup, nil, nil, nil
		}
		lookup.Err = why(hop.step)
	}
	return lookup, nil, nil, c
}

// aliasCAA follows an alias met on the climb to the set at its target. The
// climb itself goes on from the alias, not from the target: RFC 8659 follows
// the alias for the lookup alone.
func (r *run) aliasCAA(ctx context.Context, step *trace.Step, name string, lookup trace.CAALookup) (trace.CAALookup, []trace.RR, *trace.DNSSECStatus) {
	target := cnameTarget(step.Records, name)
	if target == "" {
		lookup.Err = "it is an alias for a name the answer did not carry"
		return lookup, nil, step.DNSSEC
	}
	if err := r.counters.cname(); err != nil {
		r.fail(step, step.Zone, err.Error())
		lookup.Err = err.Error()
		return lookup, nil, step.DNSSEC
	}

	// The walk's own aliases are not this lookup's, and must not read as a loop.
	saved := r.chased
	r.chased = map[string]bool{dnsutil.Canonical(name): true, dnsutil.Canonical(target): true}
	defer func() { r.chased = saved }()

	root := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true, Notes: []string{"resolving " + target + " for its CAA"}}
	r.attach(step, root)
	result := r.walk(ctx, target, dns.TypeCAA, root, 0)

	status := step.DNSSEC
	if result != nil && result.DNSSEC != nil && (status == nil || status.State == trace.Secure) {
		status = result.DNSSEC
	}
	if result == nil {
		lookup.Err = "no server answered for " + target
		return lookup, nil, status
	}
	switch result.Kind {
	case trace.KindAnswer, trace.KindNoData, trace.KindNXDomain:
	default:
		lookup.Err = why(result)
		return lookup, nil, status
	}

	lookup.Alias, lookup.Err = result.Asked.Name, ""
	records := owned(result.Records, result.Asked.Name)
	lookup.Found = trace.CAANone
	if len(records) > 0 {
		lookup.Found = trace.CAASet
	}
	return lookup, records, status
}

// verifyIn checks an answer on the climb against the keys of the zone it came
// from, as the walk held them there. An answer signed by a zone below that one
// crosses into it first, the way the walk does.
func (r *run) verifyIn(ctx context.Context, c *cut, hop *hop, name string) {
	if c.chain != nil {
		r.verify(ctx, c.chain.Clone(), hop, name, dns.TypeCAA)
	}
}

// owned are the CAA records name itself owns.
func owned(records []trace.RR, name string) []trace.RR {
	var found []trace.RR
	for _, record := range records {
		if record.Type == "CAA" && dns.EqualName(record.Name, name) {
			found = append(found, record)
		}
	}
	return found
}

// why is what a failed lookup came to, in a few words.
func why(step *trace.Step) string {
	switch {
	case step.Rcode != "" && step.Rcode != "NOERROR":
		return step.Rcode
	case step.Err != "":
		return step.Err
	}
	return string(step.Kind)
}

// decide reads the set that decides into who may issue (RFC 8659 4). A set
// with no issue property restricts nobody; one with no issuewild leaves
// wildcards to issue.
func decide(caa *trace.CAA, records []trace.RR) {
	var issue, wildcard *trace.Issuers
	for _, record := range records {
		rr, err := dns.New(". IN CAA " + record.Data)
		parsed, ok := rr.(*dns.CAA)
		if err != nil || !ok {
			// A tag the text cannot carry is no registered one, and refuses
			// all the same when it is critical (RFC 8659 4.1).
			flag, _, _ := strings.Cut(record.Data, " ")
			if n, err := strconv.ParseUint(flag, 10, 8); err == nil && n&0x80 != 0 && caa.Refused == "" {
				caa.Refused = caa.Owner + " carries a critical property whose tag is no valid one, which an authority has to refuse"
			}
			continue
		}
		tag := strings.ToLower(parsed.Tag)
		property := trace.CAARecord{
			Critical: parsed.Flag&0x80 != 0,
			Tag:      parsed.Tag,
			Value:    parsed.Value,
			Known:    slices.Contains(knownTags, tag),
		}
		caa.Records = append(caa.Records, property)

		if property.Critical && !property.Known && caa.Refused == "" {
			caa.Refused = caa.Owner + " carries the critical property " + parsed.Tag + ", which an authority that does not know it has to refuse"
		}
		switch tag {
		case "issue":
			issue = issuer(issue, parsed.Value)
		case "issuewild":
			wildcard = issuer(wildcard, parsed.Value)
		}
	}
	if wildcard == nil {
		wildcard = issue
	}
	caa.Issue, caa.Wildcard = issue, wildcard
}

// issuer adds the authority an issue or issuewild value names. A value with no
// domain before its parameters names nobody, which still restricts.
func issuer(issuers *trace.Issuers, value string) *trace.Issuers {
	if issuers == nil {
		issuers = &trace.Issuers{CAs: []string{}}
	}
	domain, _, _ := strings.Cut(value, ";")
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain != "" && !slices.Contains(issuers.CAs, domain) {
		issuers.CAs = append(issuers.CAs, domain)
	}
	return issuers
}
