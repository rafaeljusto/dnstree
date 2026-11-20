package resolver

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// srv follows the name's SRV records (RFC 2782) to the addresses of every
// target they name, as a client of the service would. end is where the walk
// for the question ended, whose answer is the set where the question was for
// one. Every other lookup is a walk of its own, drawn as an aside under under.
func (r *run) srv(ctx context.Context, under, end *trace.Step) {
	name := r.trace.Question.Name

	r.aside, r.asideStopped = true, false
	defer func() { r.aside = false }()

	s := &trace.SRV{Name: name}
	r.trace.SRV = s

	var result *trace.Step
	stopped := false
	if r.trace.Question.Type == "SRV" {
		result, s.Lookup = end, ended(name, r.trace.Root, end)
	} else {
		result, s.Lookup, stopped = r.look(ctx, under, name, dns.TypeSRV, "srv")
	}

	switch {
	case stopped:
		s.Stopped = "the budget ran out before the SRV lookup was answered"
	case s.Lookup.Err != "":
		s.Stopped = "the SRV lookup failed: " + s.Lookup.Err
		r.warnf(trace.AreaAnswer, "the SRV lookup of %s failed (%s), so a client finds no server for the service; fix the servers of its zone",
			name, s.Lookup.Err)
	case r.cfg.DNSSEC && s.Lookup.DNSSEC != nil && s.Lookup.DNSSEC.State == trace.Bogus:
		s.Stopped = "the SRV set does not validate: " + s.Lookup.DNSSEC.Reason
		r.warnf(trace.AreaDNSSEC, "the SRV set of %s does not validate (%s), so a client that validates finds no server for the service; fix the signatures of its zone",
			name, s.Lookup.DNSSEC.Reason)
	}
	if stopped {
		s.Cut = true
		r.warnf("", "the SRV check of %s ran out of budget before the SRV set was looked up; raise the budget that ran out", name)
	}
	if s.Stopped != "" {
		return
	}

	targets, null := srvTargets(result.Records, result.Asked.Name)
	switch {
	case len(targets) == 0 && null:
		s.None = true
		return
	case null:
		r.warnf(trace.AreaAnswer, "%s has an SRV record with a target of . beside others, where . says the service is not offered at all (RFC 2782); remove the one or the others",
			cmp.Or(s.Lookup.Alias, name))
	}

	// A host named on several ports, or at several priorities, is looked up
	// once. Past the budget, a record whose host was asked already is still
	// kept.
	looked := map[string]hostFound{}
	for _, target := range targets {
		host := dnsutil.Canonical(target.Name)
		found, ok := looked[host]
		if !ok {
			if r.counters.spent() {
				s.Left++
				continue
			}
			found = r.hostAddresses(ctx, under, target.Name, "srv")
			looked[host] = found
		}
		target.IPv4, target.IPv6, target.Addrs = found.ipv4, found.ipv6, found.addrs
		if found.stopped {
			s.Targets = append(s.Targets, target)
			continue
		}
		if r.internet {
			for _, addr := range target.Addrs {
				if transport.Unroutable(addr) != "" {
					target.Unreachable = append(target.Unreachable, addr)
				}
			}
		}
		if !ok {
			r.warnTarget(s, target)
		}
		s.Targets = append(s.Targets, target)
	}

	if r.cfg.TLSA {
		r.srvDANE(ctx, under, s)
	}

	if s.Left > 0 || r.counters.spent() || r.asideStopped {
		s.Cut = true
		r.warnf("", "the SRV check of %s ran out of budget before every target was looked up; raise the budget that ran out", name)
	}
}

// srvDANE looks up the TLSA set of each target where a client that checks
// DANE would (RFC 7673 3): only under a signed SRV set, over TCP, and only for
// a target with a signed address set. A host on one port is asked once.
func (r *run) srvDANE(ctx context.Context, under *trace.Step, s *trace.SRV) {
	every := func(state trace.DANEState, why string) {
		for i := range s.Targets {
			s.Targets[i].DANE, s.Targets[i].Why = state, why
		}
	}
	switch {
	case s.Lookup.DNSSEC == nil || s.Lookup.DNSSEC.State != trace.Secure:
		every(trace.DANEInsecure, "the SRV set is not signed, so a client does not look for its TLSA set")
		return
	case s.Proto() != "_tcp":
		every(trace.DANEIndeterminate, "--tlsa checks DANE over TCP alone, and the SRV set is not for _tcp")
		return
	}

	asked := map[string]*trace.SRVTarget{}
	for i := range s.Targets {
		target := &s.Targets[i]
		name := "_" + strconv.Itoa(int(target.Port)) + "._tcp." + target.Name
		key := dnsutil.Canonical(name)
		if prior, ok := asked[key]; ok {
			target.TLSA, target.Records, target.DANE, target.Why = prior.TLSA, prior.Records, prior.DANE, prior.Why
			continue
		}
		asked[key] = target
		r.srvTarget(ctx, under, target, name)
		switch {
		case target.DANE == trace.DANEFailed && target.TLSA != nil:
			// Addresses that do not validate are said with the target.
			r.warnf("", "a client that checks DANE does not connect to %s on port %d, since %s; fix the servers of its zone",
				target.Name, target.Port, target.Why)
		case target.DANE == trace.DANEInsecure && len(target.Records) > 0:
			r.warnf(trace.AreaAnswer, "%s has a TLSA set nothing signed, which clients ignore; sign the zone it is in",
				cmp.Or(target.TLSA.Alias, target.TLSA.Name))
		}
	}
}

// srvTarget decides what a client that checks DANE makes of one target, and
// looks up its TLSA set at name where it would.
func (r *run) srvTarget(ctx context.Context, under *trace.Step, target *trace.SRVTarget, name string) {
	switch {
	case target.IPv4 == nil && target.IPv6 == nil:
		target.DANE, target.Why = trace.DANEIndeterminate, "the budget ran out before its addresses were looked up"
		return
	case target.Failed() != "":
		target.DANE, target.Why = trace.DANEUnreachable, "its addresses could not be looked up: "+target.Failed()
		return
	case target.Nowhere():
		target.DANE, target.Why = trace.DANEUnreachable, "it has no address"
		return
	case len(target.Proven()) == 0:
		// One address set a client may rely on is enough to look (RFC 7673
		// 3.2); without one, the worst of them says why not.
		switch {
		case bogus(target.IPv4, target.IPv6) != "":
			target.DANE, target.Why = trace.DANEFailed, "its addresses do not validate: "+bogus(target.IPv4, target.IPv6)
		case unchecked(target.IPv4, target.IPv6) != "":
			target.DANE, target.Why = trace.DANEIndeterminate, "its addresses could not be checked: "+unchecked(target.IPv4, target.IPv6)
		default:
			target.DANE, target.Why = trace.DANEInsecure, "its addresses are not signed, so its TLSA set is not asked for"
		}
		return
	case r.counters.spent():
		target.DANE, target.Why = trace.DANEIndeterminate, "the budget ran out before its TLSA set was looked up"
		return
	}

	lookup, records, state, why := r.tlsaSet(ctx, under, name, "srv")
	target.TLSA, target.Records = &lookup, records
	switch {
	case state != "":
		target.DANE, target.Why = state, why
	case slices.ContainsFunc(records, func(t trace.TLSARecord) bool { return t.Usage == 0 || t.Usage == 1 }):
		// A PKIX record is one a client may use (RFC 7673 4.2), and one this
		// build does not check: a chain no DANE record matches may still be
		// one it vouches for.
		target.DANE, target.Why = trace.DANEIndeterminate, "its TLSA set holds PKIX records, which --tlsa does not check"
	case slices.ContainsFunc(records, func(t trace.TLSARecord) bool { return t.Usable }):
		target.DANE, target.Why = trace.DANEVerified, "a client has to see a certificate that matches"
	default:
		target.DANE, target.Why = trace.DANEUnusable, "none of its TLSA records is usable, so a client checks the certificate the usual way"
	}
}

// unchecked is why the first of the lookups whose signatures could not be
// checked was not, and empty where none.
func unchecked(lookups ...*trace.Lookup) string {
	for _, lookup := range lookups {
		if lookup != nil && lookup.DNSSEC != nil && lookup.DNSSEC.State == trace.Indeterminate {
			return lookup.DNSSEC.Reason
		}
	}
	return ""
}

// srvTargets are the SRV records owner owns, by priority, then by target and
// port so that two walks of the same set read the same, and whether one of
// them has a target of ".".
func srvTargets(records []trace.RR, owner string) ([]trace.SRVTarget, bool) {
	var targets []trace.SRVTarget
	null := false
	for _, record := range records {
		if record.Type != "SRV" || !dns.EqualName(record.Name, owner) {
			continue
		}
		// The target is last, and kept whole: it is the raw octets the zone
		// wrote, which may hold a space.
		fields := strings.SplitN(record.Data, " ", 4)
		if len(fields) != 4 {
			continue
		}
		var numbers [3]uint16
		ok := true
		for i := range numbers {
			n, err := strconv.ParseUint(fields[i], 10, 16)
			numbers[i], ok = uint16(n), ok && err == nil
		}
		if !ok {
			continue
		}
		if fields[3] == "." {
			null = true
			continue
		}
		targets = append(targets, trace.SRVTarget{
			Name: dnsutil.Fqdn(fields[3]), Priority: numbers[0], Weight: numbers[1], Port: numbers[2],
		})
	}
	slices.SortFunc(targets, func(a, b trace.SRVTarget) int {
		return cmp.Or(cmp.Compare(a.Priority, b.Priority), dns.CompareName(a.Name, b.Name), cmp.Compare(a.Port, b.Port))
	})
	return targets, null
}

// warnTarget says what keeps a client from the server a target names. It is
// said once for a host, however many records name it.
func (r *run) warnTarget(s *trace.SRV, target trace.SRVTarget) {
	switch {
	case target.Failed() != "":
		r.warnf(trace.AreaAnswer, "the addresses of %s, which the SRV records of %s name, could not be looked up (%s), so a client may have nothing to connect to there; fix the servers of its zone",
			target.Name, s.Name, target.Failed())
	case r.cfg.DNSSEC && bogus(target.IPv4, target.IPv6) != "":
		// The zone is the host's, not the name's, so it is no mark on the
		// chain of trust --check grades.
		r.warnf(trace.AreaAnswer, "the addresses of %s, which the SRV records of %s name, do not validate (%s), so a client that validates has nothing to connect to there; fix the signatures of its zone",
			target.Name, s.Name, bogus(target.IPv4, target.IPv6))
	case target.Nowhere():
		r.warnf(trace.AreaAnswer, "%s, which the SRV records of %s name, has no address, so a client has nothing to connect to there; fix the record or give the target an address",
			target.Name, s.Name)
	}
	if alias := target.Alias(); alias != "" {
		r.warnf(trace.AreaAnswer, "%s, which the SRV records of %s name, is an alias for %s, which RFC 2782 forbids, so some clients will not follow it; name the host by its own name",
			target.Name, s.Name, alias)
	}
	for _, addr := range target.Unreachable {
		r.warnf(trace.AreaAnswer, "%s, which the SRV records of %s name, has %s, %s; give it an address clients can reach",
			target.Name, s.Name, addr, unroutableTarget[transport.Unroutable(addr)])
	}
}

// unroutableTarget is what each kind of address transport.Unroutable names
// means for a server clients are sent to.
var unroutableTarget = map[string]string{
	"private":       "a private address no client on the internet can reach, usually a record from an internal view of the zone",
	"loopback":      "a loopback address, which every client takes for itself",
	"link-local":    "a link-local address no client on the internet can reach",
	"shared":        "an address in the space carriers number their own customers from (RFC 6598), which clients outside that carrier cannot reach",
	"documentation": "an address kept for documentation that no client can reach, usually an example never replaced",
	"benchmarking":  "an address kept for benchmarks that no client on the internet can reach",
	"reserved":      "a reserved address no client on the internet can reach",
}

// bogus is why the first of the lookups that does not validate failed, and
// empty where none.
func bogus(lookups ...*trace.Lookup) string {
	for _, lookup := range lookups {
		if lookup != nil && lookup.DNSSEC != nil && lookup.DNSSEC.State == trace.Bogus {
			return lookup.DNSSEC.Reason
		}
	}
	return ""
}
