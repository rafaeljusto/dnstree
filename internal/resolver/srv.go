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

	if s.Left > 0 || r.counters.spent() || r.asideStopped {
		s.Cut = true
		r.warnf("", "the SRV check of %s ran out of budget before every target was looked up; raise the budget that ran out", name)
	}
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
