package resolver

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// dsyncNotify is the one delivery scheme RFC 9859 defines.
const dsyncNotify = 1

// dsyncDuplicate is why the second record for a type and scheme is passed over.
const dsyncDuplicate = "a second record for its type and scheme, which RFC 9859 forbids"

// noticing is the zone the walk ended in, kept for the lookup of where its
// parent takes notices that follows the walk.
type noticing struct {
	under     *trace.Step
	parent    string
	delegated *trace.Delegation
}

// noticeAt keeps the zone that answered for the DSYNC lookup, where
// --check-ds or --check-ns asked for what it tells its parent.
func (r *run) noticeAt(answer, referred *trace.Step) {
	if !r.cfg.CheckDS && !r.cfg.CheckNS || referred.Delegation == nil {
		return
	}
	r.notice = &noticing{under: answer, parent: referred.Zone, delegated: referred.Delegation}
}

// dsync finds where the parent of the zone the walk ended in takes a NOTIFY
// about a change to its CDS or CSYNC (RFC 9859 4.1). The walk knows which zone
// is the parent, so the search the RFC makes to find it is not needed: the
// name for the zone alone, which a wildcard of the parent's answers too, and
// then the parent's default. A denial sends the search on only once it has
// validated, since an absence is what anyone can manufacture.
func (r *run) dsync(ctx context.Context) {
	n := r.notice
	if n == nil {
		return
	}
	r.aside, r.asideStopped = true, false
	defer func() { r.aside = false }()

	zone := n.delegated.Zone
	d := &trace.DSYNC{Parent: n.parent}
	n.delegated.DSYNC = d

	names := []string{dnsutil.Join(dnsutil.Trim(zone, n.parent), "_dsync", n.parent), dnsutil.Join("_dsync", n.parent)}
	if !dnsutil.IsName(names[0]) {
		d.Reason = "the name for " + zone + " alone would be longer than 255 octets"
		names = names[1:]
	}

	var result *trace.Step
	for _, name := range names {
		var lookup trace.Lookup
		var stopped bool
		result, lookup, stopped = r.look(ctx, n.under, name, dns.TypeDSYNC, "dsync")
		d.Lookups = append(d.Lookups, lookup)
		switch {
		case stopped:
			d.State, d.Reason = trace.DSYNCUnchecked, "the budget ran out before "+name+" was answered"
			r.warnf("", "the DSYNC check of %s ran out of budget before every lookup was made; raise the budget that ran out", zone)
			return
		case lookup.Err != "":
			d.State, d.Reason = trace.DSYNCUnchecked, "the lookup of "+name+" failed: "+lookup.Err
			r.warnf(trace.AreaDelegation, "the DSYNC lookup of %s failed (%s), so where %s takes notices about %s is unknown",
				name, lookup.Err, n.parent, zone)
			return
		case r.cfg.DNSSEC && lookup.DNSSEC != nil && lookup.DNSSEC.State == trace.Bogus:
			d.State, d.Reason = trace.DSYNCBogus, name+" does not validate: "+lookup.DNSSEC.Reason
			r.warnf(trace.AreaDelegation, "the DSYNC at %s does not validate (%s), so a notifier that validates sends %s nothing about %s; fix the signatures of its zone",
				name, lookup.DNSSEC.Reason, n.parent, zone)
			return
		}
		if result.Kind == trace.KindAnswer {
			if d.Endpoints = dsyncEndpoints(result.Records, result.Asked.Name); len(d.Endpoints) > 0 {
				d.State, d.Name = trace.DSYNCFound, result.Asked.Name
				break
			}
		}
	}
	if d.State == "" {
		d.State = trace.DSYNCNone
		return
	}

	r.dsyncTargets(ctx, n.under, d)
	if r.asideStopped {
		r.warnf("", "the DSYNC check of %s ran out of budget before every lookup was made; raise the budget that ran out", zone)
	}
	r.warnDSYNC(d, zone)
}

// dsyncEndpoints are the DSYNC records owner owns, decoded and sorted, each
// marked with why a notifier passes it over where it does.
func dsyncEndpoints(records []trace.RR, owner string) []trace.DSYNCEndpoint {
	var endpoints []trace.DSYNCEndpoint
	for _, record := range records {
		if record.Type != "DSYNC" || !dns.EqualName(record.Name, owner) {
			continue
		}
		rr, err := dns.New(". IN DSYNC " + record.Data)
		if err != nil {
			continue
		}
		found, ok := rr.(*dns.DSYNC)
		if !ok {
			continue
		}
		e := trace.DSYNCEndpoint{Type: dnsutil.TypeToString(found.Type), Scheme: strconv.Itoa(int(found.Scheme)),
			Port: found.Port, Target: found.Target}
		if found.Scheme == dsyncNotify {
			e.Scheme = "NOTIFY"
		}
		switch {
		case found.Scheme == 0:
			e.Ignored = "scheme 0 names no endpoint"
		case found.Port == 0:
			e.Ignored = "port 0 names no endpoint"
		case found.Scheme != dsyncNotify:
			e.Ignored = "RFC 9859 defines no scheme " + e.Scheme
		case found.Type != dns.TypeCDS && found.Type != dns.TypeCSYNC:
			e.Ignored = "RFC 9859 takes notices only of CDS and CSYNC"
		case found.Target == ".":
			e.Ignored = "it names no host"
		}
		endpoints = append(endpoints, e)
	}
	slices.SortFunc(endpoints, func(a, b trace.DSYNCEndpoint) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.Scheme, b.Scheme), cmp.Compare(a.Port, b.Port), cmp.Compare(dnsutil.Canonical(a.Target), dnsutil.Canonical(b.Target)))
	})
	// RFC 9859 2.1 allows one record for each type and scheme.
	for i := range endpoints {
		e := &endpoints[i]
		if e.Ignored == "" && slices.ContainsFunc(endpoints[:i], func(seen trace.DSYNCEndpoint) bool {
			return seen.Ignored == "" && seen.Type == e.Type && seen.Scheme == e.Scheme
		}) {
			e.Ignored = dsyncDuplicate
		}
	}
	return endpoints
}

// dsyncTargets looks up the addresses of every host the endpoints a notifier
// uses name, each host once.
func (r *run) dsyncTargets(ctx context.Context, under *trace.Step, d *trace.DSYNC) {
	done := map[string]*trace.DSYNCEndpoint{}
	for i := range d.Endpoints {
		e := &d.Endpoints[i]
		if e.Ignored != "" {
			continue
		}
		if seen, ok := done[dnsutil.Canonical(e.Target)]; ok {
			e.IPv4, e.IPv6, e.Addrs = seen.IPv4, seen.IPv6, seen.Addrs
			continue
		}
		for _, f := range []struct {
			family int
			qtype  uint16
			into   **trace.Lookup
		}{{4, dns.TypeA, &e.IPv4}, {6, dns.TypeAAAA, &e.IPv6}} {
			if r.cfg.Family != 0 && r.cfg.Family != f.family {
				continue
			}
			result, lookup, stopped := r.look(ctx, under, e.Target, f.qtype, "dsync")
			*f.into = &lookup
			if stopped {
				return
			}
			if lookup.Err != "" {
				continue
			}
			for _, record := range result.Records {
				if record.Type != dnsutil.TypeToString(f.qtype) || !dns.EqualName(record.Name, result.Asked.Name) {
					continue
				}
				if addr, err := netip.ParseAddr(record.Data); err == nil && !slices.Contains(e.Addrs, addr) {
					e.Addrs = append(e.Addrs, addr)
				}
			}
		}
		done[dnsutil.Canonical(e.Target)] = e
	}
}

// warnDSYNC says what keeps a notice from reaching the parent.
func (r *run) warnDSYNC(d *trace.DSYNC, zone string) {
	warned := map[string]bool{}
	for _, e := range d.Endpoints {
		if e.Ignored == dsyncDuplicate && !warned[e.Type+" "+e.Scheme] {
			warned[e.Type+" "+e.Scheme] = true
			r.warnf(trace.AreaDelegation, "%s has more than one DSYNC for %s %s at %s, which RFC 9859 forbids, so which one a notifier uses is anyone's guess; keep one",
				d.Parent, e.Type, e.Scheme, d.Name)
		}
		target := dnsutil.Canonical(e.Target)
		if e.Ignored == "" && len(e.Addrs) == 0 && answered(e.IPv4) && answered(e.IPv6) && !warned[target] {
			warned[target] = true
			r.warnf(trace.AreaDelegation, "the DSYNC target %s that %s names for notices about %s has no address, so they go nowhere; give it one, or name another",
				e.Target, d.Parent, zone)
		}
	}
}

// answered reports whether a lookup was answered, if only with nothing, or was
// never asked.
func answered(lookup *trace.Lookup) bool {
	return lookup == nil || lookup.Err == ""
}
