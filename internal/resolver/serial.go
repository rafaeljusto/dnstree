package resolver

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// checkSerial asks every nameserver of the zone the walk ended in which copy of
// that zone it is serving. Only the parent's list says who they all are, and a
// walk stops at the first that answers, so a secondary left behind by a zone
// transfer is invisible to everything else here: it answers the question
// correctly, out of an older zone.
//
// The queries go out together and join the trace afterwards, the way --all's
// do, because a step may only be attached from the goroutine doing the walking.
func (r *run) checkSerial(ctx context.Context, answer *trace.Step, zone string, servers []trace.Server) {
	if !r.cfg.Serial {
		return
	}

	var usable []trace.Server
	for _, server := range dedupe(servers) {
		// A server of the wrong family was never asked the question either, so
		// holding the zone against it here would be holding it against a
		// nameserver this walk has nothing to say about.
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		usable = append(usable, server)
	}

	usable, budget := afford(r.counters, usable)
	hops := askAll(usable, func(server trace.Server) *hop { return r.query(ctx, zone, server, zone, dns.TypeSOA) })

	for _, hop := range hops {
		step := hop.step
		if hop.resp != nil {
			step.SOA = soa(hop.resp.Answer)
		}
		step.Aside = true
		step.Records = nil // the serial is the point, and it is on the step
		step.Notes = append(step.Notes, serialNote(zone, step.SOA))
		r.attach(answer, step)
	}
	if budget != nil {
		r.warnf(trace.AreaConsistency, "the budget ran out before every nameserver of %s could be asked for its serial", zone)
	}
	r.compareSerials(zone, hops)
}

// serialNote labels the aside for a reader of the tree. A server that answered
// with no SOA is labelled by what it was asked rather than by what it gave,
// since the step itself already says how the query went.
func serialNote(zone string, soa *trace.SOA) string {
	if soa == nil {
		return "SOA of " + zone
	}
	return fmt.Sprintf("SOA of %s: %d", zone, soa.Serial)
}

// compareSerials warns where the nameservers of a zone do not hold the same
// copy of it. Which serial is the newer one is deliberately not claimed: serial
// arithmetic wraps (RFC 1982), and a walk that named the wrong one as behind
// would send somebody to restart the wrong server.
func (r *run) compareSerials(zone string, hops []*hop) {
	name := naming(hops)
	var order []uint32
	serving := make(map[uint32][]string)
	for _, hop := range hops {
		if hop.step.SOA == nil {
			continue
		}
		serial := hop.step.SOA.Serial
		if _, seen := serving[serial]; !seen {
			order = append(order, serial)
		}
		serving[serial] = append(serving[serial], name(hop.step))
	}
	if len(order) < 2 {
		return
	}

	held := make([]string, 0, len(order))
	for _, serial := range order {
		held = append(held, fmt.Sprintf("%d at %s", serial, strings.Join(serving[serial], " and ")))
	}
	r.warnf(trace.AreaConsistency, "the nameservers of %s are serving different copies of it: %s", zone, strings.Join(held, ", "))
}

// at is a server as a reader would name it.
func at(step *trace.Step) string {
	if step.Server.Name != "" {
		return step.Server.Name
	}
	return step.Server.IP.String()
}

// naming names the servers of a sweep, with the address where one name stands
// for several: anycast sites behind one name can disagree, and naming only the
// host would put it on both sides.
func naming(hops []*hop) func(*trace.Step) string {
	addrs := make(map[string]map[netip.Addr]bool)
	for _, hop := range hops {
		name := at(hop.step)
		if addrs[name] == nil {
			addrs[name] = make(map[netip.Addr]bool)
		}
		addrs[name][hop.step.Server.IP] = true
	}
	return func(step *trace.Step) string {
		name := at(step)
		if len(addrs[name]) > 1 {
			return name + " (" + step.Server.IP.String() + ")"
		}
		return name
	}
}
