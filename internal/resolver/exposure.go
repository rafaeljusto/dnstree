package resolver

import (
	"cmp"
	"context"
	"slices"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// checkExposure asks every nameserver of the zone the walk ended in for what it
// should keep from strangers: the whole zone, a lookup of somebody else's name,
// and a denial that may list the zone a name at a time. Like checkSerial the
// questions go out together and join the trace afterwards, from the goroutine
// doing the walking.
//
// The root is left alone. Its servers hand the zone to anyone on purpose (RFC
// 8806), and a name outside the root's zones does not exist to be asked.
func (r *run) checkExposure(ctx context.Context, answer *trace.Step, zone string, servers []trace.Server) {
	if (!r.cfg.CheckTransfer && !r.cfg.CheckRecursion) || zone == "." {
		return
	}

	// A transfer is a stream over TCP (RFC 5936). A walk over DoT can ask it
	// over TLS, which is how XoT carries one (RFC 9103); DoH carries none.
	transfer := r.cfg.TCP
	if transfer == nil {
		switch r.cfg.Transport.Proto() {
		case transport.ProtoTCP, transport.ProtoDoT:
			transfer = r.cfg.Transport
		}
	}
	checkTransfer := r.cfg.CheckTransfer
	if checkTransfer && transfer == nil {
		checkTransfer = false
		r.warnf(trace.AreaStrangers, "zone transfers of %s were not checked: they need tcp, and %s carries none; walk with --udp, --tcp or --dot to check them",
			zone, r.cfg.Transport.Proto())
	}

	type probe struct {
		server trace.Server
		kind   trace.ProbeKind
	}
	var probes []probe
	for _, server := range dedupe(servers) {
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		if checkTransfer {
			probes = append(probes, probe{server, trace.ProbeTransfer})
		}
		// Following NSEC records lists a zone as surely as a transfer does, so
		// it goes with --check-axfr, over any transport.
		if r.cfg.CheckTransfer {
			probes = append(probes, probe{server, trace.ProbeListing})
		}
		if r.cfg.CheckRecursion {
			probes = append(probes, probe{server, trace.ProbeRecursion})
		}
	}

	probes, budget := afford(r.counters, probes)
	steps := askAll(probes, func(p probe) *trace.Step {
		switch p.kind {
		case trace.ProbeTransfer:
			return r.probe(ctx, zone, p.server, transfer, zone, dns.TypeAXFR, p.kind, false, transferred(zone))
		case trace.ProbeListing:
			qname := listingName + zone
			return r.probe(ctx, zone, p.server, r.cfg.Transport, qname, dns.TypeA, p.kind, false, listed(qname))
		}
		return r.probe(ctx, zone, p.server, r.cfg.Transport, ".", dns.TypeNS, p.kind, true, recursed)
	})

	for _, step := range steps {
		r.attach(answer, step)
	}
	if budget != nil {
		r.warnf(trace.AreaStrangers, "the budget ran out before every nameserver of %s could be checked for what it gives strangers", zone)
	}
}

// listingName is the label of the made-up name a listing probe asks for. It is
// fixed rather than random so that a capture of the walk replays.
const listingName = "dnstree-listing."

// probe asks one server one of the questions checkExposure puts, and reads the
// answer with read. Whatever came back is dropped once it has been read: the
// zone a server should not have handed over is not ours to keep or draw.
func (r *run) probe(ctx context.Context, zone string, server trace.Server, carrier transport.Transport,
	qname string, qtype uint16, kind trace.ProbeKind, recurse bool, read func(*dns.Msg, *trace.Probe)) *trace.Step {

	port := server.Port
	server.Port = cmp.Or(port, carrier.Port())
	if r.cfg.Asking != nil {
		if done := r.cfg.Asking(zone, server); done != nil {
			defer done()
		}
	}
	step := &trace.Step{
		Zone:   zone,
		Server: server,
		Proto:  carrier.Proto(),
		Asked:  trace.Question{Name: qname, Type: dnsutil.TypeToString(qtype)},
		Start:  r.since(),
		Aside:  true,
		Probe:  &trace.Probe{Kind: kind, State: trace.ProbeUnchecked},
	}
	desire := func(req *dns.Msg) {
		req.RecursionDesired = recurse
		// The denials only come signed to a query that asks for DNSSEC.
		if kind == trace.ProbeListing {
			req.Security = req.UDPSize > 0
		}
	}

	udpSize := r.cfg.UDPSize
	resp, err := r.exchange(ctx, step, carrier, qname, qtype, udpSize, port, desire)

	// A lookup can go wherever the walk's own questions went, plain DNS
	// included. A transfer cannot: the fallback is a datagram.
	if err != nil && kind == trace.ProbeRecursion && r.cfg.Fallback != nil {
		if retry, fallbackErr := r.exchange(ctx, step, r.cfg.Fallback, qname, qtype, udpSize, port, desire); fallbackErr == nil {
			step.Notes = append(step.Notes, carrier.Proto()+" did not get through, asked over "+r.cfg.Fallback.Proto())
			carrier = r.cfg.Fallback
			step.Proto = carrier.Proto()
			step.Server.Port = cmp.Or(port, carrier.Port())
			resp, err = retry, nil
		}
	}
	if err == nil && udpSize > 0 && (resp.Rcode == dns.RcodeFormatError || resp.Rcode == dns.RcodeNotImplemented) {
		if retry, retryErr := r.exchange(ctx, step, carrier, qname, qtype, 0, port, desire); retryErr == nil {
			resp = retry
			step.Notes = append(step.Notes, "retried without EDNS0")
		}
	}
	if err == nil && resp.Truncated && r.cfg.TCP != nil && carrier.Proto() != r.cfg.TCP.Proto() {
		if retry, retryErr := r.exchange(ctx, step, r.cfg.TCP, qname, qtype, udpSize, port, desire); retryErr == nil {
			resp = retry
			step.Proto = r.cfg.TCP.Proto()
			step.Notes = append(step.Notes, "truncated over "+carrier.Proto())
		}
	}
	switch {
	case err != nil:
		failed(ctx, step, err)
		// A connection taken and then reset once the AXFR was in is how some
		// providers refuse a transfer, Route 53 among them. One never taken
		// says nothing of what the server would have done, and stays unchecked,
		// and so does a reset over TLS, which may have come before the AXFR.
		if kind == trace.ProbeTransfer && carrier.Proto() == transport.ProtoTCP && transport.IsReset(err) {
			step.Probe.State = trace.ProbeClosed
			step.Notes = append(step.Notes, "reset, which is how some servers refuse a transfer")
		}
		return step
	case resp.Truncated:
		// What is missing from a truncated reply could be the very records
		// that would have said it was open.
		step.Kind, step.Err = trace.KindError, "the answer did not fit and could not be fetched whole"
		return step
	}

	step.Kind = trace.KindAnswer
	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	step.Size = len(resp.Data)
	step.Flags = trace.Flags{AA: resp.Authoritative, EDNS: resp.UDPSize > 0}
	step.Probe.State = trace.ProbeClosed
	read(resp, step.Probe)
	return step
}

// transferred reads a reply to an AXFR as the zone where it opens with the
// zone's own SOA (RFC 5936 2.2). A refusal, or anything else, is not.
func transferred(zone string) func(*dns.Msg, *trace.Probe) {
	return func(resp *dns.Msg, probe *trace.Probe) {
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			return
		}
		first := resp.Answer[0]
		if dns.RRToType(first) == dns.TypeSOA && dns.EqualName(first.Header().Name, zone) {
			probe.State = trace.ProbeOpen
		}
	}
}

// listed reads the denial of qname, a name made up under the zone. A reply
// that is no denial with authority says nothing about how the zone denies, and
// nor does one without EDNS0, which cannot have carried the DNSSEC records:
// a server that refused EDNS0 was asked again without it.
func listed(qname string) func(*dns.Msg, *trace.Probe) {
	return func(resp *dns.Msg, probe *trace.Probe) {
		if !resp.Authoritative || resp.UDPSize == 0 || resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			probe.State = trace.ProbeUnchecked
			return
		}
		probe.Denial = denial(resp, qname)
		if probe.Denial == trace.DenialNSEC {
			probe.State = trace.ProbeOpen
		}
	}
}

// denial is how resp proves qname missing. A signer working as it answers
// gives the name itself as an owner (RFC 9824) or the name just after it as
// the next one (RFC 4470); one real neighbour among them would still be read
// as made up, which is the side that claims less.
func denial(resp *dns.Msg, qname string) trace.Denial {
	found := trace.DenialNone
	for _, rr := range slices.Concat(resp.Answer, resp.Ns) {
		switch rr := rr.(type) {
		case *dns.NSEC:
			// The codec unpacks a zero octet escaped, though it packs one raw.
			next := rr.NextDomain
			if dns.EqualName(rr.Hdr.Name, qname) || dns.EqualName(next, `\000.`+qname) || dns.EqualName(next, "\x00."+qname) {
				return trace.DenialMadeUp
			}
			found = trace.DenialNSEC
		case *dns.NSEC3:
			if found == trace.DenialNone {
				found = trace.DenialNSEC3
			}
		}
	}
	return found
}

// recursed reads a reply to the root's NS set, asked of a server that does not
// serve the root, as a lookup done for us where it carries that set. It goes by
// what came back and not by RA, which servers set without recursing. An
// authoritative answer is a server holding a copy of the root, which is not a
// resolver.
func recursed(resp *dns.Msg, probe *trace.Probe) {
	if resp.Rcode != dns.RcodeSuccess || resp.Authoritative {
		return
	}
	for _, rr := range resp.Answer {
		if dns.RRToType(rr) == dns.TypeNS && dns.EqualName(rr.Header().Name, ".") {
			probe.State = trace.ProbeOpen
			return
		}
	}
}
