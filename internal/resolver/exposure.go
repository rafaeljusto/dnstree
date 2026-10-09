package resolver

import (
	"cmp"
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// checkExposure asks every nameserver of the zone the walk ended in for what it
// should keep from strangers: the whole zone, and a lookup of somebody else's
// name. Like checkSerial the questions go out together and join the trace
// afterwards, from the goroutine doing the walking.
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
		if r.cfg.CheckRecursion {
			probes = append(probes, probe{server, trace.ProbeRecursion})
		}
	}

	probes, budget := afford(r.counters, probes)
	steps := askAll(probes, func(p probe) *trace.Step {
		if p.kind == trace.ProbeTransfer {
			return r.probe(ctx, zone, p.server, transfer, zone, dns.TypeAXFR, p.kind, false, transferred)
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

// probe asks one server one of the questions checkExposure puts, and reads the
// answer with open. Whatever came back is dropped once it has been read: the
// zone a server should not have handed over is not ours to keep or draw.
func (r *run) probe(ctx context.Context, zone string, server trace.Server, carrier transport.Transport,
	qname string, qtype uint16, kind trace.ProbeKind, recurse bool, open func(*dns.Msg, string) bool) *trace.Step {

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
	desire := func(req *dns.Msg) { req.RecursionDesired = recurse }

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
	if open(resp, zone) {
		step.Probe.State = trace.ProbeOpen
	}
	return step
}

// transferred reports whether a reply to an AXFR is the zone: a transfer opens
// with the zone's own SOA (RFC 5936 2.2). A refusal, or anything else, is not.
func transferred(resp *dns.Msg, zone string) bool {
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return false
	}
	first := resp.Answer[0]
	return dns.RRToType(first) == dns.TypeSOA && dns.EqualName(first.Header().Name, zone)
}

// recursed reports whether a reply to the root's NS set, asked of a server
// that does not serve the root, is a lookup done for us. It goes by what came
// back and not by RA, which servers set without recursing. An authoritative
// answer is a server holding a copy of the root, which is not a resolver.
func recursed(resp *dns.Msg, _ string) bool {
	if resp.Rcode != dns.RcodeSuccess || resp.Authoritative {
		return false
	}
	for _, rr := range resp.Answer {
		if dns.RRToType(rr) == dns.TypeNS && dns.EqualName(rr.Header().Name, ".") {
			return true
		}
	}
	return false
}
