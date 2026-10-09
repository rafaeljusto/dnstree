package resolver

import (
	"cmp"
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// ednsFlag and ednsOption are what RFC 8906 sends as the flag and the option
// nobody has defined: sections 8.2.4 and 8.2.3, as dig's +ednsflags=0x40 and
// +ednsopt=100 put them.
const (
	ednsFlag   = 0x40
	ednsOption = 100
)

// checkEDNS puts the questions of RFC 8906 to every nameserver of the zone the
// walk ended in. Every server is asked the baseline first, and only one that
// passed it is asked the rest: a server that cannot answer EDNS0, or does not
// serve the zone, would fail them all for the same reason. The servers are
// asked side by side and join the trace afterwards, from the goroutine doing
// the walking.
func (r *run) checkEDNS(ctx context.Context, answer *trace.Step, zone string, servers []trace.Server) {
	if !r.cfg.CheckEDNS {
		return
	}

	var (
		asked  []trace.Server
		budget error
	)
	for _, server := range dedupe(servers) {
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			continue
		}
		if budget = r.counters.query(); budget != nil {
			break
		}
		asked = append(asked, server)
	}
	steps := make([][]*trace.Step, len(asked))
	askEach(asked, func(i int, server trace.Server) {
		steps[i] = []*trace.Step{r.askEDNS(ctx, zone, server, trace.EDNSPlain)}
	})

	// The rest cost three queries a server, spent whole or not at all.
	var passed []int
	for i, hops := range steps {
		if budget != nil || hops[0].EDNS.State != trace.EDNSOK {
			continue
		}
		for range 3 {
			if budget = r.counters.query(); budget != nil {
				break
			}
		}
		if budget == nil {
			passed = append(passed, i)
		}
	}
	askEach(passed, func(_ int, i int) {
		for _, kind := range []trace.EDNSKind{trace.EDNSVersion, trace.EDNSOption, trace.EDNSFlag} {
			step := r.askEDNS(ctx, zone, asked[i], kind)
			if step.Kind == trace.KindTimeout {
				// The baseline got through, so silence here is the answer.
				step.EDNS.State, step.EDNS.Fault = trace.EDNSBroken, trace.EDNSSilent
			}
			steps[i] = append(steps[i], step)
		}
	})

	for _, hops := range steps {
		for _, step := range hops {
			r.attach(answer, step)
		}
	}
	if budget != nil {
		r.warnf(trace.AreaEDNS, "the budget ran out before every nameserver of %s could be checked for how it handles edns; raise --max-queries to check them all", zone)
	}
}

// askEDNS asks one server for the zone's SOA in one of the shapes checkEDNS
// tests, and reads the reply against RFC 8906. It never asks again without
// EDNS0, which would hide the very thing being tested.
func (r *run) askEDNS(ctx context.Context, zone string, server trace.Server, kind trace.EDNSKind) *trace.Step {
	carrier := r.cfg.Transport
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
		Asked:  trace.Question{Name: zone, Type: "SOA"},
		Start:  r.since(),
		Aside:  true,
		EDNS:   &trace.EDNSTest{Kind: kind, State: trace.EDNSUnchecked},
	}
	shape := func(req *dns.Msg) {
		switch kind {
		case trace.EDNSVersion:
			req.Version = 1
		case trace.EDNSOption:
			req.Pseudo = append(req.Pseudo, &dns.ERFC3597{EDNS0Code: ednsOption})
		case trace.EDNSFlag:
			req.Z = ednsFlag
		}
	}

	udpSize := r.cfg.UDPSize
	resp, err := r.exchange(ctx, step, carrier, zone, dns.TypeSOA, udpSize, port, shape)
	if err != nil && r.cfg.Fallback != nil {
		if retry, fallbackErr := r.exchange(ctx, step, r.cfg.Fallback, zone, dns.TypeSOA, udpSize, port, shape); fallbackErr == nil {
			step.Notes = append(step.Notes, carrier.Proto()+" did not get through, asked over "+r.cfg.Fallback.Proto())
			carrier = r.cfg.Fallback
			step.Proto = carrier.Proto()
			step.Server.Port = cmp.Or(port, carrier.Port())
			resp, err = retry, nil
		}
	}
	if err == nil && resp.Truncated && r.cfg.TCP != nil && carrier.Proto() != r.cfg.TCP.Proto() {
		if retry, retryErr := r.exchange(ctx, step, r.cfg.TCP, zone, dns.TypeSOA, udpSize, port, shape); retryErr == nil {
			resp = retry
			step.Proto = r.cfg.TCP.Proto()
			step.Notes = append(step.Notes, "truncated over "+carrier.Proto())
		}
	}
	switch {
	case err != nil:
		failed(ctx, step, err)
		return step
	case resp.Truncated:
		// What a truncated reply leaves out is no fault of the server's.
		step.Kind, step.Err = trace.KindError, "the answer did not fit and could not be fetched whole"
		return step
	}

	step.Kind = trace.KindAnswer
	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	if resp.Rcode == dns.RcodeBadVers {
		step.Rcode = "BADVERS" // the library names 16 after TSIG's BADSIG
	}
	step.Size = len(resp.Data)
	step.Flags = trace.Flags{AA: resp.Authoritative, EDNS: resp.UDPSize > 0}
	step.EDNS.State, step.EDNS.Fault = trace.EDNSOK, ednsFault(resp, zone, kind)
	if step.EDNS.Fault == "" {
		return step
	}
	// A baseline refused, or answered without the SOA, is a server that does
	// not serve the zone (RFC 8906 8.1.1), which says nothing about EDNS. Only
	// FORMERR and NOTIMP are a server that cannot parse it.
	lame := step.EDNS.Fault == trace.EDNSNoSOA ||
		step.EDNS.Fault == trace.EDNSRcode && resp.Rcode != dns.RcodeFormatError && resp.Rcode != dns.RcodeNotImplemented
	if kind == trace.EDNSPlain && lame {
		step.EDNS.State, step.EDNS.Fault = trace.EDNSUnchecked, ""
		step.Notes = append(step.Notes, "does not serve the zone")
		return step
	}
	step.EDNS.State = trace.EDNSBroken
	return step
}

// ednsFault is what a reply got wrong against what RFC 8906 section 8 expects
// of it, empty when nothing. Every shape is answered with an OPT record of
// version 0; an unknown version is BADVERS without the answer (RFC 6891
// 6.1.3), and everything else NOERROR with the SOA, the unknown option or flag
// ignored rather than copied back.
func ednsFault(resp *dns.Msg, zone string, kind trace.EDNSKind) trace.EDNSFault {
	want := dns.RcodeSuccess
	if kind == trace.EDNSVersion {
		want = dns.RcodeBadVers
	}
	switch {
	case int(resp.Rcode) != want:
		return trace.EDNSRcode
	case resp.UDPSize == 0:
		return trace.EDNSNoOPT
	case resp.Version != 0:
		return trace.EDNSBadVers
	}

	carries := false
	for _, rr := range resp.Answer {
		if dns.RRToType(rr) == dns.TypeSOA && dns.EqualName(rr.Header().Name, zone) {
			carries = true
		}
	}
	switch kind {
	case trace.EDNSVersion:
		if carries {
			return trace.EDNSAnswer
		}
		return ""
	case trace.EDNSFlag:
		if resp.Z&ednsFlag != 0 {
			return trace.EDNSEchoed
		}
	case trace.EDNSOption:
		for _, rr := range resp.Pseudo {
			if unknown, ok := rr.(*dns.ERFC3597); ok && unknown.EDNS0Code == ednsOption {
				return trace.EDNSEchoed
			}
		}
	}
	if !carries {
		return trace.EDNSNoSOA
	}
	return ""
}
