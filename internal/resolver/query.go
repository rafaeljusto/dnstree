package resolver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// query is one hop: a single question to a single server, including whatever it
// took to get a whole answer out of it.
func (r *run) query(ctx context.Context, zone string, server trace.Server, qname string, qtype uint16) *hop {
	// Glue carries addresses and never ports, so the transport says where to
	// knock, unless the server was named with a port of its own.
	port := server.Port
	server.Port = cmp.Or(port, r.cfg.Transport.Port())
	if r.cfg.Discovered != nil {
		r.cfg.Discovered(server.IP)
	}
	if r.cfg.Asking != nil {
		if done := r.cfg.Asking(zone, server); done != nil {
			defer done()
		}
	}
	step := &trace.Step{
		Zone:   zone,
		Server: server,
		Proto:  r.cfg.Transport.Proto(),
		Asked:  trace.Question{Name: qname, Type: dnsutil.TypeToString(qtype)},
		Start:  r.since(),
	}

	udpSize := r.cfg.UDPSize
	carrier := r.cfg.Transport
	resp, err := r.exchange(ctx, step, carrier, qname, qtype, udpSize, port)

	// A server that does not speak the transport asked for is the ordinary case
	// for DoT and DoH, so plain DNS can be allowed to pick the hop up.
	if err != nil && r.cfg.Fallback != nil {
		if retry, fallbackErr := r.exchange(ctx, step, r.cfg.Fallback, qname, qtype, udpSize, port); fallbackErr == nil {
			step.Notes = append(step.Notes, step.Proto+" did not get through, asked over "+r.cfg.Fallback.Proto())
			step.Proto = r.cfg.Fallback.Proto()
			step.Server.Port = cmp.Or(port, r.cfg.Fallback.Port())
			carrier = r.cfg.Fallback
			resp, err = retry, nil
		}
	}
	if err != nil {
		failed(ctx, step, err)
		return &hop{step: step}
	}

	// A server that cannot parse EDNS0 gets the question again without it.
	if udpSize > 0 && (resp.Rcode == dns.RcodeFormatError || resp.Rcode == dns.RcodeNotImplemented) {
		udpSize = 0
		if retry, err := r.exchange(ctx, step, r.cfg.Transport, qname, qtype, udpSize, port); err == nil {
			resp = retry
			step.Notes = append(step.Notes, "retried without EDNS0")
		}
	}

	// A server that insists on a cookie of its own hands one out with
	// BADCOOKIE, and is asked again with it (RFC 7873 section 5.3). Once: a
	// server that turns down its own cookie has nothing more to say.
	var cookieRetried bool
	if resp.Rcode == dns.RcodeBadCookie && r.cookie(step.Server.IP) != "" {
		if state, _ := transport.EchoedCookie(resp, r.clientCookie(step.Server.IP)); state == trace.CookieSupported {
			if retry, err := r.exchange(ctx, step, carrier, qname, qtype, udpSize, port); err == nil {
				resp, cookieRetried = retry, true
				step.Notes = append(step.Notes, "asked again with the server's cookie")
			}
		}
	}

	// An answer that did not fit has to be fetched again over TCP.
	if resp.Truncated && r.cfg.TCP != nil && step.Proto != r.cfg.TCP.Proto() {
		retry, retryErr := r.exchange(ctx, step, r.cfg.TCP, qname, qtype, udpSize, port)
		if retryErr != nil {
			step.Notes = append(step.Notes,
				"truncated over "+step.Proto+", and "+r.cfg.TCP.Proto()+" did not get through")
		} else {
			step.Notes = append(step.Notes, "truncated over "+step.Proto)
			step.Proto = r.cfg.TCP.Proto()
			resp = retry
		}
	}

	// What arrived, and what it had to fit in. The limit is the transport's
	// rather than the question's, so it belongs to whichever attempt the hop
	// kept: an answer refetched over TCP was bounded by nothing, whatever the
	// datagram that failed before it advertised.
	step.Size = len(resp.Data)
	if step.Proto == transport.ProtoUDP {
		step.Limit = int(cmp.Or(udpSize, dns.MinMsgSize))
	}

	// What is left of a truncated message is not what the server holds, and
	// reading it as one would turn a dropped section into a statement about
	// the zone: a missing answer into NODATA, a missing NS set into a lame
	// server. The hop says the answer could not be fetched whole instead.
	if resp.Truncated {
		step.Rcode = dnsutil.RcodeToString(resp.Rcode)
		step.Extended = transport.Extended(resp)
		step.Flags.TC = true
		step.Kind = trace.KindError
		step.Err = "the answer did not fit and could not be fetched whole"
		if r.cfg.TCP == nil {
			step.Err += "; no TCP transport to fetch it with"
		}
		r.warnIn(trace.AreaServers, step.Zone, "%s answered %s truncated, and the whole answer could not be fetched",
			step.Server.IP, qname)
		return &hop{step: step}
	}

	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	step.Extended = transport.Extended(resp)
	step.Subnet = transport.EchoedSubnet(resp)
	step.NSID = transport.EchoedNSID(resp)
	step.ReportTo = transport.ReportChannel(resp)
	if r.cfg.Cookie && udpSize > 0 && transport.CarriesCookie(step.Proto) {
		step.Cookie, _ = transport.EchoedCookie(resp, r.clientCookie(step.Server.IP))
		switch {
		case step.Cookie == trace.CookieSupported && resp.Rcode == dns.RcodeBadCookie && cookieRetried:
			step.Cookie = trace.CookieRejected
		case step.Cookie == trace.CookieMismatch:
			r.warnf("", "%s answered with a client cookie other than the one sent, so the answer may not be its own",
				step.Server.IP)
		}
	}
	step.Flags = trace.Flags{
		AA:   resp.Authoritative,
		TC:   resp.Truncated,
		AD:   resp.AuthenticatedData,
		DO:   resp.Security,
		EDNS: resp.UDPSize > 0,
	}
	step.Kind, step.Delegation = classify(resp, zone, qname, qtype, step.Extended)

	switch step.Kind {
	case trace.KindAnswer, trace.KindCNAME:
		step.Records = records(resp.Answer)
	case trace.KindNoData, trace.KindNXDomain:
		step.SOA = soa(resp.Ns)
	}
	return &hop{step: step, resp: resp}
}

// failed says on the step why a server could not be asked. A run interrupted
// or out of time is the run's doing, and never blamed on the server: a silence
// cut short by it was not the server's whole answer.
func failed(ctx context.Context, step *trace.Step, err error) {
	// An error can quote the server, a TLS one the names on its certificate.
	step.Kind, step.Err = trace.KindError, trace.Printable(err.Error(), trace.MaxErr)
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		step.Err = "interrupted before the server answered"
	case outOfTime(ctx):
		step.Err = "the walk ran out of time before the server answered"
	case transport.IsTimeout(err):
		step.Kind = trace.KindTimeout
	}
}

// outOfTime reports whether the run is past its deadline, or stopped. The
// deadline is read as well as the context: a read cut short by it can return
// before the context's own timer has marked it done.
func outOfTime(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return ctx.Err() != nil || ok && !time.Now().Before(deadline)
}

// exchange sends one message and adds what it cost to the step. A server that
// stays silent is asked again, since a lost datagram is not an answer.
//
// Shape, where it is given, changes the query before it is sent.
func (r *run) exchange(ctx context.Context, step *trace.Step, carrier transport.Transport, qname string, qtype uint16, udpSize, port uint16, shape ...func(*dns.Msg)) (*dns.Msg, error) {
	server := netip.AddrPortFrom(step.Server.IP, cmp.Or(port, carrier.Port()))

	var err error
	silences := -1 // the note that counts them, once there is one
	for attempt := 0; ; attempt++ {
		var req *dns.Msg
		if req, err = transport.NewQuery(qname, qtype, udpSize, r.cfg.DNSSEC); err != nil {
			return nil, err
		}
		transport.WithSubnet(req, r.cfg.Subnet)
		for _, change := range shape {
			change(req)
		}
		if r.cfg.NSID {
			transport.WithNSID(req)
		}
		cookie := r.cfg.Cookie && transport.CarriesCookie(carrier.Proto())
		if cookie {
			transport.WithCookie(req, r.clientCookie(server.Addr()), r.cookie(server.Addr()))
		}

		var (
			resp *dns.Msg
			rtt  time.Duration
		)
		resp, rtt, err = carrier.Exchange(ctx, req, server, step.Server.Name)
		step.RTT += rtt
		if cookie && err == nil {
			r.remember(server.Addr(), resp)
		}

		r.cfg.Log.Debug("asked a nameserver",
			"zone", step.Zone, "server", server, "proto", carrier.Proto(),
			"name", qname, "type", qtype, "rtt", rtt, "error", err)

		if err == nil || attempt >= r.cfg.Retries || !transport.IsTimeout(err) || outOfTime(ctx) {
			return resp, err
		}
		if silences < 0 {
			silences = len(step.Notes)
			step.Notes = append(step.Notes, "asked again after a silence")
		} else {
			step.Notes[silences] = fmt.Sprintf("asked again after %d silences", attempt+1)
		}
	}
}

// clientCookie is the client half of the cookie a server is sent.
func (r *run) clientCookie(server netip.Addr) string {
	return transport.ClientCookie(r.secret, server)
}

// cookie is the server cookie a server handed out, empty before it has.
func (r *run) cookie(server netip.Addr) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cookies[server]
}

// remember keeps the server cookie a reply handed out, so that the server is
// sent it next time. Only a reply to our own client cookie can hand one out.
func (r *run) remember(server netip.Addr, resp *dns.Msg) {
	state, cookie := transport.EchoedCookie(resp, r.clientCookie(server))
	if state != trace.CookieSupported {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cookies[server] = cookie
}

// askEach runs ask for every item side by side, no more than maxParallel
// at once, and returns when all of them have.
func askEach[T any](items []T, ask func(int, T)) {
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, item := range items {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			ask(i, item)
		})
	}
	wait.Wait()
}

// askAll is askEach for asks that each come back with one thing, kept in the
// order of items so that the tree stays the same between runs.
func askAll[T, R any](items []T, ask func(T) R) []R {
	out := make([]R, len(items))
	askEach(items, func(i int, item T) { out[i] = ask(item) })
	return out
}

// afford spends a query of the budget on each item, and is the items it could
// pay for, with why it stopped where it could not pay for them all.
func afford[T any](c *counters, items []T) ([]T, error) {
	for i := range items {
		if err := c.query(); err != nil {
			return items[:i], err
		}
	}
	return items, nil
}
