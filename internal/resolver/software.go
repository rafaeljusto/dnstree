package resolver

import (
	"context"
	"net/netip"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// asking is one server --software asks, over the transport its hops got
// through on, and what it has said so far.
type asking struct {
	zone    string
	server  trace.Server
	carrier transport.Transport
	said    *trace.Software
	refused bool // answered the first name with nothing, and gets the second
}

// software asks every server that answered a hop of the run which software it
// runs, under each of transport.VersionNames until one gets an answer, and
// writes what it said on every hop sent to it. The servers are asked side by
// side; the budget is spent, and the hops written, from the goroutine doing
// the walking.
func (r *run) software(ctx context.Context) {
	if !r.cfg.Software {
		return
	}

	var servers []*asking
	seen := map[netip.AddrPort]bool{}
	for step := range r.trace.Steps() {
		key := netip.AddrPortFrom(step.Server.IP, step.Server.Port)
		if step.Rcode == "" || seen[key] {
			continue
		}
		seen[key] = true
		carrier := r.cfg.Transport
		if r.cfg.Fallback != nil && step.Proto == r.cfg.Fallback.Proto() && step.Proto != carrier.Proto() {
			carrier = r.cfg.Fallback
		}
		servers = append(servers, &asking{zone: step.Zone, server: step.Server, carrier: carrier})
	}

	for _, name := range transport.VersionNames {
		var ask []*asking
		for _, a := range servers {
			if name == transport.VersionNames[0] || a.refused {
				ask = append(ask, a)
			}
		}
		ask, budget := afford(r.counters, ask)
		askEach(ask, func(_ int, a *asking) { r.askSoftware(ctx, a, name) })
		if budget != nil {
			r.warnf(trace.AreaServers, "the budget ran out before every server could be asked which software it runs; raise --max-queries to ask them all")
			break
		}
	}

	said := map[netip.AddrPort]*trace.Software{}
	for _, a := range servers {
		if a.said != nil {
			said[netip.AddrPortFrom(a.server.IP, a.server.Port)] = a.said
		}
	}
	for step := range r.trace.Steps() {
		step.Server.Software = said[netip.AddrPortFrom(step.Server.IP, step.Server.Port)]
	}
}

// askSoftware puts one of transport.VersionNames to a server. Any answer at
// all is the server's word, an empty one included; only silence or an error
// leaves it unsaid.
func (r *run) askSoftware(ctx context.Context, a *asking, name string) {
	if r.cfg.Asking != nil {
		if done := r.cfg.Asking(a.zone, a.server); done != nil {
			defer done()
		}
	}
	step := &trace.Step{Zone: a.zone, Server: a.server}
	resp, err := r.exchange(ctx, step, a.carrier, name, dns.TypeTXT, r.cfg.UDPSize, a.server.Port, transport.Chaos)
	if err != nil {
		return
	}
	version, ok := transport.SaidVersion(resp)
	a.said, a.refused = &trace.Software{Version: version}, !ok
}
