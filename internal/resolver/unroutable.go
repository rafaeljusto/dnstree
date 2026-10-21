package resolver

import (
	"net/netip"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// unroutable is what each kind of address transport.Unroutable names means
// for a nameserver handed out at one. The shared space alone is not said to be
// out of everyone's reach, since the carrier's own customers reach it.
var unroutable = map[string]string{
	"private":       "a private address no resolver on the internet can reach, usually a record from an internal view of the zone",
	"loopback":      "a loopback address, which every resolver takes for itself, usually a placeholder never replaced",
	"link-local":    "a link-local address no resolver on the internet can reach",
	"shared":        "an address in the space carriers number their own customers from (RFC 6598), which resolvers outside that carrier cannot reach",
	"documentation": "an address kept for documentation that no resolver on the internet can reach, usually an example never replaced",
	"benchmarking":  "an address kept for benchmarks that no resolver on the internet can reach",
	"reserved":      "a reserved address no resolver on the internet can reach",
}

// checkReach warns when from, the zone that said so, gives a nameserver of
// zone an address nobody on the internet can reach it at, and remembers the
// address so that the hops sent to it say why they went unanswered. A walk
// that started anywhere but public roots is a lab, built of such addresses on
// purpose, and is left alone.
func (r *run) checkReach(zone, from, name string, addr netip.Addr, fix string) {
	if !r.internet {
		return
	}
	kind := transport.Unroutable(addr)
	if kind == "" {
		return
	}
	r.warnOnceIn(trace.AreaDelegation, zone, "%s gives %s for %s, %s; %s", from, addr, name, unroutable[kind], fix)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unreached == nil {
		r.unreached = make(map[netip.Addr]string)
	}
	r.unreached[addr] = kind + " address"
}

// markReach notes on a hop that it was sent to an address checkReach warned
// about.
func (r *run) markReach(step *trace.Step) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if note, ok := r.unreached[step.Server.IP]; ok {
		step.Notes = append(step.Notes, note)
	}
}
