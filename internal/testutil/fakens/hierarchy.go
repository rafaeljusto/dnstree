package fakens

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// Hierarchy is a set of fake nameservers standing in for a delegation chain.
// Every server has a declared address, the one its parent hands out as glue,
// and a real loopback socket behind it. The transport maps one to the other, so
// the engine has to pick glue exactly as it would in the wild: a test that
// follows the wrong address reaches nothing.
type Hierarchy struct {
	tb      testing.TB
	servers []*Server
	real    map[netip.Addr][]*Server
}

// NewHierarchy returns an empty hierarchy.
func NewHierarchy(tb testing.TB) *Hierarchy {
	tb.Helper()
	return &Hierarchy{tb: tb, real: make(map[netip.Addr][]*Server)}
}

// Add starts one more nameserver. Its declared address must be set, and must be
// the one the zones above it use as glue. Several zones may share an address,
// the way a registry serves a ccTLD and its own domains from the same machines;
// the queries are then routed by name, as one server would answer them.
func (h *Hierarchy) Add(cfg Config) *Server {
	h.tb.Helper()

	if cfg.Declared == "" {
		h.tb.Fatalf("fakens: the %s server has no declared address", cfg.Origin)
	}
	server := New(h.tb, cfg)
	for _, sharing := range h.real[server.Declared] {
		if dns.EqualName(sharing.origin, server.origin) {
			h.tb.Fatalf("fakens: %s already serves %s", server.Declared, server.origin)
		}
	}
	h.real[server.Declared] = append(h.real[server.Declared], server)
	h.servers = append(h.servers, server)
	h.publishDS(server)
	return server
}

// publishDS hands the DS of every signed zone to the server of its parent, the
// way a registry would, whichever order the zones were added in. A zone set up
// with NoDS is left unvouched for, which is how a delegation goes insecure.
func (h *Hierarchy) publishDS(added *Server) {
	for _, child := range h.servers {
		if child.signer == nil || child.behaviour.NoDS {
			continue
		}
		parent := h.parentOf(child)
		if parent == nil || (parent != added && child != added) {
			continue
		}
		parent.publish(child.signer.ds())
	}
}

// parentOf is the server of the closest zone above this one.
func (h *Hierarchy) parentOf(child *Server) *Server {
	var parent *Server
	for _, candidate := range h.servers {
		switch {
		case candidate == child || dns.EqualName(candidate.origin, child.origin):
		case !dnsutil.IsBelow(candidate.origin, child.origin):
		case parent == nil || dnsutil.Labels(candidate.origin) > dnsutil.Labels(parent.origin):
			parent = candidate
		}
	}
	return parent
}

// Transport wraps inner so that queries sent to a declared address reach the
// server that stands behind it, on the socket that speaks the right protocol.
// Addresses it knows nothing about are left alone, and so fail the way an
// unreachable server would.
func (h *Hierarchy) Transport(inner transport.Transport) transport.Transport {
	return &hierarchyTransport{hierarchy: h, inner: inner}
}

type hierarchyTransport struct {
	hierarchy *Hierarchy
	inner     transport.Transport
}

func (t *hierarchyTransport) Proto() string { return t.inner.Proto() }

func (t *hierarchyTransport) Port() uint16 { return t.inner.Port() }

func (t *hierarchyTransport) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error) {
	if behind := t.hierarchy.serving(server.Addr(), req); behind != nil {
		server = behind.listenerFor(t.inner.Proto())
	}
	return t.inner.Exchange(ctx, req, server, name)
}

// serving picks which of the zones at one address answers a query, the way a
// server holding several of them would: the deepest zone at or above the name,
// except for a DS, which belongs to the parent side of the cut.
func (h *Hierarchy) serving(addr netip.Addr, req *dns.Msg) *Server {
	sharing := h.real[addr]
	if len(sharing) == 0 {
		return nil
	}
	qname, qtype := dnsutil.Question(req)

	var chosen *Server
	for _, candidate := range sharing {
		switch {
		case !dnsutil.IsBelow(candidate.origin, qname):
		case qtype == dns.TypeDS && dns.EqualName(candidate.origin, qname):
		case chosen == nil || dnsutil.Labels(candidate.origin) > dnsutil.Labels(chosen.origin):
			chosen = candidate
		}
	}
	if chosen == nil {
		chosen = sharing[0] // out of bailiwick, and refused by whoever answers
	}
	return chosen
}
