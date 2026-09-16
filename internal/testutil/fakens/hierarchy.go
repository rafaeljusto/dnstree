package fakens

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/transport"
)

// Hierarchy is a set of fake nameservers standing in for a delegation chain.
// Every server has a declared address, the one its parent hands out as glue,
// and a real loopback socket behind it. The transport maps one to the other, so
// the engine has to pick glue exactly as it would in the wild: a test that
// follows the wrong address reaches nothing.
type Hierarchy struct {
	tb      testing.TB
	servers []*Server
	real    map[netip.Addr]*Server
}

// NewHierarchy returns an empty hierarchy.
func NewHierarchy(tb testing.TB) *Hierarchy {
	tb.Helper()
	return &Hierarchy{tb: tb, real: make(map[netip.Addr]*Server)}
}

// Add starts one more nameserver. Its declared address must be set, and must be
// the one the zones above it use as glue.
func (h *Hierarchy) Add(cfg Config) *Server {
	h.tb.Helper()

	if cfg.Declared == "" {
		h.tb.Fatalf("fakens: the %s server has no declared address", cfg.Origin)
	}
	server := New(h.tb, cfg)
	if _, taken := h.real[server.Declared]; taken {
		h.tb.Fatalf("fakens: %s is already declared by another server", server.Declared)
	}
	h.real[server.Declared] = server
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
	if real, known := t.hierarchy.real[server.Addr()]; known {
		server = real.listenerFor(t.inner.Proto())
	}
	return t.inner.Exchange(ctx, req, server, name)
}
