package transport

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

// ErrNotAllowed is what a guarded transport answers for an address it will not
// send to.
var ErrNotAllowed = errors.New("not asked")

// Guard is inner, except that it only sends to the addresses allow lets
// through. Glue is whatever a zone says it is, so a walk run on somebody
// else's behalf can be pointed at the network it runs on; guarded, it records
// the hop as refused and moves on.
func Guard(inner Transport, allow func(netip.Addr) bool) Transport {
	return &guarded{inner: inner, allow: allow}
}

type guarded struct {
	inner Transport
	allow func(netip.Addr) bool
}

func (g *guarded) Proto() string { return g.inner.Proto() }

func (g *guarded) Port() uint16 { return g.inner.Port() }

func (g *guarded) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error) {
	if !g.allow(server.Addr().Unmap()) {
		return nil, 0, fmt.Errorf("%w: %s is not a public address", ErrNotAllowed, server.Addr().Unmap())
	}
	return g.inner.Exchange(ctx, req, server, name)
}

// notPublic are the ranges that reach no nameserver on the internet: this
// network, somebody's private one, the provider's, or nothing at all.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), // the 6to4 relays, retired
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),           // IPv4-compatible, retired but still routed by some hosts
	netip.MustParsePrefix("::ffff:0:0:0/96"), // SIIT carries an IPv4 address of any kind
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 reaches IPv4 of any kind
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"), // Teredo carries one too
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4 carries an IPv4 address of any kind
	netip.MustParsePrefix("fec0::/10"), // site-local, retired
}

// Public reports whether addr is one a nameserver on the internet could have.
func Public(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range notPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
