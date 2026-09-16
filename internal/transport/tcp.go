package transport

import (
	"context"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

// TCP is the fallback for truncated answers, and the only way to move a large
// RRset such as a signed DNSKEY set.
type TCP struct {
	Config
}

var _ Transport = (*TCP)(nil)

// NewTCP returns a TCP transport.
func NewTCP(cfg Config) *TCP { return &TCP{Config: cfg} }

// Proto implements [Transport].
func (t *TCP) Proto() string { return "tcp" }

// Exchange implements [Transport].
func (t *TCP) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, _ string) (*dns.Msg, time.Duration, error) {
	return exchange(ctx, "tcp", t.Config, req, server)
}
