package transport

import (
	"context"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

// UDP is the default transport: one datagram out, one back, and a truncated
// answer when it does not fit.
type UDP struct {
	Config
}

var _ Transport = (*UDP)(nil)

// NewUDP returns a UDP transport.
func NewUDP(cfg Config) *UDP { return &UDP{Config: cfg} }

// Proto implements [Transport].
func (u *UDP) Proto() string { return "udp" }

// Port implements [Transport].
func (u *UDP) Port() uint16 { return u.port(PortDNS) }

// Exchange implements [Transport].
func (u *UDP) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, _ string) (*dns.Msg, time.Duration, error) {
	return exchange(ctx, "udp", u.Config, nil, req, server)
}
