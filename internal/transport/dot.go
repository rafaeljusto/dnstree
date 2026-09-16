package transport

import (
	"context"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

// DoT is DNS over TLS: the same messages TCP carries, inside a TLS session on a
// port of its own. Authoritative servers rarely offer it, so a walk over DoT is
// a question about who does.
type DoT struct {
	Config
}

var _ Transport = (*DoT)(nil)

// NewDoT returns a DoT transport.
func NewDoT(cfg Config) *DoT { return &DoT{Config: cfg} }

// Proto implements [Transport].
func (d *DoT) Proto() string { return "dot" }

// Port implements [Transport].
func (d *DoT) Port() uint16 { return PortDoT }

// Exchange implements [Transport]. The name is what the certificate is checked
// against, so a server known only by address cannot be verified.
func (d *DoT) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error) {
	return exchange(ctx, "tcp", d.Config, d.tlsConfig(name, dns.NextProtos), req, server)
}
