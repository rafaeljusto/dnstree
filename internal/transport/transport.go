// Package transport carries a single DNS message to one server over UDP, TCP,
// DoT or DoH, and measures the round trip.
package transport

import (
	"context"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

// Transport exchanges messages with one server. Implementations are
// stateless with respect to the resolution: retries, truncation handling and
// EDNS fallback are the resolver's business.
type Transport interface {
	// Proto names the transport as it appears in the trace: udp, tcp, dot or doh.
	Proto() string

	// Exchange sends req to server and returns the response and the measured
	// round trip time. name is the server's DNS name when known, used for TLS
	// verification by the encrypted transports.
	Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error)
}
