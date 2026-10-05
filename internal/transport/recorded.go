package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/capture"
)

// Recorded is inner, except that every query it sends, and the answer to it,
// is handed to record: from as many goroutines as are querying. A query that
// got no answer worth reading, silence or otherwise, is handed over without
// one; a query that never left, because the connection could not be made or
// the run was over, is not handed over at all.
func Recorded(inner Transport, record func(capture.Exchange)) Transport {
	return &recorded{inner: inner, record: record}
}

type recorded struct {
	inner  Transport
	record func(capture.Exchange)
}

func (r *recorded) Proto() string { return r.inner.Proto() }

func (r *recorded) Port() uint16 { return r.inner.Port() }

func (r *recorded) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error) {
	// A copy of our own: over a stream the codec hands the query's buffer on to
	// the answer, and the exchange packs the query again into a fresh one,
	// with the same bytes.
	req.Data = nil
	if err := req.Pack(); err != nil {
		return r.inner.Exchange(ctx, req, server, name)
	}
	query := append([]byte(nil), req.Data...)

	sent := time.Now()
	resp, rtt, err := r.inner.Exchange(ctx, req, server, name)
	if err != nil && (neverConnected(err) || errors.Is(err, context.Canceled)) {
		return resp, rtt, err
	}
	exchange := capture.Exchange{Proto: r.inner.Proto(), Server: server, Sent: sent, Took: rtt, Query: query}
	if resp != nil {
		exchange.Answer = append([]byte(nil), resp.Data...)
	}
	r.record(exchange)
	return resp, rtt, err
}

// neverConnected reports whether err is a connection that was never made, which sent
// nothing to record.
func neverConnected(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}
