package fakens

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
	"codeberg.org/miekg/dns/dnstest"
)

// ClientTLS trusts this server and nothing else. The certificate is the
// library's test one, which is self-signed and long expired, so a client has to
// be told to accept it.
func (s *Server) ClientTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// listenerFor is where this server answers a given protocol. A server that was
// not set up for one hands back its plain socket, where the handshake goes
// unanswered. A real nameserver would refuse the connection instead; either
// way the hop does not get through.
func (s *Server) listenerFor(proto string) netip.AddrPort {
	switch proto {
	case "dot":
		if s.TLSAddr.IsValid() {
			return s.TLSAddr
		}
	case "doh":
		if s.DoHAddr.IsValid() {
			return s.DoHAddr
		}
	}
	return s.Addr
}

// listenTLS starts a DNS over TLS listener on a port of its own.
func (s *Server) listenTLS(tb testing.TB, host string) {
	tb.Helper()

	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		tb.Fatalf("fakens: listening for TLS on %s: %v", host, err)
	}
	s.TLSAddr = netip.MustParseAddrPort(listener.Addr().String())

	config := dnstest.TLSConfig()
	config.NextProtos = dns.NextProtos
	cancel, _, err := dnstest.Server("", func(server *dns.Server) {
		server.Listener = tls.NewListener(listener, config)
		server.Handler = s
		server.MsgInvalidFunc = func(*dns.Msg, error) {}
	})
	if err != nil {
		tb.Fatalf("fakens: starting the TLS server for %s: %v", s.origin, err)
	}
	tb.Cleanup(cancel)
}

// listenDoH starts a DNS over HTTPS server, which is the same zone behind an
// HTTP handler.
func (s *Server) listenDoH(tb testing.TB, host string) {
	tb.Helper()

	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		tb.Fatalf("fakens: listening for HTTPS on %s: %v", host, err)
	}
	s.DoHAddr = netip.MustParseAddrPort(listener.Addr().String())

	config := dnstest.TLSConfig()
	config.NextProtos = dnshttp.NextProtos

	mux := http.NewServeMux()
	mux.Handle(dnshttp.Path, s)
	server := &http.Server{Handler: mux, ReadTimeout: 5 * time.Second, TLSConfig: config}

	go server.Serve(tls.NewListener(listener, config))
	tb.Cleanup(func() { server.Shutdown(context.Background()) })
}
