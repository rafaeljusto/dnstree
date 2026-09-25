package transport_test

import (
	"crypto/tls"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// TestEncrypted covers DoT and DoH against a server offering both. They differ
// in everything but the message they carry, so they are asked the same things.
func TestEncrypted(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "example.com.", Zone: zone, TLS: true, DoH: true})
	config := transport.Config{Timeout: fastConfig.Timeout, TLS: server.ClientTLS()}

	tests := map[string]struct {
		carrier transport.Transport
		addr    netip.AddrPort
		port    uint16
	}{
		"dot": {carrier: transport.NewDoT(config), addr: server.TLSAddr, port: transport.PortDoT},
		"doh": {carrier: transport.NewDoH(config), addr: server.DoHAddr, port: transport.PortDoH},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := test.carrier.Proto(); got != name {
				t.Errorf("got proto %q, want %q", got, name)
			}
			if got := test.carrier.Port(); got != test.port {
				t.Errorf("got port %d, want %d", got, test.port)
			}

			resp, rtt, err := test.carrier.Exchange(t.Context(),
				query(t, "www.example.com.", dns.TypeA), test.addr, "ns1.example.com.")
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("got rcode %d, want NOERROR", resp.Rcode)
			}
			if !resp.Authoritative {
				t.Error("got no AA bit, want one")
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want 1", len(resp.Answer))
			}
			if rtt <= 0 {
				t.Errorf("got rtt %v, want a positive duration", rtt)
			}
		})
	}
}

// TestEncryptedRejectsUnknownCertificate covers the point of the encrypted
// transports: a server that cannot prove who it is does not get the question.
func TestEncryptedRejectsUnknownCertificate(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "example.com.", Zone: zone, TLS: true, DoH: true})
	config := transport.Config{Timeout: fastConfig.Timeout, TLS: &tls.Config{}}

	tests := map[string]struct {
		carrier transport.Transport
		addr    netip.AddrPort
	}{
		"dot": {carrier: transport.NewDoT(config), addr: server.TLSAddr},
		"doh": {carrier: transport.NewDoH(config), addr: server.DoHAddr},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := test.carrier.Exchange(t.Context(),
				query(t, "www.example.com.", dns.TypeA), test.addr, "ns1.example.com.")
			if err == nil {
				t.Fatal("got no error from a certificate nothing vouches for, want one")
			}
		})
	}
}

// TestEncryptedAgainstPlainServer covers what a walk over DoT or DoH usually
// meets: a nameserver that only speaks DNS.
func TestEncryptedAgainstPlainServer(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "example.com.", Zone: zone})
	config := transport.Config{Timeout: fastConfig.Timeout, TLS: server.ClientTLS()}

	for name, carrier := range map[string]transport.Transport{
		"dot": transport.NewDoT(config),
		"doh": transport.NewDoH(config),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := carrier.Exchange(t.Context(),
				query(t, "www.example.com.", dns.TypeA), server.Addr, "ns1.example.com.")
			if err == nil {
				t.Error("got no error talking TLS to a plain nameserver, want one")
			}
		})
	}
}

func TestEncryptedBadServer(t *testing.T) {
	config := transport.Config{Timeout: fastConfig.Timeout}

	for name, carrier := range map[string]transport.Transport{
		"dot": transport.NewDoT(config),
		"doh": transport.NewDoH(config),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := carrier.Exchange(t.Context(),
				query(t, "www.example.com.", dns.TypeA), netip.AddrPort{}, ""); err == nil {
				t.Error("got no error, want one")
			}
		})
	}
}
