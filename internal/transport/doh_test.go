package transport_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/transport"
)

// TestDoHStatusIsNotTheServersWords covers a DoH server refusing with a status
// line of its own. The reason phrase is free text that ends up drawn as the
// hop's error, so only the code is kept.
func TestDoHStatusIsNotTheServersWords(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 503 x\x1b[2K\x1b[32m[secure]\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		_ = buf.Flush()
	}))
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	doh := transport.NewDoH(transport.Config{TLS: &tls.Config{RootCAs: roots}})

	address := netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "https://"))
	_, _, err := doh.Exchange(t.Context(), dns.NewMsg("example.com.", dns.TypeA), address, "")
	if err == nil {
		t.Fatal("got an answer, want the 503 refused")
	}
	if strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Errorf("got %q, want the code and its registered name only", err)
	}
}
