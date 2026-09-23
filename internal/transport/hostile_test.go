package transport_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/transport"
)

// datagrams is a UDP server that answers the first query it gets with every
// reply write makes of it, in order.
func datagrams(t *testing.T, write func(req *dns.Msg) []*dns.Msg) netip.AddrPort {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, dns.MaxMsgSize)
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req := &dns.Msg{Data: buf[:n]}
		if req.Unpack() != nil {
			return
		}
		for _, reply := range write(req) {
			if reply.Pack() == nil {
				_, _ = conn.WriteTo(reply.Data, from)
			}
		}
	}()
	return netip.MustParseAddrPort(conn.LocalAddr().String())
}

func reply(req *dns.Msg, records ...string) *dns.Msg {
	resp := dnsutil.SetReply(new(dns.Msg), req)
	resp.Authoritative = true
	for _, text := range records {
		rr, err := dns.New(text)
		if err != nil {
			panic(err)
		}
		resp.Answer = append(resp.Answer, rr)
	}
	return resp
}

// TestSpoofedDatagramsAreSkipped covers a spoofer who guessed the port but not
// the query: a reply with the wrong ID and one to another question arrive
// first. Both are dropped and the real answer, arriving after them, is read.
func TestSpoofedDatagramsAreSkipped(t *testing.T) {
	server := datagrams(t, func(req *dns.Msg) []*dns.Msg {
		wrongID := reply(req, "www.example.com. 60 IN A 192.0.2.66")
		wrongID.ID++
		elsewhere := reply(dns.NewMsg("elsewhere.test.", dns.TypeA), "elsewhere.test. 60 IN A 192.0.2.66")
		elsewhere.ID, elsewhere.Response = req.ID, true
		return []*dns.Msg{wrongID, elsewhere, reply(req, "www.example.com. 60 IN A 192.0.2.1")}
	})

	resp, _, err := transport.NewUDP(transport.Config{Timeout: 2 * time.Second}).
		Exchange(t.Context(), dns.NewMsg("www.example.com.", dns.TypeA), server, "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(resp.Answer) != 1 || !strings.Contains(resp.Answer[0].String(), "192.0.2.1") {
		t.Errorf("got %v, want the real answer", resp.Answer)
	}
}

// TestOnlySpoofedDatagrams covers a hop where nothing but the spoofer spoke:
// it ends the way silence does, and says what was dropped.
func TestOnlySpoofedDatagrams(t *testing.T) {
	server := datagrams(t, func(req *dns.Msg) []*dns.Msg {
		wrongID := reply(req, "www.example.com. 60 IN A 192.0.2.66")
		wrongID.ID++
		return []*dns.Msg{wrongID}
	})

	_, _, err := transport.NewUDP(transport.Config{Timeout: 200 * time.Millisecond}).
		Exchange(t.Context(), dns.NewMsg("www.example.com.", dns.TypeA), server, "")
	if !transport.IsTimeout(err) || !strings.Contains(err.Error(), "another query") {
		t.Errorf("got %v, want a timeout that mentions the datagram dropped", err)
	}
}

// TestOtherClassesAreDropped covers records of a class nobody asked about. The
// walk reads no class, so a CHAOS record left in would pass for an answer.
func TestOtherClassesAreDropped(t *testing.T) {
	server := datagrams(t, func(req *dns.Msg) []*dns.Msg {
		return []*dns.Msg{reply(req, "www.example.com. 60 CH A 192.0.2.66")}
	})

	resp, _, err := transport.NewUDP(transport.Config{Timeout: 2 * time.Second}).
		Exchange(t.Context(), dns.NewMsg("www.example.com.", dns.TypeA), server, "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("got %v, want the CHAOS record dropped", resp.Answer)
	}
}

// TestBareFormErr covers the servers that answer FORMERR with no question at
// all. There is nothing in such a reply to mislead with, and the EDNS0
// fallback depends on reading it.
func TestBareFormErr(t *testing.T) {
	server := datagrams(t, func(req *dns.Msg) []*dns.Msg {
		resp := reply(req)
		resp.Rcode, resp.Question = dns.RcodeFormatError, nil
		return []*dns.Msg{resp}
	})

	resp, _, err := transport.NewUDP(transport.Config{Timeout: 2 * time.Second}).
		Exchange(t.Context(), dns.NewMsg("www.example.com.", dns.TypeA), server, "")
	if err != nil || resp.Rcode != dns.RcodeFormatError {
		t.Errorf("got %v, %v, want the FORMERR read", resp, err)
	}
}

// TestCancelInterruptsTheRead covers Ctrl-C with a query in flight. The read
// is cut short there and then, and says it was cancelled rather than blaming
// the server with a timeout.
func TestCancelInterruptsTheRead(t *testing.T) {
	server := datagrams(t, func(*dns.Msg) []*dns.Msg { return nil })

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)

	started := time.Now()
	_, _, err := transport.NewUDP(transport.Config{Timeout: 5 * time.Second}).
		Exchange(ctx, dns.NewMsg("www.example.com.", dns.TypeA), server, "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want the cancellation", err)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Errorf("took %s, want the read interrupted", took)
	}
}

// TestDoHReplyMustBeTheReply covers what a DoH server can send besides the
// reply: a page, a redirect, or a reply to another question. The ID is zero
// both ways over HTTPS, so none of it can be caught any other way.
func TestDoHReplyMustBeTheReply(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"a page instead of a message": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(packed(t, "www.example.com."))
		},
		// Followed, the redirect would find a sound reply waiting.
		"a redirect somewhere else": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/moved" {
				http.Redirect(w, r, "/moved", http.StatusTemporaryRedirect)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(packed(t, "www.example.com."))
		},
		"a reply to another question": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(packed(t, "elsewhere.test."))
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()

			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			doh := transport.NewDoH(transport.Config{TLS: &tls.Config{RootCAs: roots}})

			address := netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "https://"))
			if resp, _, err := doh.Exchange(t.Context(), dns.NewMsg("www.example.com.", dns.TypeA), address, ""); err == nil {
				t.Errorf("got %v, want it refused", resp)
			}
		})
	}
}

// packed is an answer for owner, packed the way a DoH body carries it.
func packed(t *testing.T, owner string) []byte {
	t.Helper()
	resp := reply(dns.NewMsg(owner, dns.TypeA), owner+" 60 IN A 192.0.2.66")
	resp.Response = true
	if err := resp.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return resp.Data
}
