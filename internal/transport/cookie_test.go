package transport_test

import (
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// TestClientCookie covers what RFC 9018 asks of the client half: the same for
// one server all run long, and different for every other.
func TestClientCookie(t *testing.T) {
	secret := []byte("0123456789abcdef")
	one, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

	cookie := transport.ClientCookie(secret, one)
	if len(cookie) != 16 {
		t.Errorf("got %q, want eight bytes of hex", cookie)
	}
	if again := transport.ClientCookie(secret, one); again != cookie {
		t.Errorf("got %q then %q, want one server sent one cookie", cookie, again)
	}
	if elsewhere := transport.ClientCookie(secret, other); elsewhere == cookie {
		t.Errorf("got %q for both, want each server its own", cookie)
	}
	if mapped := transport.ClientCookie(secret, netip.MustParseAddr("::ffff:192.0.2.1")); mapped != cookie {
		t.Errorf("got %q for the mapped address, want %q", mapped, cookie)
	}
}

// TestWithCookie covers both halves going out, and the query that has nowhere
// to carry an option.
func TestWithCookie(t *testing.T) {
	for name, tt := range map[string]struct {
		udpSize uint16
		server  string
		want    string
	}{
		"a first query carries the client cookie alone": {
			udpSize: transport.DefaultUDPSize, want: "0102030405060708",
		},
		"a later one carries the server cookie behind it": {
			udpSize: transport.DefaultUDPSize, server: "a1a2a3a4a5a6a7a8", want: "0102030405060708a1a2a3a4a5a6a7a8",
		},
		"a query without EDNS0 carries none": {},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := transport.NewQuery("www.test.", dns.TypeA, tt.udpSize, false)
			if err != nil {
				t.Fatalf("NewQuery: %v", err)
			}
			transport.WithCookie(req, "0102030405060708", tt.server)

			var got string
			for _, rr := range req.Pseudo {
				if cookie, ok := rr.(*dns.COOKIE); ok {
					got = cookie.Cookie
				}
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEchoedCookie covers what a server may send back. The codec takes a
// cookie of any length, so every length RFC 7873 rules out is ruled out here.
func TestEchoedCookie(t *testing.T) {
	const client = "0102030405060708"
	for name, tt := range map[string]struct {
		given  []dns.RR
		want   trace.CookieState
		server string
	}{
		"our client cookie and a server cookie": {
			given: []dns.RR{&dns.COOKIE{Cookie: client + "a1a2a3a4a5a6a7a8"}},
			want:  trace.CookieSupported, server: "a1a2a3a4a5a6a7a8",
		},
		"the longest server cookie there is": {
			given: []dns.RR{&dns.COOKIE{Cookie: client + strings.Repeat("ab", 32)}},
			want:  trace.CookieSupported, server: strings.Repeat("ab", 32),
		},
		"no cookie at all": {
			given: []dns.RR{&dns.NSID{}}, want: trace.CookieAbsent,
		},
		"somebody else's client cookie": {
			given: []dns.RR{&dns.COOKIE{Cookie: "ffffffffffffffff" + "a1a2a3a4a5a6a7a8"}},
			want:  trace.CookieMismatch,
		},
		"a client cookie and no server cookie": {
			given: []dns.RR{&dns.COOKIE{Cookie: client}}, want: trace.CookieMalformed,
		},
		"a server cookie shorter than eight bytes": {
			given: []dns.RR{&dns.COOKIE{Cookie: client + "a1a2"}}, want: trace.CookieMalformed,
		},
		"a server cookie longer than thirty-two bytes": {
			given: []dns.RR{&dns.COOKIE{Cookie: client + strings.Repeat("ab", 33)}},
			want:  trace.CookieMalformed,
		},
		"less than a client cookie": {
			given: []dns.RR{&dns.COOKIE{Cookie: "0102"}}, want: trace.CookieMalformed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp := dns.NewMsg("www.test.", dns.TypeA)
			resp.Pseudo = tt.given

			state, server := transport.EchoedCookie(resp, client)
			if state != tt.want || server != tt.server {
				t.Errorf("got %s %q, want %s %q", state, server, tt.want, tt.server)
			}
		})
	}
}

// TestCarriesCookie covers the transports a cookie is sent over. The encrypted
// ones prove the address already, and an HTTPS front end may drop the option.
func TestCarriesCookie(t *testing.T) {
	for proto, want := range map[string]bool{
		transport.ProtoUDP: true, transport.ProtoTCP: true,
		transport.ProtoDoT: false, transport.ProtoDoH: false,
	} {
		if got := transport.CarriesCookie(proto); got != want {
			t.Errorf("got %v for %s, want %v", got, proto, want)
		}
	}
}
