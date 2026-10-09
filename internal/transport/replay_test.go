package transport_test

import (
	"net/netip"
	"strings"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/capture"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// recording asks a server through carrier, once for each query, and keeps what
// went across.
func recording(t *testing.T, carrier transport.Transport, server netip.AddrPort, queries ...*dns.Msg) []capture.Exchange {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []capture.Exchange
	)
	recorded := transport.Recorded(carrier, func(ex capture.Exchange) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, ex)
	})
	for _, req := range queries {
		_, _, _ = recorded.Exchange(t.Context(), req, server, "")
	}
	return seen
}

func TestReplay(t *testing.T) {
	t.Parallel()

	server := newServer(t, fakens.Behaviour{})
	signed := query(t, "www.example.com.", dns.TypeA)
	signed.Security = true
	exchanges := recording(t, transport.NewUDP(fastConfig), server.Addr, query(t, "www.example.com.", dns.TypeA))
	elsewhere := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.53"), server.Addr.Port())

	tests := map[string]struct {
		proto  string
		server netip.AddrPort
		req    *dns.Msg
		want   string
	}{
		"the same question to the same server is answered as it was": {
			proto: transport.ProtoUDP, server: server.Addr, req: query(t, "WWW.example.com.", dns.TypeA),
		},
		"another type was never asked": {
			proto: transport.ProtoUDP, server: server.Addr, req: query(t, "www.example.com.", dns.TypeAAAA),
			want: "the capture holds no answer to www.example.com. AAAA",
		},
		"the DO bit makes another question": {
			proto: transport.ProtoUDP, server: server.Addr, req: signed,
			want: "the capture holds no answer",
		},
		"another server was never asked": {
			proto: transport.ProtoUDP, server: elsewhere, req: query(t, "www.example.com.", dns.TypeA),
			want: "the capture holds no answer",
		},
		"over tcp it was never asked": {
			proto: transport.ProtoTCP, server: server.Addr, req: query(t, "www.example.com.", dns.TypeA),
			want: "the capture holds no answer",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			carrier := transport.NewReplay(exchanges).Carrier(test.proto, transport.PortDNS)
			resp, rtt, err := carrier.Exchange(t.Context(), test.req, test.server, "")
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) || transport.IsTimeout(err) {
					t.Fatalf("got %v, want an error saying %q that is no timeout", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if resp.ID != test.req.ID || len(resp.Answer) == 0 {
				t.Errorf("got answer %d with %v, want %d with the records", resp.ID, resp.Answer, test.req.ID)
			}
			if len(resp.Data) != len(exchanges[0].Answer) {
				t.Errorf("got %d bytes, want the %d that came back when it was asked", len(resp.Data), len(exchanges[0].Answer))
			}
			if rtt != exchanges[0].Took {
				t.Errorf("got a round trip of %s, want the %s recorded", rtt, exchanges[0].Took)
			}
		})
	}
}

// TestReplayInOrder covers a server asked twice the same way: silent the first
// time and answering the retry, which a replay hands back in that order, and
// then answering again with the last.
func TestReplayInOrder(t *testing.T) {
	t.Parallel()

	silent := newServer(t, fakens.Behaviour{Drop: true})
	answering := newServer(t, fakens.Behaviour{})
	exchanges := recording(t, transport.NewUDP(fastConfig), silent.Addr, query(t, "www.example.com.", dns.TypeA))
	answered := recording(t, transport.NewUDP(fastConfig), answering.Addr, query(t, "www.example.com.", dns.TypeA))
	if len(exchanges) != 1 || len(answered) != 1 {
		t.Fatalf("got %d and %d exchanges, want one of each", len(exchanges), len(answered))
	}
	answered[0].Server = silent.Addr
	exchanges = append(exchanges, answered...)

	carrier := transport.NewReplay(exchanges).Carrier(transport.ProtoUDP, transport.PortDNS)
	if _, _, err := carrier.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), silent.Addr, ""); !transport.IsTimeout(err) {
		t.Fatalf("got %v the first time, want the silence it was", err)
	}
	for range 2 {
		if _, _, err := carrier.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), silent.Addr, ""); err != nil {
			t.Fatalf("got %v, want the answer to the retry", err)
		}
	}
}

// TestReplayEchoesTheCookie covers a replay under --cookie: the walk derives
// a client cookie of its own, and the server's answer echoes that one.
func TestReplayEchoesTheCookie(t *testing.T) {
	t.Parallel()

	server := newServer(t, fakens.Behaviour{Cookies: fakens.CookieSupport})
	then := query(t, "www.example.com.", dns.TypeA)
	then.UDPSize = transport.DefaultUDPSize
	transport.WithCookie(then, "0102030405060708", "")
	exchanges := recording(t, transport.NewUDP(fastConfig), server.Addr, then)

	now := query(t, "www.example.com.", dns.TypeA)
	now.UDPSize = transport.DefaultUDPSize
	transport.WithCookie(now, "a1a2a3a4a5a6a7a8", "")
	resp, _, err := transport.NewReplay(exchanges).Carrier(transport.ProtoUDP, transport.PortDNS).Exchange(t.Context(), now, server.Addr, "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if state, _ := transport.EchoedCookie(resp, "a1a2a3a4a5a6a7a8"); state != trace.CookieSupported {
		t.Errorf("got the cookie %s, want the client half of this walk echoed", state)
	}
	if len(resp.Data) != len(exchanges[0].Answer) {
		t.Errorf("got %d bytes, want the %d that came back", len(resp.Data), len(exchanges[0].Answer))
	}
}
