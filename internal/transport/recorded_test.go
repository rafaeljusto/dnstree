package transport_test

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/capture"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

func TestRecorded(t *testing.T) {
	udp := func(c transport.Config) transport.Transport { return transport.NewUDP(c) }
	tcp := func(c transport.Config) transport.Transport { return transport.NewTCP(c) }

	tests := map[string]struct {
		behaviour fakens.Behaviour
		carrier   func(transport.Config) transport.Transport
		answered  bool
	}{
		"an answer over udp is recorded as the bytes that came back": {
			carrier:  udp,
			answered: true,
		},
		"an answer over tcp is recorded as the bytes that came back": {
			carrier:  tcp,
			answered: true,
		},
		"a server that stays silent is recorded as a query nothing answered": {
			behaviour: fakens.Behaviour{Drop: true},
			carrier:   udp,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := newServer(t, test.behaviour)
			var (
				mu   sync.Mutex
				seen []capture.Exchange
			)
			carrier := transport.Recorded(test.carrier(fastConfig), func(ex capture.Exchange) {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, ex)
			})

			req := query(t, "www.example.com.", dns.TypeA)
			resp, _, err := carrier.Exchange(t.Context(), req, server.Addr, "")
			if test.answered && err != nil {
				t.Fatalf("Exchange: %v", err)
			}

			if len(seen) != 1 {
				t.Fatalf("got %d exchanges recorded, want 1", len(seen))
			}
			ex := seen[0]
			if ex.Proto != carrier.Proto() || ex.Server != server.Addr {
				t.Errorf("got %s to %s, want %s to %s", ex.Proto, ex.Server, carrier.Proto(), server.Addr)
			}
			sent := &dns.Msg{Data: ex.Query}
			if err := sent.Unpack(); err != nil {
				t.Fatalf("the recorded query does not read as DNS: %v", err)
			}
			if sent.ID != req.ID || sent.Question[0].Header().Name != "www.example.com." {
				t.Errorf("got query %d for %v, want %d for www.example.com.", sent.ID, sent.Question, req.ID)
			}
			// A datagram keeps the buffer it was sent from, so it is what went
			// out, byte for byte.
			if carrier.Proto() == transport.ProtoUDP && !bytes.Equal(ex.Query, req.Data) {
				t.Errorf("got query % x recorded, want the % x sent", ex.Query, req.Data)
			}

			if !test.answered {
				if ex.Answer != nil {
					t.Errorf("got an answer recorded from a silent server: %x", ex.Answer)
				}
				return
			}
			got := &dns.Msg{Data: ex.Answer}
			if err := got.Unpack(); err != nil {
				t.Fatalf("the recorded answer does not read as DNS: %v", err)
			}
			if !got.Response || got.ID != resp.ID || len(got.Answer) != len(resp.Answer) {
				t.Errorf("got answer %d with %d records, want %d with %d", got.ID, len(got.Answer), resp.ID, len(resp.Answer))
			}
		})
	}
}

// TestRecordedLeavesOutWhatNeverLeft covers a connection that could not be
// made: nothing was sent, so a capture holding the query would be a lie.
func TestRecordedLeavesOutWhatNeverLeft(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	closed := netip.MustParseAddrPort(listener.Addr().String())
	_ = listener.Close()

	recorded := 0
	carrier := transport.Recorded(transport.NewTCP(fastConfig), func(capture.Exchange) { recorded++ })
	if _, _, err := carrier.Exchange(t.Context(), query(t, "www.example.com.", dns.TypeA), closed, ""); err == nil {
		t.Fatal("got an answer from a closed port")
	}
	if recorded != 0 {
		t.Errorf("got %d exchanges recorded, want none", recorded)
	}
}

// TestRecordedKeepsWhatWasRefusedLate covers a server that takes the query and
// resets the connection, the way some refuse a zone transfer: the query went
// out, so the capture holds it, with nothing back.
func TestRecordedKeepsWhatWasRefusedLate(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Read(make([]byte, 512))
		_ = conn.(*net.TCPConn).SetLinger(0) // close with RST
		_ = conn.Close()
	}()

	var seen []capture.Exchange
	carrier := transport.Recorded(transport.NewTCP(fastConfig), func(ex capture.Exchange) { seen = append(seen, ex) })
	server := netip.MustParseAddrPort(listener.Addr().String())
	if _, _, err := carrier.Exchange(t.Context(), query(t, "example.com.", dns.TypeAXFR), server, ""); !transport.IsReset(err) {
		t.Fatalf("got %v, want a reset", err)
	}
	if len(seen) != 1 || seen[0].Query == nil || seen[0].Answer != nil {
		t.Errorf("got %+v recorded, want the query alone", seen)
	}
}
