package capture

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// read is a written capture taken apart again: the packets in the order they
// were written, each checked as it goes.
type read struct {
	at                time.Time
	src, dst          netip.AddrPort
	proto             byte
	flags             byte
	seq, ack          uint32
	payload           []byte
	transportChecksum bool
}

func readBack(t *testing.T, c *Capture) []read {
	t.Helper()
	var buf bytes.Buffer
	if _, err := c.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	data := buf.Bytes()
	if len(data) < 24 {
		t.Fatalf("got %d bytes, want a pcap header at least", len(data))
	}
	le := binary.LittleEndian
	if le.Uint32(data) != 0xa1b2c3d4 || le.Uint16(data[4:]) != 2 || le.Uint16(data[6:]) != 4 || le.Uint32(data[20:]) != linkRaw {
		t.Fatalf("got a pcap header of % x", data[:24])
	}

	var packets []read
	for rest := data[24:]; len(rest) > 0; {
		if len(rest) < 16 {
			t.Fatalf("got %d bytes left, too few for a record header", len(rest))
		}
		incl, orig := int(le.Uint32(rest[8:])), int(le.Uint32(rest[12:]))
		if incl != orig || len(rest) < 16+incl {
			t.Fatalf("got a record of %d bytes kept and %d sent, with %d left", incl, orig, len(rest)-16)
		}
		at := time.Unix(int64(le.Uint32(rest)), int64(le.Uint32(rest[4:]))*1000)
		packets = append(packets, parse(t, at, rest[16:16+incl]))
		rest = rest[16+incl:]
	}
	return packets
}

func parse(t *testing.T, at time.Time, pkt []byte) read {
	t.Helper()
	be := binary.BigEndian
	var (
		src, dst netip.Addr
		proto    byte
		body     []byte
	)
	switch pkt[0] >> 4 {
	case 4:
		if checksum(nil, pkt[:20]) != 0 {
			t.Errorf("got an IPv4 header whose checksum does not hold: % x", pkt[:20])
		}
		if int(be.Uint16(pkt[2:])) != len(pkt) {
			t.Errorf("got an IPv4 length of %d for %d bytes", be.Uint16(pkt[2:]), len(pkt))
		}
		src, dst = netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
		proto, body = pkt[9], pkt[20:]
	case 6:
		if int(be.Uint16(pkt[4:])) != len(pkt)-40 {
			t.Errorf("got an IPv6 payload length of %d for %d bytes", be.Uint16(pkt[4:]), len(pkt)-40)
		}
		src, dst = netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
		proto, body = pkt[6], pkt[40:]
	default:
		t.Fatalf("got IP version %d", pkt[0]>>4)
	}

	r := read{
		at:                at,
		src:               netip.AddrPortFrom(src, be.Uint16(body)),
		dst:               netip.AddrPortFrom(dst, be.Uint16(body[2:])),
		proto:             proto,
		transportChecksum: checksum(pseudo(src, dst, proto, len(body)), body) == 0,
	}
	switch proto {
	case protoUDP:
		if int(be.Uint16(body[4:])) != len(body) {
			t.Errorf("got a UDP length of %d for %d bytes", be.Uint16(body[4:]), len(body))
		}
		r.payload = body[8:]
	case protoTCP:
		r.seq, r.ack, r.flags = be.Uint32(body[4:]), be.Uint32(body[8:]), body[13]
		r.payload = body[int(body[12]>>4)*4:]
	}
	return r
}

var (
	v4Server = netip.MustParseAddrPort("198.41.0.4:53")
	v6Server = netip.MustParseAddrPort("[2001:503:ba3e::2:30]:53")
	start    = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
)

func TestUDP(t *testing.T) {
	tests := map[string]struct {
		server netip.AddrPort
		client netip.Addr
	}{
		"a server over IPv4 is asked from the IPv4 documentation address": {server: v4Server, client: Client.V4},
		"a server over IPv6 is asked from the IPv6 documentation address": {server: v6Server, client: Client.V6},
		"a server written as IPv4 inside IPv6 is asked over IPv4": {
			server: netip.AddrPortFrom(netip.AddrFrom16(v4Server.Addr().As16()), 53),
			client: Client.V4,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := New()
			query, answer := []byte("the query, of an odd length"), []byte("the answer")
			c.Record(Exchange{Proto: UDP, Server: test.server, Sent: start, Took: 30 * time.Millisecond, Query: query, Answer: answer})

			packets := readBack(t, c)
			if len(packets) != 2 {
				t.Fatalf("got %d packets, want the query and the answer", len(packets))
			}
			out, back := packets[0], packets[1]
			server := netip.AddrPortFrom(test.server.Addr().Unmap(), 53)
			if out.src.Addr() != test.client || out.dst != server || back.src != server || back.dst != out.src {
				t.Errorf("got %s to %s and %s to %s, want %s and %s between them", out.src, out.dst, back.src, back.dst, test.client, server)
			}
			for _, p := range packets {
				if p.proto != protoUDP || !p.transportChecksum {
					t.Errorf("got protocol %d with a checksum that holds %v, want UDP with one that does", p.proto, p.transportChecksum)
				}
			}
			if !bytes.Equal(out.payload, query) || !bytes.Equal(back.payload, answer) {
				t.Errorf("got %q and %q, want the messages as they were", out.payload, back.payload)
			}
			if !out.at.Equal(start) || !back.at.Equal(start.Add(30*time.Millisecond)) {
				t.Errorf("got the packets at %v and %v, want the query sent and the answer 30ms later", out.at, back.at)
			}
		})
	}
}

func TestUnanswered(t *testing.T) {
	c := New()
	c.Record(Exchange{Proto: UDP, Server: v4Server, Sent: start, Took: 2 * time.Second, Query: []byte("hello")})
	if packets := readBack(t, c); len(packets) != 1 {
		t.Errorf("got %d packets, want the query alone", len(packets))
	}
}

func TestTCP(t *testing.T) {
	const (
		syn = 0x02
		psh = 0x08
		ack = 0x10
	)
	query := bytes.Repeat([]byte{'q'}, 40)
	answer := bytes.Repeat([]byte{'a'}, 4000) // three segments, with its length in front
	c := New()
	c.Record(Exchange{Proto: TCP, Server: v6Server, Sent: start, Took: 50 * time.Millisecond, Query: query, Answer: answer})

	packets := readBack(t, c)
	var flags []byte
	var fromClient, fromServer []byte
	for _, p := range packets {
		if p.proto != protoTCP || !p.transportChecksum {
			t.Errorf("got protocol %d with a checksum that holds %v, want TCP with one that does", p.proto, p.transportChecksum)
		}
		flags = append(flags, p.flags)
		if p.src.Addr() == Client.V6 {
			fromClient = append(fromClient, p.payload...)
		} else {
			fromServer = append(fromServer, p.payload...)
		}
	}
	want := []byte{syn, syn | ack, ack, psh | ack, psh | ack, psh | ack, psh | ack, ack}
	if !slices.Equal(flags, want) {
		t.Errorf("got flags %x, want %x", flags, want)
	}
	if !bytes.Equal(fromClient, framed(query)) || !bytes.Equal(fromServer, framed(answer)) {
		t.Errorf("got %d bytes from the client and %d from the server, want each message behind its length", len(fromClient), len(fromServer))
	}

	// Each side acknowledges everything the other has sent.
	last := packets[len(packets)-1]
	if last.ack != uint32(1+len(framed(answer))) || last.seq != uint32(1+len(framed(query))) {
		t.Errorf("got the last ack at seq %d ack %d, want %d and %d", last.seq, last.ack, 1+len(framed(query)), 1+len(framed(answer)))
	}
}

// TestOrder covers --all, where several queries are out at once: the capture
// holds them in the order they went out and came back, not the order they
// were recorded in.
func TestOrder(t *testing.T) {
	c := New()
	c.Record(Exchange{Proto: UDP, Server: v4Server, Sent: start, Took: 100 * time.Millisecond, Query: []byte("first"), Answer: []byte("late")})
	c.Record(Exchange{Proto: UDP, Server: v4Server, Sent: start.Add(10 * time.Millisecond), Took: 20 * time.Millisecond, Query: []byte("second"), Answer: []byte("early")})

	var got []string
	for _, p := range readBack(t, c) {
		got = append(got, string(p.payload))
	}
	if want := []string{"first", "second", "early", "late"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncryptedIsLeftOut(t *testing.T) {
	c := New()
	c.Record(Exchange{Proto: "dot", Server: v4Server, Sent: start, Query: []byte("q"), Answer: []byte("a")})
	if packets := readBack(t, c); len(packets) != 0 {
		t.Errorf("got %d packets of encrypted traffic written as plain, want none", len(packets))
	}
}
