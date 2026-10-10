// Package capture writes the messages of a walk as a packet capture, in the
// pcap format Wireshark and tcpdump read.
//
// The capture is rebuilt rather than taken off the wire: the DNS messages are
// the bytes that were sent and received, and the servers, ports and times are
// real, but the IP, UDP and TCP headers around them are made up. dnstree's own
// side is written as an address from the documentation ranges, which also
// keeps the machine's address out of a capture that gets pasted somewhere.
package capture

import (
	"cmp"
	"encoding/binary"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// The protocols a capture can rebuild. Encrypted traffic cannot be: what was
// on the wire is TLS, and plain DNS on its port would say otherwise.
const (
	UDP = "udp"
	TCP = "tcp"
)

// Client is the address dnstree's side of every exchange is written from.
var Client = struct{ V4, V6 netip.Addr }{
	V4: netip.MustParseAddr("192.0.2.1"),
	V6: netip.MustParseAddr("2001:db8::1"),
}

// Exchange is one query and what came back. A nil Answer is a query nothing
// answered.
type Exchange struct {
	Proto  string
	Server netip.AddrPort
	Sent   time.Time
	Took   time.Duration
	Query  []byte
	Answer []byte
}

// Capture gathers the exchanges of a run. Record may be called from as many
// goroutines as are querying; the packets are put in the order they were sent
// when the capture is written.
type Capture struct {
	mu      sync.Mutex
	packets []packet
	flows   int
}

type packet struct {
	at   time.Time
	data []byte
}

// New returns an empty capture.
func New() *Capture { return &Capture{} }

// Record adds an exchange, as the packets that would have carried it. One over
// a protocol the capture cannot rebuild is left out.
func (c *Capture) Record(ex Exchange) {
	if ex.Proto != UDP && ex.Proto != TCP {
		return
	}
	server := netip.AddrPortFrom(ex.Server.Addr().Unmap(), ex.Server.Port())
	if !server.IsValid() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.flows++
	f := flow{
		client: netip.AddrPortFrom(Client.V4, ephemeral(c.flows)),
		server: server,
	}
	if server.Addr().Is6() {
		f.client = netip.AddrPortFrom(Client.V6, f.client.Port())
	}
	answered := ex.Sent.Add(ex.Took)
	if ex.Proto == UDP {
		c.add(ex.Sent, f.udp(true, ex.Query))
		if ex.Answer != nil {
			c.add(answered, f.udp(false, ex.Answer))
		}
		return
	}
	c.tcp(f, ex.Sent, answered, ex.Query, ex.Answer)
}

// ephemeral is the client port of the nth exchange, inside the range RFC 6335
// leaves to them.
func ephemeral(n int) uint16 { return uint16(49152 + n%16384) }

func (c *Capture) add(at time.Time, data []byte) {
	if data != nil {
		c.packets = append(c.packets, packet{at: at, data: data})
	}
}

// mss is how much of a message one TCP segment carries.
const mss = 1460

// tcp rebuilds a connection: the handshake, the query, and the answer in as
// many segments as it takes, each acknowledged the way the stream would be.
// Sequence numbers start at zero on both sides, which is what Wireshark shows
// as relative ones anyway.
func (c *Capture) tcp(f flow, sent, answered time.Time, query, answer []byte) {
	const (
		fin = 1 << iota
		syn
		_
		psh
		ack
	)
	var clientSeq, serverSeq uint32
	c.add(sent, f.segment(true, syn, clientSeq, 0, nil))
	c.add(sent, f.segment(false, syn|ack, serverSeq, clientSeq+1, nil))
	clientSeq++
	serverSeq++
	c.add(sent, f.segment(true, ack, clientSeq, serverSeq, nil))

	for chunk := range slices.Chunk(framed(query), mss) {
		c.add(sent, f.segment(true, psh|ack, clientSeq, serverSeq, chunk))
		clientSeq += uint32(len(chunk))
	}
	if answer == nil {
		return
	}
	for chunk := range slices.Chunk(framed(answer), mss) {
		c.add(answered, f.segment(false, psh|ack, serverSeq, clientSeq, chunk))
		serverSeq += uint32(len(chunk))
	}
	c.add(answered, f.segment(true, ack, clientSeq, serverSeq, nil))
}

// framed is a message as TCP carries it, behind its length (RFC 1035 4.2.2).
func framed(msg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}

// WriteTo writes the capture as a pcap file, the packets in the order they
// were sent.
func (c *Capture) WriteTo(w io.Writer) (int64, error) {
	c.mu.Lock()
	packets := slices.Clone(c.packets)
	c.mu.Unlock()
	slices.SortStableFunc(packets, func(a, b packet) int { return cmp.Compare(a.at.UnixNano(), b.at.UnixNano()) })

	var out []byte
	out = binary.LittleEndian.AppendUint32(out, magicNano)
	out = binary.LittleEndian.AppendUint16(out, 2)
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = binary.LittleEndian.AppendUint32(out, 0) // the timestamps are UTC
	out = binary.LittleEndian.AppendUint32(out, 0)
	out = binary.LittleEndian.AppendUint32(out, snaplen)
	out = binary.LittleEndian.AppendUint32(out, linkRaw)
	for _, p := range packets {
		out = binary.LittleEndian.AppendUint32(out, uint32(p.at.Unix()))
		out = binary.LittleEndian.AppendUint32(out, uint32(p.at.Nanosecond()))
		out = binary.LittleEndian.AppendUint32(out, uint32(len(p.data)))
		out = binary.LittleEndian.AppendUint32(out, uint32(len(p.data)))
		out = append(out, p.data...)
	}
	n, err := w.Write(out)
	return int64(n), err
}

const (
	// The timestamps are kept to the nanosecond, so that a hop replayed takes
	// exactly as long as the one recorded: to the microsecond, sent and
	// answered round apart, and a hop of two exchanges can come out 2µs off.
	magicNano  = 0xa1b23c4d
	magicMicro = 0xa1b2c3d4 // what earlier releases wrote, still read

	snaplen = 262144
	linkRaw = 101 // LINKTYPE_RAW: each packet starts at its IP header
)
