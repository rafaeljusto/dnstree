package capture

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"
)

// MaxRead is the largest capture Read takes in.
const MaxRead = 64 << 20

// Read takes a capture written by WriteTo apart again, into the exchanges it
// was built from, in the order they were sent. It reads the shape WriteTo
// writes and refuses any other: a capture taken off the wire carries link
// headers, fragments and retransmissions that nothing here would read right.
// A query whose answer never came is an exchange without one.
func Read(r io.Reader) ([]Exchange, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRead+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxRead {
		return nil, fmt.Errorf("larger than the %d MiB a capture is read up to", MaxRead>>20)
	}
	if len(data) < 24 {
		return nil, errors.New("too short to be a packet capture")
	}
	var unit time.Duration
	switch binary.LittleEndian.Uint32(data) {
	case magicNano:
		unit = time.Nanosecond
	case magicMicro:
		unit = time.Microsecond
	default:
		return nil, errors.New("not a packet capture dnstree --pcap wrote")
	}
	if binary.LittleEndian.Uint32(data[20:]) != linkRaw {
		return nil, errors.New("a packet capture with link headers, which only one dnstree --pcap wrote does not have")
	}

	var (
		rd   reader
		last time.Time
	)
	for offset, n := 24, 1; offset < len(data); n++ {
		if len(data)-offset < 16 {
			return nil, fmt.Errorf("packet %d is cut short", n)
		}
		header := data[offset : offset+16]
		size := int(binary.LittleEndian.Uint32(header[8:]))
		offset += 16
		if size > snaplen || size > len(data)-offset {
			return nil, fmt.Errorf("packet %d is cut short", n)
		}
		fraction := time.Duration(binary.LittleEndian.Uint32(header[4:])) * unit
		if fraction >= time.Second {
			// Carried into the seconds, it would name a time no capture
			// can write.
			return nil, fmt.Errorf("packet %d has a timestamp of more than a second past its seconds", n)
		}
		at := time.Unix(int64(binary.LittleEndian.Uint32(header)), int64(fraction)).UTC()
		// WriteTo puts every packet in the order it was sent, which is what
		// pairs an answer with the query before it.
		if at.Before(last) {
			return nil, fmt.Errorf("packet %d is out of order", n)
		}
		last = at
		if err := rd.packet(at, data[offset:offset+size]); err != nil {
			return nil, fmt.Errorf("packet %d: %w", n, err)
		}
		offset += size
	}
	return rd.exchanges(), nil
}

// reader is a capture being taken apart: the exchanges so far, and the ones
// still waiting on an answer, by the client port and server they went between.
type reader struct {
	done []*Exchange
	udp  map[flow]*Exchange
	tcp  map[flow]*stream
}

// stream is one TCP connection, each side's bytes in the order they were
// sent.
type stream struct {
	exchange             *Exchange
	query, answer        []byte
	clientSeq, serverSeq uint32
}

func (rd *reader) packet(at time.Time, data []byte) error {
	src, dst, proto, payload, err := unwrap(data)
	if err != nil {
		return err
	}
	out := src.Addr() == Client.V4 || src.Addr() == Client.V6
	f := flow{client: dst, server: src}
	if out {
		f = flow{client: src, server: dst}
	}

	switch proto {
	case protoUDP:
		if rd.udp == nil {
			rd.udp = map[flow]*Exchange{}
		}
		if out {
			ex := &Exchange{Proto: UDP, Server: f.server, Sent: at, Query: payload}
			rd.done = append(rd.done, ex)
			rd.udp[f] = ex
			return nil
		}
		// An answer nobody asked for, or a second one, is not part of any
		// exchange WriteTo could have written.
		if ex := rd.udp[f]; ex != nil {
			ex.Answer, ex.Took = payload, at.Sub(ex.Sent)
			delete(rd.udp, f)
		}
		return nil

	default:
		return rd.segment(f, out, at, payload)
	}
}

// segment adds a TCP segment to its connection. A SYN from the client starts
// one; anything out of order is dropped, since WriteTo writes none.
func (rd *reader) segment(f flow, out bool, at time.Time, segment []byte) error {
	if len(segment) < 20 {
		return errors.New("a TCP segment too short for its header")
	}
	offset := int(segment[12]>>4) * 4
	if offset < 20 || offset > len(segment) {
		return errors.New("a TCP header longer than its segment")
	}
	seq, flags, payload := binary.BigEndian.Uint32(segment[4:]), segment[13], segment[offset:]
	const syn = 2

	if rd.tcp == nil {
		rd.tcp = map[flow]*stream{}
	}
	s := rd.tcp[f]
	if out && flags&syn != 0 {
		ex := &Exchange{Proto: TCP, Server: f.server, Sent: at}
		rd.done = append(rd.done, ex)
		rd.tcp[f] = &stream{exchange: ex, clientSeq: seq + 1}
		return nil
	}
	if s == nil {
		return nil
	}
	if flags&syn != 0 {
		s.serverSeq = seq + 1
		return nil
	}
	if len(payload) == 0 {
		return nil
	}
	// Only the first message each way is read, and once it is in, what
	// follows is not kept: copying it out again for every later segment
	// would cost a capture of small segments the square of its length.
	if out {
		if seq == s.clientSeq {
			s.clientSeq += uint32(len(payload))
			if s.exchange.Query == nil {
				s.query = append(s.query, payload...)
				s.exchange.Query = unframed(s.query)
			}
		}
		return nil
	}
	if seq == s.serverSeq {
		s.serverSeq += uint32(len(payload))
		if s.exchange.Answer == nil {
			s.answer = append(s.answer, payload...)
			if answer := unframed(s.answer); answer != nil {
				s.exchange.Answer, s.exchange.Took = answer, at.Sub(s.exchange.Sent)
			}
		}
	}
	return nil
}

// unframed is the message at the start of a stream, nil until all of it is
// there.
func unframed(stream []byte) []byte {
	if len(stream) < 2 {
		return nil
	}
	size := int(binary.BigEndian.Uint16(stream))
	if len(stream) < 2+size {
		return nil
	}
	return bytes.Clone(stream[2 : 2+size])
}

// exchanges are the ones that carried a query, in the order they were sent.
func (rd *reader) exchanges() []Exchange {
	exchanges := make([]Exchange, 0, len(rd.done))
	for _, ex := range rd.done {
		if ex.Query != nil {
			exchanges = append(exchanges, *ex)
		}
	}
	slices.SortStableFunc(exchanges, func(a, b Exchange) int { return cmp.Compare(a.Sent.UnixNano(), b.Sent.UnixNano()) })
	return exchanges
}

// unwrap takes the IP header off a packet: the two ends, the protocol and
// what it carries.
func unwrap(data []byte) (src, dst netip.AddrPort, proto byte, payload []byte, err error) {
	var srcAddr, dstAddr netip.Addr
	switch {
	case len(data) >= 20 && data[0]>>4 == 4:
		size, length := int(data[0]&0x0f)*4, int(binary.BigEndian.Uint16(data[2:]))
		if size < 20 || length < size || length > len(data) {
			return src, dst, 0, nil, errors.New("an IPv4 header that does not fit its packet")
		}
		if binary.BigEndian.Uint16(data[6:])&0x3fff != 0 {
			return src, dst, 0, nil, errors.New("a fragment, which dnstree never writes")
		}
		srcAddr, dstAddr = netip.AddrFrom4([4]byte(data[12:16])), netip.AddrFrom4([4]byte(data[16:20]))
		proto, payload = data[9], data[size:length]
	case len(data) >= 40 && data[0]>>4 == 6:
		length := int(binary.BigEndian.Uint16(data[4:]))
		if 40+length > len(data) {
			return src, dst, 0, nil, errors.New("an IPv6 header that does not fit its packet")
		}
		srcAddr, dstAddr = netip.AddrFrom16([16]byte(data[8:24])), netip.AddrFrom16([16]byte(data[24:40]))
		proto, payload = data[6], data[40:40+length]
	default:
		return src, dst, 0, nil, errors.New("not an IP packet")
	}

	switch proto {
	case protoUDP:
		if len(payload) < 8 {
			return src, dst, 0, nil, errors.New("a UDP datagram too short for its header")
		}
		length := int(binary.BigEndian.Uint16(payload[4:]))
		if length < 8 || length > len(payload) {
			return src, dst, 0, nil, errors.New("a UDP header that does not fit its datagram")
		}
		src = netip.AddrPortFrom(srcAddr, binary.BigEndian.Uint16(payload))
		dst = netip.AddrPortFrom(dstAddr, binary.BigEndian.Uint16(payload[2:]))
		return src, dst, proto, bytes.Clone(payload[8:length]), nil
	case protoTCP:
		if len(payload) < 4 {
			return src, dst, 0, nil, errors.New("a TCP segment too short for its header")
		}
		src = netip.AddrPortFrom(srcAddr, binary.BigEndian.Uint16(payload))
		dst = netip.AddrPortFrom(dstAddr, binary.BigEndian.Uint16(payload[2:]))
		return src, dst, proto, payload, nil
	default:
		return src, dst, 0, nil, fmt.Errorf("IP protocol %d, which is neither UDP nor TCP", proto)
	}
}
