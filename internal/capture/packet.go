package capture

import (
	"encoding/binary"
	"net/netip"
)

// flow is the two ends of one exchange.
type flow struct {
	client, server netip.AddrPort
}

const (
	protoTCP = 6
	protoUDP = 17
)

// udp is a datagram one way or the other, nil for one too large for any IP
// packet to carry, which no socket would have handed over.
func (f flow) udp(out bool, payload []byte) []byte {
	src, dst := f.ends(out)
	transport := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(transport[0:], src.Port())
	binary.BigEndian.PutUint16(transport[2:], dst.Port())
	binary.BigEndian.PutUint16(transport[4:], uint16(8+len(payload)))
	transport = append(transport, payload...)
	if len(transport) > 0xffff {
		return nil
	}
	sum := checksum(pseudo(src.Addr(), dst.Addr(), protoUDP, len(transport)), transport)
	if sum == 0 {
		sum = 0xffff // zero says no checksum was computed (RFC 768)
	}
	binary.BigEndian.PutUint16(transport[6:], sum)
	return ip(src.Addr(), dst.Addr(), protoUDP, transport)
}

// segment is one TCP segment one way or the other.
func (f flow) segment(out bool, flags byte, seq, ack uint32, payload []byte) []byte {
	src, dst := f.ends(out)
	transport := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(transport[0:], src.Port())
	binary.BigEndian.PutUint16(transport[2:], dst.Port())
	binary.BigEndian.PutUint32(transport[4:], seq)
	binary.BigEndian.PutUint32(transport[8:], ack)
	transport[12] = 5 << 4 // a header of five words, without options
	transport[13] = flags
	binary.BigEndian.PutUint16(transport[14:], 0xffff) // the window
	transport = append(transport, payload...)
	binary.BigEndian.PutUint16(transport[16:], checksum(pseudo(src.Addr(), dst.Addr(), protoTCP, len(transport)), transport))
	return ip(src.Addr(), dst.Addr(), protoTCP, transport)
}

func (f flow) ends(out bool) (src, dst netip.AddrPort) {
	if out {
		return f.client, f.server
	}
	return f.server, f.client
}

// ip wraps a transport header and its payload in an IPv4 or IPv6 header.
func ip(src, dst netip.Addr, proto byte, transport []byte) []byte {
	if src.Is4() {
		if 20+len(transport) > 0xffff {
			return nil
		}
		header := make([]byte, 20, 20+len(transport))
		header[0] = 0x45 // version 4, five words of header
		binary.BigEndian.PutUint16(header[2:], uint16(20+len(transport)))
		header[6] = 0x40 // don't fragment
		header[8] = 64   // the TTL
		header[9] = proto
		s, d := src.As4(), dst.As4()
		copy(header[12:], s[:])
		copy(header[16:], d[:])
		binary.BigEndian.PutUint16(header[10:], checksum(nil, header))
		return append(header, transport...)
	}

	header := make([]byte, 40, 40+len(transport))
	header[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(header[4:], uint16(len(transport)))
	header[6] = proto
	header[7] = 64 // the hop limit
	s, d := src.As16(), dst.As16()
	copy(header[8:], s[:])
	copy(header[24:], d[:])
	return append(header, transport...)
}

// pseudo is the header the UDP and TCP checksums are computed over, besides
// the segment itself.
func pseudo(src, dst netip.Addr, proto byte, length int) []byte {
	var p []byte
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		p = append(append(p, s[:]...), d[:]...)
		p = append(p, 0, proto)
		return binary.BigEndian.AppendUint16(p, uint16(length))
	}
	s, d := src.As16(), dst.As16()
	p = append(append(p, s[:]...), d[:]...)
	p = binary.BigEndian.AppendUint32(p, uint32(length))
	return append(p, 0, 0, 0, proto)
}

// checksum is the internet checksum of RFC 1071 over a and then b. a is always
// of an even length, so b's words line up where they would in one buffer.
func checksum(a, b []byte) uint16 {
	var sum uint32
	for _, data := range [][]byte{a, b} {
		for i := 0; i+1 < len(data); i += 2 {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		}
		if len(data)%2 == 1 {
			sum += uint32(data[len(data)-1]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
