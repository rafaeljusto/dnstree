package capture

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func written(t testing.TB, exchanges ...Exchange) []byte {
	t.Helper()
	c := New()
	for _, ex := range exchanges {
		c.Record(ex)
	}
	var buf bytes.Buffer
	if _, err := c.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return buf.Bytes()
}

func sameExchanges(a, b []Exchange) bool {
	return slices.EqualFunc(a, b, func(x, y Exchange) bool {
		return x.Proto == y.Proto && x.Server == y.Server && x.Sent.Equal(y.Sent) && x.Took == y.Took &&
			bytes.Equal(x.Query, y.Query) && bytes.Equal(x.Answer, y.Answer)
	})
}

func TestRead(t *testing.T) {
	long := bytes.Repeat([]byte{'a'}, 4000)
	tests := map[string][]Exchange{
		"a datagram over IPv4 and its answer": {
			{Proto: UDP, Server: v4Server, Sent: start, Took: 30 * time.Millisecond, Query: []byte("q"), Answer: []byte("a")},
		},
		"a datagram over IPv6 nothing answered": {
			{Proto: UDP, Server: v6Server, Sent: start, Query: []byte("q")},
		},
		"an answer over TCP in three segments": {
			{Proto: TCP, Server: v6Server, Sent: start, Took: 50 * time.Millisecond, Query: []byte("q"), Answer: long},
		},
		"a connection nothing answered on": {
			{Proto: TCP, Server: v4Server, Sent: start, Query: []byte("q")},
		},
		"queries out at once, answered out of order": {
			{Proto: UDP, Server: v4Server, Sent: start, Took: 100 * time.Millisecond, Query: []byte("first"), Answer: []byte("late")},
			{Proto: TCP, Server: v4Server, Sent: start.Add(10 * time.Millisecond), Took: 20 * time.Millisecond, Query: []byte("second"), Answer: []byte("early")},
		},
	}

	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Read(bytes.NewReader(written(t, want...)))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if !sameExchanges(got, want) {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestReadRefuses(t *testing.T) {
	good := written(t, Exchange{Proto: UDP, Server: v4Server, Sent: start, Took: time.Millisecond, Query: []byte("q"), Answer: []byte("a")})
	ethernet := slices.Clone(good)
	binary.LittleEndian.PutUint32(ethernet[20:], 1)
	backwards := slices.Clone(good)
	binary.LittleEndian.PutUint32(backwards[24+16+len("q")+28:], uint32(start.Unix()-1))
	overflowing := slices.Clone(good)
	binary.LittleEndian.PutUint32(overflowing[24+4:], 1e6)

	tests := map[string]struct {
		data []byte
		want string
	}{
		"nothing at all":                     {nil, "too short"},
		"a file that is no capture":          {bytes.Repeat([]byte("{}"), 20), "not a packet capture"},
		"a capture with link headers":        {ethernet, "link headers"},
		"a capture cut in the middle":        {good[:len(good)-1], "cut short"},
		"an answer written before its query": {backwards, "out of order"},
		"microseconds past a second":         {overflowing, "more than a second of microseconds"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(test.data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("got %v, want an error saying %q", err, test.want)
			}
		})
	}
}

// TestReadSegmentsAfterTheMessage covers a stream that goes on in one-byte
// segments once its message is in: reading it costs what the file holds, not
// a copy of the message for every segment after it.
func TestReadSegmentsAfterTheMessage(t *testing.T) {
	var data bytes.Buffer
	header := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	header = binary.LittleEndian.AppendUint32(header, 2|4<<16)
	header = binary.LittleEndian.AppendUint64(header, 0)
	header = binary.LittleEndian.AppendUint32(header, snaplen)
	header = binary.LittleEndian.AppendUint32(header, linkRaw)
	data.Write(header)
	segment := func(seq uint32, flags byte, payload []byte) {
		packet := make([]byte, 40+len(payload))
		packet[0], packet[9] = 0x45, protoTCP
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		copy(packet[12:], []byte{192, 0, 2, 1})
		copy(packet[16:], []byte{198, 51, 100, 53})
		binary.BigEndian.PutUint16(packet[20:], 40000)
		binary.BigEndian.PutUint16(packet[22:], 53)
		binary.BigEndian.PutUint32(packet[24:], seq)
		packet[32], packet[33] = 5<<4, flags
		copy(packet[40:], payload)
		record := binary.LittleEndian.AppendUint64(nil, 1)
		record = binary.LittleEndian.AppendUint32(record, uint32(len(packet)))
		record = binary.LittleEndian.AppendUint32(record, uint32(len(packet)))
		data.Write(record)
		data.Write(packet)
	}
	const syn, psh = 0x02, 0x18
	message := make([]byte, 2+65000)
	binary.BigEndian.PutUint16(message, 65000)
	segment(0, syn, nil)
	segment(1, psh, message)
	for seq := uint32(1 + len(message)); data.Len() < 1<<20; seq++ {
		segment(seq, psh, []byte{0})
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	exchanges, err := Read(bytes.NewReader(data.Bytes()))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(exchanges) != 1 || !bytes.Equal(exchanges[0].Query, message[2:]) {
		t.Errorf("got %d exchanges, want the one message", len(exchanges))
	}
	if spent, most := after.TotalAlloc-before.TotalAlloc, uint64(16*data.Len()); spent > most {
		t.Errorf("reading %d bytes allocated %d, want at most %d", data.Len(), spent, most)
	}
}

// FuzzRead reads a capture whoever wrote it, the way --replay does. One that
// is refused is refused; what is read is written and read back to the same
// exchanges, so a replay hands the walk what the file holds and nothing else.
func FuzzRead(f *testing.F) {
	f.Add(written(f,
		Exchange{Proto: UDP, Server: v4Server, Sent: start, Took: 30 * time.Millisecond, Query: []byte("q"), Answer: []byte("a")},
		Exchange{Proto: TCP, Server: v6Server, Sent: start, Took: 50 * time.Millisecond, Query: []byte("q"), Answer: bytes.Repeat([]byte{'a'}, 3000)},
		Exchange{Proto: UDP, Server: v6Server, Sent: start.Add(time.Second), Query: []byte("silence")},
	))

	f.Fuzz(func(t *testing.T, data []byte) {
		once, err := Read(bytes.NewReader(data))
		if err != nil {
			return
		}
		twice, err := Read(bytes.NewReader(written(t, once...)))
		if err != nil {
			t.Fatalf("what was read, written again, is refused: %v", err)
		}
		if !sameExchanges(once, twice) {
			t.Fatalf("read %+v, and %+v once written again", once, twice)
		}
	})
}
