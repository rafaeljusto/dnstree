package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/capture"
)

// Replay answers a walk from a capture --pcap made, the way the servers in it
// answered then. Nothing is sent: a query is matched to the one the capture
// holds that was put the same way to the same server, and handed back what came
// of it. Answers to the same query are handed out in the order they came, so
// a silence and then the answer to the retry come back that way again, and the
// last one is handed out again once they run out.
type Replay struct {
	made    time.Time
	mu      sync.Mutex
	answers map[string][]replayed
	reached time.Duration // the latest any answer handed out came back, from made
}

type replayed struct {
	sent   time.Time
	took   time.Duration
	answer []byte
}

// NewReplay holds the exchanges of a capture to answer from. A query that does
// not read as DNS can never be asked again, and is left out.
func NewReplay(exchanges []capture.Exchange) *Replay {
	r := &Replay{answers: map[string][]replayed{}}
	for _, ex := range exchanges {
		if r.made.IsZero() || ex.Sent.Before(r.made) {
			r.made = ex.Sent
		}
		query := &dns.Msg{Data: ex.Query}
		if query.Unpack() != nil || len(query.Question) != 1 {
			continue
		}
		k := replayKey(ex.Proto, ex.Server, query)
		r.answers[k] = append(r.answers[k], replayed{sent: ex.Sent, took: ex.Took, answer: ex.Answer})
	}
	return r
}

// Made is when the first query of the capture was sent, zero for a capture
// that holds none.
func (r *Replay) Made() time.Time { return r.made }

// Clock is how far the capture had got by the latest answer handed out, which
// is where a walk replayed from it stands: its hops take the time they took
// then, so its length has to be counted the same way.
func (r *Replay) Clock() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reached
}

// Carrier is the transport that answers what the capture holds for proto,
// expecting servers on port where a delegation names none.
func (r *Replay) Carrier(proto string, port uint16) Transport {
	return &replay{store: r, proto: proto, port: port}
}

func (r *Replay) next(k string) (replayed, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	queue := r.answers[k]
	if len(queue) == 0 {
		return replayed{}, false
	}
	if len(queue) > 1 {
		r.answers[k] = queue[1:]
	}
	r.reached = max(r.reached, queue[0].sent.Add(queue[0].took).Sub(r.made))
	return queue[0], true
}

type replay struct {
	store *Replay
	proto string
	port  uint16
}

func (t *replay) Proto() string { return t.proto }

func (t *replay) Port() uint16 { return t.port }

func (t *replay) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, _ string) (*dns.Msg, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	if len(req.Question) != 1 {
		return nil, 0, fmt.Errorf("%s %s: not one question to look up in the capture", t.proto, server)
	}

	saved, ok := t.store.next(replayKey(t.proto, server, req))
	if !ok {
		q := req.Question[0]
		return nil, 0, fmt.Errorf("%s %s: the capture holds no answer to %s %s asked this way",
			t.proto, server, q.Header().Name, dnsutil.TypeToString(dns.RRToType(q)))
	}
	if saved.answer == nil {
		return nil, saved.took, &silence{text: fmt.Sprintf("%s %s: nothing came back when the capture was made", t.proto, server)}
	}

	// The bytes are patched rather than packed again, which would compress
	// the names its own way and change the size the hop is drawn with.
	data := slices.Clone(saved.answer)
	if len(data) >= 2 {
		binary.BigEndian.PutUint16(data, req.ID)
	}
	echoCookie(req, data)
	resp := &dns.Msg{Data: data}
	if err := resp.Unpack(); err != nil {
		return nil, saved.took, fmt.Errorf("%s %s: %w", t.proto, server, err)
	}
	if err := answers(req, resp); err != nil {
		return nil, saved.took, fmt.Errorf("%s %s: %w", t.proto, server, err)
	}
	return inClass(resp), saved.took, nil
}

// echoCookie gives the answer the client half of the cookie the query carries
// now. A replayed walk derives its cookies from a secret of its own, and the
// half a server echoes is the client's, never the server's say.
func echoCookie(req *dns.Msg, answer []byte) {
	var client []byte
	for _, rr := range req.Pseudo {
		if cookie, ok := rr.(*dns.COOKIE); ok {
			if raw, err := hex.DecodeString(cookie.Cookie); err == nil && len(raw) >= clientCookieSize {
				client = raw[:clientCookieSize]
			}
		}
	}
	saved := &dns.Msg{Data: answer}
	if client == nil || saved.Unpack() != nil {
		return
	}
	for _, rr := range saved.Pseudo {
		cookie, ok := rr.(*dns.COOKIE)
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(cookie.Cookie)
		if err != nil || len(raw) < clientCookieSize {
			continue
		}
		// The option as it sits in the message: its code, its length, and
		// the client half first.
		option := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, dns.CodeCOOKIE), uint16(len(raw)))
		option = append(option, raw[:clientCookieSize]...)
		if at := bytes.LastIndex(answer, option); at >= 0 {
			copy(answer[at+4:], client)
		}
	}
}

// replayKey is what makes two queries the same one: the server and the way it
// was asked, down to the EDNS options sent, but not the ID or the cookie,
// which differ every run.
func replayKey(proto string, server netip.AddrPort, req *dns.Msg) string {
	q := req.Question[0]
	var options []string
	for _, rr := range req.Pseudo {
		option, ok := rr.(dns.EDNS0)
		if !ok {
			continue
		}
		switch option.(type) {
		case *dns.COOKIE:
			options = append(options, "cookie")
		case *dns.SUBNET:
			options = append(options, option.String())
		default:
			options = append(options, fmt.Sprint(dns.RRToCode(option)))
		}
	}
	slices.Sort(options)
	return fmt.Sprintf("%s %s %s %d %d opcode=%d rd=%t cd=%t edns=%d version=%d do=%t z=%d %s",
		proto, netip.AddrPortFrom(server.Addr().Unmap(), server.Port()),
		dnsutil.Canonical(q.Header().Name), dns.RRToType(q), q.Header().Class,
		req.Opcode, req.RecursionDesired, req.CheckingDisabled,
		req.UDPSize, req.Version, req.Security, req.Z, strings.Join(options, ","))
}

// silence is a server that said nothing when the capture was made, which a
// replay has to read as the timeout it was.
type silence struct{ text string }

func (s *silence) Error() string   { return s.text }
func (s *silence) Timeout() bool   { return true }
func (s *silence) Temporary() bool { return false }
