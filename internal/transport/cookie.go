package transport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// The sizes RFC 7873 section 4 gives the two halves of a cookie.
const (
	clientCookieSize   = 8
	minServerCookieLen = 8
	maxServerCookieLen = 32
)

// ClientCookie is the client half of a DNS cookie for one server, hex encoded.
// It is derived from the server's address, so that no two servers are handed
// the same value to follow a client between them with (RFC 9018 appendix A).
func ClientCookie(secret []byte, server netip.Addr) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(server.Unmap().AsSlice())
	return hex.EncodeToString(mac.Sum(nil)[:clientCookieSize])
}

// WithCookie attaches a DNS cookie to a query: the client half, and the server
// half when the server has handed one out. Like every option it needs EDNS0 to
// ride in, so a query asked without it is left alone.
func WithCookie(req *dns.Msg, client, server string) {
	if req.UDPSize == 0 || client == "" {
		return
	}
	req.Pseudo = append(req.Pseudo, &dns.COOKIE{Cookie: client + server})
}

// EchoedCookie is how a server answered the cookie it was sent, and the server
// cookie to send it next time where it answered properly. The codec takes any
// length, so the lengths are checked here.
func EchoedCookie(resp *dns.Msg, client string) (trace.CookieState, string) {
	if resp == nil {
		return trace.CookieAbsent, ""
	}
	for _, rr := range resp.Pseudo {
		cookie, ok := rr.(*dns.COOKIE)
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(cookie.Cookie)
		size := len(raw) - clientCookieSize
		if err != nil || size < minServerCookieLen || size > maxServerCookieLen {
			return trace.CookieMalformed, ""
		}
		sent, err := hex.DecodeString(client)
		if err != nil || !bytes.Equal(raw[:clientCookieSize], sent) {
			return trace.CookieMismatch, ""
		}
		return trace.CookieSupported, hex.EncodeToString(raw[clientCookieSize:])
	}
	return trace.CookieAbsent, ""
}

// CarriesCookie reports whether a transport is one a cookie means anything
// over. The encrypted ones prove the address with a handshake already, and an
// HTTPS front end may drop the option, which would read as a server without.
func CarriesCookie(proto string) bool {
	return proto == ProtoUDP || proto == ProtoTCP
}
