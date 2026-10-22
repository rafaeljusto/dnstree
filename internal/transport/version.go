package transport

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
)

// VersionNames are where a server is asked which software it runs, in the
// order they are asked: BIND's name, then the one other servers answer to.
// They are a convention, not a standard.
var VersionNames = []string{"version.bind.", "version.server."}

// MaxVersion is how much of what a server says it runs is kept.
const MaxVersion = 48

// Chaos moves a query into the CHAOS class, where a server answers questions
// about itself rather than about a zone. Signatures have nothing to say there.
func Chaos(req *dns.Msg) {
	req.Question[0].Header().Class = dns.ClassCHAOS
	req.Security = false
}

// SaidVersion is the text a server answered a question of VersionNames with,
// and whether it answered with any. The text is free and the server's alone:
// often a version, as often a joke or a lie. It arrives escaped by the codec,
// so it is clipped without cutting an escape in half.
func SaidVersion(resp *dns.Msg) (string, bool) {
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return "", false
	}
	var said []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			said = append(said, txt.Txt...)
		}
	}
	text := strings.TrimSpace(strings.Join(said, " "))
	return clipEscaped(text, MaxVersion), text != ""
}

// clipEscaped bounds escaped text to limit bytes, and says where it was cut.
// An escape is \DDD or a backslash and the byte after it, and is kept whole
// or not at all. Anything outside printable ASCII is escaped on the way, in
// case the text did not come from the codec.
func clipEscaped(text string, limit int) string {
	var b strings.Builder
	for i, used := 0, 0; i < len(text); i += used {
		token := text[i : i+1]
		used = 1
		switch {
		case !printable(text[i]):
			token = fmt.Sprintf("\\%03d", text[i])
		case text[i] != '\\':
		case i+3 < len(text) && isDigits(text[i+1:i+4]):
			token, used = text[i:i+4], 4
		case i+1 < len(text) && printable(text[i+1]):
			token, used = text[i:i+2], 2
		default:
			token = `\\`
		}
		if b.Len()+len(token) > limit {
			b.WriteString("...")
			break
		}
		b.WriteString(token)
	}
	return b.String()
}

func printable(c byte) bool { return c >= ' ' && c <= '~' }

func isDigits(s string) bool {
	return strings.Trim(s, "0123456789") == ""
}
