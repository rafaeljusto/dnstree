package markdown

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// FuzzEscape reads escaped text back the way CommonMark does, a backslash
// before ASCII punctuation being that character, over the text it is handed:
// what Shown made of a zone's words. Whatever the text, it comes back whole,
// none of the characters that mean something inline is left bare, and the
// text cannot open a heading, a list or a quote.
func FuzzEscape(f *testing.F) {
	f.Add("www.example.com.")
	f.Add("# heading")
	f.Add("12. not a list | `code` *em* [link](x) <b> ~~s~~ &amp; \\")
	f.Add("-1) x")
	f.Fuzz(func(t *testing.T, text string) {
		text = trace.Shown(text)
		escaped := escape(text)

		var read strings.Builder
		var bare []int // where unescaped characters land in what is read back
		for i := 0; i < len(escaped); i++ {
			c := escaped[i]
			if c == '\\' && i+1 < len(escaped) && strings.IndexByte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", escaped[i+1]) >= 0 {
				i++
				read.WriteByte(escaped[i])
				continue
			}
			if strings.IndexByte("\\`*_[]<>|~&", c) >= 0 {
				t.Fatalf("%q leaves %q bare at %d", escaped, c, i)
			}
			bare = append(bare, read.Len())
			read.WriteByte(c)
		}
		if read.String() != text {
			t.Fatalf("%q reads back as %q", text, read.String())
		}

		if len(bare) > 0 && bare[0] == 0 && strings.IndexByte("#+->", text[0]) >= 0 {
			t.Fatalf("%q opens a line with %q", escaped, text[0])
		}
		digits := len(text) - len(strings.TrimLeft(text, "0123456789"))
		if digits > 0 && digits+1 < len(text) && strings.IndexByte(".)", text[digits]) >= 0 && text[digits+1] == ' ' &&
			strings.HasPrefix(escaped, text[:digits+1]) {
			t.Fatalf("%q opens a numbered list", escaped)
		}
	})
}
