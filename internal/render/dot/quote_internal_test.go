package dot

import (
	"strings"
	"testing"
)

// FuzzQuote reads a quoted label back the way Graphviz does: a backslash takes
// the byte after it, \n is a line break, and only the last quote ends the
// string. Whatever the text, it comes back whole and nothing in it ends the
// string early.
func FuzzQuote(f *testing.F) {
	f.Add("www.example.com.")
	f.Add("a \"quoted\" \\ name\\n\nwarning: x\\")
	f.Fuzz(func(t *testing.T, text string) {
		text = strings.ToValidUTF8(text, "?")
		quoted := quote(text)
		inner, opened := strings.CutPrefix(quoted, `"`)
		inner, closed := strings.CutSuffix(inner, `"`)
		if !opened || !closed {
			t.Fatalf("%q is not quoted", quoted)
		}
		var read strings.Builder
		for i := 0; i < len(inner); i++ {
			switch c := inner[i]; c {
			case '"', '\n':
				t.Fatalf("%q holds a raw %q at %d", quoted, c, i+1)
			case '\\':
				if i++; i == len(inner) {
					t.Fatalf("%q escapes its own closing quote", quoted)
				}
				if inner[i] == 'n' {
					read.WriteByte('\n')
				} else {
					read.WriteByte(inner[i])
				}
			default:
				read.WriteByte(c)
			}
		}
		if read.String() != text {
			t.Fatalf("%q reads back as %q", text, read.String())
		}
	})
}
