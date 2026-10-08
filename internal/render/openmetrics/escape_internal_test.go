package openmetrics

import (
	"strings"
	"testing"
)

// FuzzEscape reads a label value back the way both exposition formats do: \\,
// \" and \n are the only escapes, and a bare quote or line break would end the
// value or the sample early. Whatever the text, it comes back whole.
func FuzzEscape(f *testing.F) {
	f.Add("www.example.com.")
	f.Add("a \"b\" \\123 c\nd\\")
	f.Fuzz(func(t *testing.T, text string) {
		escaped := escape(text)
		var read strings.Builder
		for i := 0; i < len(escaped); i++ {
			switch c := escaped[i]; c {
			case '"', '\n':
				t.Fatalf("%q holds a raw %q at %d", escaped, c, i)
			case '\\':
				if i++; i == len(escaped) {
					t.Fatalf("%q ends in a lone backslash", escaped)
				}
				switch escaped[i] {
				case '\\', '"':
					read.WriteByte(escaped[i])
				case 'n':
					read.WriteByte('\n')
				default:
					t.Fatalf("%q holds \\%c, which neither format reads", escaped, escaped[i])
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
