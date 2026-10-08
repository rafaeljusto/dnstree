package mermaid

import (
	"strings"
	"testing"
)

// entities are what quote writes for the characters Mermaid or a GitHub page
// would otherwise read.
var entities = map[string]string{
	"#quot;": `"`, "#35;": "#", "#lt;": "<", "#gt;": ">", "#amp;": "&", "#96;": "`", "<br/>": "\n",
}

// FuzzQuote reads a quoted label back entity by entity. Whatever the text, it
// comes back whole, and the string holds no quote, tag, backtick, ampersand or
// line break of its own, nor a # that starts anything but the entities quote
// writes.
func FuzzQuote(f *testing.F) {
	f.Add("www.example.com.")
	f.Add("a \"b\" #35; <br/> & `c`\nwarning: <script>")
	f.Fuzz(func(t *testing.T, text string) {
		text = strings.ToValidUTF8(text, "?")
		quoted := quote(text)
		inner, opened := strings.CutPrefix(quoted, `"`)
		inner, closed := strings.CutSuffix(inner, `"`)
		if !opened || !closed {
			t.Fatalf("%q is not quoted", quoted)
		}
		var read strings.Builder
	scan:
		for i := 0; i < len(inner); {
			for entity, c := range entities {
				if strings.HasPrefix(inner[i:], entity) {
					read.WriteString(c)
					i += len(entity)
					continue scan
				}
			}
			if c := inner[i]; strings.IndexByte("\"#<>&`\n", c) >= 0 {
				t.Fatalf("%q holds a raw %q at %d", quoted, c, i+1)
			}
			read.WriteByte(inner[i])
			i++
		}
		if read.String() != text {
			t.Fatalf("%q reads back as %q", text, read.String())
		}
	})
}
