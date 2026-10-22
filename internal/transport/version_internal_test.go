package transport

import (
	"strings"
	"testing"
)

// FuzzClipEscaped reads clipped text back as escaped text: printable ASCII
// only, every backslash the start of a whole escape, no longer than the limit
// and the mark of the cut. Text that already fits, as the codec escapes it,
// comes back as it was.
func FuzzClipEscaped(f *testing.F) {
	f.Add(`9.18.24-1ubuntu1.1-Ubuntu`, 48)
	f.Add(`a\027[31m\"q\ \195\169\010`, 12)
	f.Add("raw \x1b[2J and a trailing \\", 10)
	f.Fuzz(func(t *testing.T, text string, limit int) {
		limit = max(0, limit%256)
		clipped := clipEscaped(text, limit)
		inner, cut := strings.CutSuffix(clipped, "...")
		if len(inner) > limit {
			t.Fatalf("%q is %d bytes, over %d", clipped, len(inner), limit)
		}
		for i := 0; i < len(inner); i++ {
			switch c := inner[i]; {
			case !printable(c):
				t.Fatalf("%q holds %q at %d", clipped, c, i)
			case c != '\\':
			case i+3 < len(inner) && isDigits(inner[i+1:i+4]):
				i += 3
			case i+1 < len(inner):
				i++
			default:
				t.Fatalf("%q ends in half an escape", clipped)
			}
		}
		if !cut && len(text) <= limit && text == clipEscaped(text, len(text)) && clipped != text {
			t.Fatalf("%q came back as %q", text, clipped)
		}
	})
}
