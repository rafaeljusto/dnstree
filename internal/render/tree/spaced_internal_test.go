package tree

import "testing"

func TestSpaced(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		icon, want string
	}{
		"an emoji by default gets one space":                          {"🧭", "🧭 "},
		"a symbol from before the emoji blocks, with a selector, two": {"⚠️", "⚠️  "},
		"a pictograph that is text by default, with a selector, two":  {"🕸️", "🕸️  "},
		"a record icon that is text by default, with a selector, two": {"🗂️", "🗂️  "},
		"a symbol from before the emoji blocks that needs none, one":  {"⚡", "⚡ "},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := spaced(tt.icon); got != tt.want {
				t.Errorf("spaced(%q) = %q, want %q", tt.icon, got, tt.want)
			}
		})
	}
}
