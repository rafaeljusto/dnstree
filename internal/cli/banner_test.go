package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/cli"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
)

func TestWriteVersion(t *testing.T) {
	tests := map[string]struct {
		charset tree.Charset
		mode    tree.ColorMode
	}{
		// A bytes.Buffer is not a terminal, so auto is what a pipe sees.
		"a pipe gets the one line an install script can parse": {
			charset: tree.Unicode,
			mode:    tree.ColorAuto,
		},
		"colour turned off by hand gets the same line": {
			charset: tree.Unicode,
			mode:    tree.ColorNever,
		},
		"the charset does not bring the mark back": {
			charset: tree.ASCII,
			mode:    tree.ColorAuto,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			cli.WriteVersion(&buf, "1.2.3", test.charset, test.mode)
			if got, want := buf.String(), "dnstree 1.2.3\n"; got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestWriteVersionDrawsTheMark(t *testing.T) {
	tests := map[string]struct {
		charset tree.Charset
		rows    int
	}{
		"a terminal that can draw gets the braille mark": {charset: tree.Unicode, rows: 9},
		"emoji is no reason to fall back":                {charset: tree.Emoji, rows: 9},
		"ascii asks for the mark that needs no font":     {charset: tree.ASCII, rows: 6},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			cli.WriteVersion(&buf, "1.2.3", test.charset, tree.ColorAlways)
			got := buf.String()

			if !strings.Contains(got, "dnstree 1.2.3") {
				t.Errorf("got %q, want the version in it", got)
			}
			if !strings.Contains(got, "\x1b[94m") {
				t.Errorf("got %q, want it painted in the accent the mark uses", got)
			}
			if rows := strings.Count(got, "\n"); rows != test.rows {
				t.Errorf("got %d rows, want the %d the mark is drawn in", rows, test.rows)
			}
			for line := range strings.SplitSeq(got, "\n") {
				if strings.HasSuffix(line, " ") {
					t.Errorf("got %q, want no trailing blanks: they show when a line is selected", line)
				}
				if strings.ContainsRune(line, '⠀') {
					t.Errorf("got %q, want spaces rather than blank braille cells", line)
				}
			}
		})
	}
}

// The ascii mark is the one for a terminal running any font at all, so it stays
// inside ASCII for the reason --format ascii does. The braille mark is the one
// that is allowed to ask for more, which is the whole reason there are two.
func TestWriteVersionMarkCharsets(t *testing.T) {
	var ascii bytes.Buffer
	cli.WriteVersion(&ascii, "1.2.3", tree.ASCII, tree.ColorAlways)
	for _, r := range ascii.String() {
		if r > 127 {
			t.Errorf("got %q, want nothing above codepoint 127", r)
		}
	}

	var braille bytes.Buffer
	cli.WriteVersion(&braille, "1.2.3", tree.Unicode, tree.ColorAlways)
	if !strings.ContainsFunc(braille.String(), func(r rune) bool { return r >= 0x2801 && r <= 0x28ff }) {
		t.Error("got no braille in the default mark, want the detail it is there for")
	}
}
