package tree

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// How a live drawing moves around the screen: back up over the frame it drew
// last, wiping each line as it writes the new one over it.
const (
	cursorUp   = "\x1b[A"
	eraseLine  = "\x1b[K"
	eraseBelow = "\x1b[J"
	hideCursor = "\x1b[?25l"
	showCursor = "\x1b[?25h"
)

// redrawEvery bounds how often the screen is rewritten. A walk can attach
// several hops within a millisecond, and nobody can read that.
const redrawEvery = 40 * time.Millisecond

// What a terminal that will not say its size is taken to be.
const (
	fallbackWidth  = 80
	fallbackHeight = 24
)

// elision stands in for the hops that scrolled off the top of a frame too tall
// for the screen.
const elision = "⋮"

// Live draws a trace over and over in the same place, so that a walk can be
// watched while it is being made. Its frames are scratch: Clear takes the last
// one off the screen and leaves the cursor where the frame began, for the
// caller to write the finished tree exactly where it stood.
//
// A nil *Live draws nothing, which is what a writer nobody is watching gets.
type Live struct {
	w    io.Writer
	opts Options

	mu   sync.Mutex
	rows int       // screen lines the frame now on screen takes
	last time.Time // when it was drawn
	hid  bool      // whether the cursor is ours to give back
}

// NewLive returns a drawing on w, or nil when w is not a terminal: cursor
// movement only means something to someone watching it.
func NewLive(w io.Writer, opts Options) *Live {
	if !IsTerminal(w) {
		return nil
	}

	// Colour is decided here, against the terminal, because the frames
	// themselves are rendered into a buffer that would never ask for it.
	color := ColorNever
	if colorEnabled(w, opts.Color) {
		color = ColorAlways
	}
	opts.Color = color
	return &Live{w: w, opts: opts}
}

// Draw puts the trace on the screen over the frame before it, unless one was
// drawn a moment ago. It is meant to be called from the goroutine building the
// trace, which is the only one that may read it.
func (l *Live) Draw(tr *trace.Trace) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.last.IsZero() && time.Since(l.last) < redrawEvery {
		return
	}
	l.draw(tr)
}

// Clear wipes the frame and gives the cursor back.
func (l *Live) Clear() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	var out strings.Builder
	if l.rows > 0 {
		out.WriteString(strings.Repeat(cursorUp, l.rows) + "\r" + eraseBelow)
	}
	if l.hid {
		out.WriteString(showCursor)
		l.hid = false
	}
	_, _ = io.WriteString(l.w, out.String())
	l.rows, l.last = 0, time.Time{}
}

// draw writes one frame. Every line is cut to the width of the screen, since a
// line that wrapped would take two rows and the next frame would come back up
// one row short, smearing the drawing down the terminal.
func (l *Live) draw(tr *trace.Trace) {
	var buf bytes.Buffer
	if err := Render(&buf, tr, l.opts); err != nil {
		return
	}

	width, height := terminalSize(l.w)
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if room := height - 1; len(lines) > room {
		lines = append([]string{elision}, lines[len(lines)-room+1:]...)
	}

	var out strings.Builder
	if !l.hid {
		out.WriteString(hideCursor)
		l.hid = true
	}
	out.WriteString(strings.Repeat(cursorUp, l.rows) + "\r")
	for _, line := range lines {
		out.WriteString(truncate(line, width-1) + eraseLine + "\n")
	}
	out.WriteString(eraseBelow) // whatever a taller frame left behind

	if _, err := io.WriteString(l.w, out.String()); err != nil {
		return
	}
	l.rows, l.last = len(lines), time.Now()
}

// truncate cuts a line down to cells columns, counting what the terminal
// shows rather than what the string holds: escapes take no room, and an emoji
// takes two. A cut line keeps its colour from running on.
func truncate(line string, cells int) string {
	cells = max(cells, 1)

	var (
		width    int
		escaped  bool
		previous rune
		fits     int // where a cut leaves room for the ellipsis
	)
	for i := 0; i < len(line); {
		if skip := escape(line[i:]); skip > 0 {
			escaped, i = true, i+skip
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		if width < cells {
			fits = i
		}
		w := cellWidth(r, previous)
		if width+w > cells {
			cut := line[:fits] + "…"
			if escaped {
				cut += reset
			}
			return cut
		}
		width, previous, i = width+w, r, i+size
	}
	return line
}

// escape reports how many bytes of a CSI sequence start s, so that the cursor
// and colour codes in a line are not counted as anything on screen.
func escape(s string) int {
	if len(s) < 2 || s[0] != 0x1b {
		return 0
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; i > 1 && c >= '@' && c <= '~' {
			return i + 1
		}
	}
	return len(s)
}

// cellWidth is how many columns a rune adds to the one before it. It rounds up
// rather than down: guessing a glyph wider than it is costs a column of the
// frame, guessing it narrower wraps the line and breaks the next redraw.
func cellWidth(r, previous rune) int {
	switch {
	case r == 0x200d: // a joiner welds the glyphs either side of it into one
		return -2
	case r == 0xfe0f: // and this draws the one before it as an emoji
		if wide(previous) {
			return 0
		}
		return 1
	case r < 0x20 || (r >= 0x300 && r <= 0x36f): // control and combining marks
		return 0
	case wide(r):
		return 2
	default:
		return 1
	}
}

// wide reports whether a rune is drawn over two columns: the emoji blocks and
// the East Asian ones.
func wide(r rune) bool {
	switch {
	case r >= 0x1f300 && r <= 0x1faff: // pictographs, emoticons, transport, symbols
		return true
	case r >= 0x2600 && r <= 0x27bf: // miscellaneous symbols and dingbats
		return true
	case r >= 0x23e9 && r <= 0x23fa: // the clocks and the media controls
		return true
	case r >= 0x1100 && r <= 0x115f, r >= 0x2e80 && r <= 0xa4cf: // Hangul, CJK
		return true
	case r >= 0xac00 && r <= 0xd7a3, r >= 0xf900 && r <= 0xfaff:
		return true
	case r >= 0xfe30 && r <= 0xfe6f, r >= 0xff00 && r <= 0xff60:
		return true
	default:
		return false
	}
}
