package tree

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// walk is a trace of hops hanging one under the other, as a live drawing sees
// it: the same tree, a step taller each time.
func walk(hops int) *trace.Trace {
	root := &trace.Step{Zone: ".", Kind: trace.KindZone}
	parent := root
	for i := range hops {
		step := &trace.Step{
			Zone:   ".",
			Server: trace.Server{Name: "ns.example.com.", IP: netip.MustParseAddr("192.0.2.1"), Port: 53},
			Rcode:  "NOERROR",
			Kind:   trace.KindReferral,
			Delegation: &trace.Delegation{
				Zone: strings.Repeat("a", i+1) + ".",
			},
		}
		parent.Children = append(parent.Children, step)
		parent = step
	}
	return &trace.Trace{Root: root}
}

func TestLiveDraw(t *testing.T) {
	var buf bytes.Buffer
	live := &Live{w: &buf, opts: Options{Color: ColorNever}}

	live.draw(walk(1))
	first := buf.String()
	if !strings.HasPrefix(first, hideCursor) {
		t.Errorf("got %q, want the cursor hidden first", first)
	}
	if strings.Contains(first, cursorUp) {
		t.Errorf("got %q, want no going up over a frame that is not there", first)
	}
	if got, want := live.rows, 2; got != want {
		t.Errorf("got %d rows, want %d", got, want)
	}

	// The next frame starts by going back over the one before it, so that it is
	// drawn where it stood.
	buf.Reset()
	live.draw(walk(2))
	second := buf.String()
	if want := strings.Repeat(cursorUp, 2) + "\r"; !strings.HasPrefix(second, want) {
		t.Errorf("got %q, want it to start %q", second, want)
	}
	if got, want := strings.Count(second, eraseLine), 3; got != want {
		t.Errorf("got %d lines wiped, want %d", got, want)
	}
	if !strings.HasSuffix(second, eraseBelow) {
		t.Errorf("got %q, want the frame before it wiped off below", second)
	}

	buf.Reset()
	live.Clear()
	want := strings.Repeat(cursorUp, 3) + "\r" + eraseBelow + showCursor
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if live.rows != 0 {
		t.Errorf("got %d rows still on screen, want none", live.rows)
	}
}

// TestLiveDrawTall guards the screen: a frame taller than the terminal would
// scroll the top of itself away, and the next redraw would go up into whatever
// took its place.
func TestLiveDrawTall(t *testing.T) {
	var buf bytes.Buffer
	live := &Live{w: &buf, opts: Options{Color: ColorNever}}
	live.draw(walk(fallbackHeight * 2))

	if got, want := live.rows, fallbackHeight-1; got != want {
		t.Errorf("got %d rows, want %d", got, want)
	}
	if lines := strings.Split(buf.String(), "\n"); !strings.Contains(lines[0], elision) {
		t.Errorf("got %q, want the hops that did not fit spoken for", lines[0])
	}
}

func TestLiveDrawThrottle(t *testing.T) {
	var buf bytes.Buffer
	live := &Live{w: &buf, opts: Options{Color: ColorNever}}

	live.Draw(walk(1))
	if buf.Len() == 0 {
		t.Fatal("got nothing drawn, want the first frame")
	}

	buf.Reset()
	live.Draw(walk(2))
	if buf.Len() != 0 {
		t.Errorf("got %q, want nothing so soon after the frame before", buf.String())
	}

	live.last = time.Now().Add(-redrawEvery)
	live.Draw(walk(2))
	if buf.Len() == 0 {
		t.Error("got nothing drawn, want the frame once the moment has passed")
	}
}

// TestLiveNowhere covers the writer nobody is watching, which is every writer a
// test or a pipe has.
func TestLiveNowhere(t *testing.T) {
	var buf bytes.Buffer
	live := NewLive(&buf, Options{})
	if live != nil {
		t.Fatalf("got %v, want no drawing on something that is not a terminal", live)
	}

	live.Draw(walk(1)) // a nil drawing draws nothing, rather than panicking
	live.Clear()
	if buf.Len() != 0 {
		t.Errorf("got %q, want nothing", buf.String())
	}
}

func TestTruncate(t *testing.T) {
	tests := map[string]struct {
		line  string
		cells int
		want  string
	}{
		"shorter than the screen": {line: "example.com.", cells: 20, want: "example.com."},
		"exactly the screen":      {line: "example.com.", cells: 12, want: "example.com."},
		"the ellipsis fits too":   {line: "example.com.", cells: 7, want: "exampl…"},
		"colour is free":          {line: grey + "example.com." + reset, cells: 12, want: grey + "example.com." + reset},
		"a cut closes the colour": {line: grey + "example.com." + reset, cells: 7, want: grey + "exampl…" + reset},
		"an emoji takes two":      {line: "🌍 ab", cells: 3, want: "🌍…"},
		"a joined emoji is two":   {line: "🛰️ ab", cells: 5, want: "🛰️ ab"},
		"nowhere to cut":          {line: "example.com.", cells: 0, want: "…"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := truncate(test.line, test.cells); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestTruncateFits is the promise the redraw rests on: whatever comes back is
// drawn inside the screen, so no line wraps onto a row the next frame does not
// know about.
func TestTruncateFits(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, walk(8), Options{Charset: Emoji, Color: ColorAlways}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	for _, line := range strings.Split(buf.String(), "\n") {
		for _, cells := range []int{1, 8, 40, 79} {
			if got := width(truncate(line, cells)); got > cells {
				t.Errorf("got %d columns of %q, want at most %d", got, line, cells)
			}
		}
	}
}

// width is what truncate counts, spelled out again so that the test does not
// simply agree with the code it is checking.
func width(s string) int {
	for _, code := range strings.Split(s, "\x1b[")[1:] {
		if end := strings.IndexFunc(code, func(r rune) bool { return r >= '@' && r <= '~' }); end >= 0 {
			s = strings.Replace(s, "\x1b["+code[:end+1], "", 1)
		}
	}

	var (
		width    int
		previous rune
	)
	for _, r := range s {
		width += cellWidth(r, previous)
		previous = r
	}
	return width
}
