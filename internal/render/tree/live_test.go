package tree

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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

// tailRows is what every frame carries under the tree: a blank line and the
// footer, and nothing waiting for an answer.
const tailRows = 2

func TestLiveDraw(t *testing.T) {
	var buf bytes.Buffer
	live := newLive(&buf, Options{Color: ColorNever})

	live.draw(walk(1))
	first := buf.String()
	if !strings.HasPrefix(first, hideCursor) {
		t.Errorf("got %q, want the cursor hidden first", first)
	}
	if strings.Contains(first, cursorUp) {
		t.Errorf("got %q, want no going up over a frame that is not there", first)
	}
	if got, want := live.rows, 2+tailRows; got != want {
		t.Errorf("got %d rows, want %d", got, want)
	}

	// The next frame starts by going back over the one before it, so that it is
	// drawn where it stood.
	buf.Reset()
	live.draw(walk(2))
	second := buf.String()
	if want := strings.Repeat(cursorUp, 2+tailRows) + "\r"; !strings.HasPrefix(second, want) {
		t.Errorf("got %q, want it to start %q", second, want)
	}
	if got, want := strings.Count(second, eraseLine), 3+tailRows; got != want {
		t.Errorf("got %d lines wiped, want %d", got, want)
	}
	if !strings.HasSuffix(second, eraseBelow) {
		t.Errorf("got %q, want the frame before it wiped off below", second)
	}

	buf.Reset()
	live.Clear()
	want := strings.Repeat(cursorUp, 3+tailRows) + "\r" + eraseBelow + showCursor
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
	live := newLive(&buf, Options{Color: ColorNever})
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
	live := newLive(&buf, Options{Color: ColorNever})

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

	// A nil drawing does nothing, rather than panicking.
	live.Draw(walk(1))
	if done := live.Asking(".", trace.Server{}); done != nil {
		t.Error("got something to call back, want nothing from a drawing that is not there")
	}
	live.Summary(&buf, walk(1))
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
		"shorter than the screen":  {line: "example.com.", cells: 20, want: "example.com."},
		"exactly the screen":       {line: "example.com.", cells: 12, want: "example.com."},
		"the ellipsis fits too":    {line: "example.com.", cells: 7, want: "exampl…"},
		"colour is free":           {line: grey + "example.com." + reset, cells: 12, want: grey + "example.com." + reset},
		"a cut closes the colour":  {line: grey + "example.com." + reset, cells: 7, want: grey + "exampl…" + reset},
		"an emoji takes two":       {line: "🌍 ab", cells: 3, want: "🌍…"},
		"so does CJK past the BMP": {line: "\U00020000\U00020001ab", cells: 3, want: "\U00020000…"},
		"and a flag's half":        {line: "\U0001F1FA\U0001F1F8ab", cells: 3, want: "\U0001F1FA…"},
		"a joined emoji is two":    {line: "🛰️ ab", cells: 5, want: "🛰️ ab"},
		"nowhere to cut":           {line: "example.com.", cells: 0, want: "…"},
		"a joiner gives no room back": {line: strings.Repeat("A\u200d", 8), cells: 4,
			want: strings.Repeat("A\u200d", 3) + "…"},
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

	for line := range strings.SplitSeq(buf.String(), "\n") {
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

// TestLiveAsking covers what Stepped cannot say: between one hop and the next
// the trace does not change at all, and the only sign that a walk is waiting
// rather than wedged is the query it is waiting on.
func TestLiveAsking(t *testing.T) {
	var buf bytes.Buffer
	live := newLive(&buf, Options{Color: ColorNever})

	done := live.Asking("com.", trace.Server{
		Name: "b.gtld-servers.net.", IP: netip.MustParseAddr("192.33.14.30"), Port: 53,
	})
	live.draw(walk(1))

	frame := buf.String()
	if want := "asking b.gtld-servers.net. 192.33.14.30"; !strings.Contains(frame, want) {
		t.Errorf("got %q, want it to carry %q", frame, want)
	}
	if want := "1 query"; !strings.Contains(frame, want) {
		t.Errorf("got %q, want it to carry %q", frame, want)
	}
	if got, want := live.tail, tailRows+1; got != want {
		t.Errorf("got %d rows that move on their own, want %d", got, want)
	}

	// An answer takes the query off the screen, but not off the tally.
	done()
	buf.Reset()
	live.draw(walk(1))
	frame = buf.String()
	if strings.Contains(frame, "asking") {
		t.Errorf("got %q, want nothing in flight once it has come back", frame)
	}
	if want := "1 query"; !strings.Contains(frame, want) {
		t.Errorf("got %q, want it to carry %q", frame, want)
	}
	if want := "1 server"; !strings.Contains(frame, want) {
		t.Errorf("got %q, want it to carry %q", frame, want)
	}
}

// TestLiveNamesAreEscaped covers the names a server hands out, which reach the
// tail and the crumbs without going through a tree. A frame is escapes of its
// own, so what matters is that none of the server's gets through.
func TestLiveNamesAreEscaped(t *testing.T) {
	const forged = "ns\x1b[3A\x1b[2K.example."
	var buf bytes.Buffer
	live := newLive(&buf, Options{Color: ColorNever})

	live.Asking(forged, trace.Server{Name: forged, IP: netip.MustParseAddr("192.0.2.1"), Port: 53})
	tr := walk(1)
	tr.Root.Children[0].Delegation.Zone = forged
	live.draw(tr)

	if frame := buf.String(); strings.Contains(frame, "\x1b[3A") {
		t.Errorf("got %q, want the server's escape kept off the screen", frame)
	}
	if got := live.crumbs(tr); strings.Contains(got, "\x1b") {
		t.Errorf("got crumbs %q, want them escaped", got)
	}
}

// TestLiveAskingMany is --all: more queries in flight than there is room to
// name, which are counted instead so that the tail stays a tail.
func TestLiveAskingMany(t *testing.T) {
	var buf bytes.Buffer
	live := newLive(&buf, Options{Color: ColorNever})

	for i := range maxPending + 2 {
		live.Asking("com.", trace.Server{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
	}
	live.draw(walk(1))

	frame := buf.String()
	if got, want := strings.Count(frame, "asking"), maxPending; got != want {
		t.Errorf("got %d queries named in %q, want %d", got, frame, want)
	}
	if want := "and 2 more in flight"; !strings.Contains(frame, want) {
		t.Errorf("got %q, want it to carry %q", frame, want)
	}
}

// TestLiveTick is the cheap redraw: the tree has not moved, so the cursor goes
// back over the tail alone and leaves everything above it where it is.
func TestLiveTick(t *testing.T) {
	var buf bytes.Buffer
	live := newLive(&buf, Options{Color: ColorNever})

	live.tick() // nothing has been drawn, so there is nothing to go back over
	if buf.Len() != 0 {
		t.Errorf("got %q, want nothing before the first frame", buf.String())
	}

	live.draw(walk(2))
	rows := live.rows
	buf.Reset()

	live.tick()
	ticked := buf.String()
	if want := strings.Repeat(cursorUp, tailRows) + "\r"; !strings.HasPrefix(ticked, want) {
		t.Errorf("got %q, want it to start %q", ticked, want)
	}
	if got, want := strings.Count(ticked, eraseLine), tailRows; got != want {
		t.Errorf("got %d lines wiped, want %d", got, want)
	}
	if got, want := live.rows, rows; got != want {
		t.Errorf("got %d rows, want the %d that were there", got, want)
	}
}

func TestLiveSummary(t *testing.T) {
	answer := func() *trace.Trace {
		tr := walk(1)
		tr.Root.Children[0].Kind = trace.KindAnswer
		tr.Elapsed = 412 * time.Millisecond
		return tr
	}

	tests := map[string]struct {
		trace *trace.Trace
		want  string
	}{
		"answered": {trace: answer(), want: "answered in 412ms"},
		"nothing answered": {
			trace: &trace.Trace{Root: walk(1).Root, Elapsed: 3 * time.Second},
			want:  "no answer in 3s",
		},
		"a broken chain outranks the answer": {
			trace: func() *trace.Trace {
				tr := answer()
				tr.Root.Children[0].DNSSEC = &trace.DNSSECStatus{State: trace.Bogus}
				return tr
			}(),
			want: "bogus in 412ms",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			live := newLive(&buf, Options{Color: ColorNever})
			live.Asking(".", trace.Server{IP: netip.MustParseAddr("192.0.2.1")})
			live.Summary(&buf, test.trace)

			got := buf.String()
			if !strings.Contains(got, test.want) {
				t.Errorf("got %q, want it to carry %q", got, test.want)
			}
			if want := "1 query · 1 server"; !strings.Contains(got, want) {
				t.Errorf("got %q, want it to carry %q", got, want)
			}
			if !strings.HasSuffix(got, "\n") {
				t.Errorf("got %q, want a line of its own", got)
			}
		})
	}
}

// TestLiveCrumbs is the walk so far, read off the branch it is working on.
func TestLiveCrumbs(t *testing.T) {
	live := newLive(&bytes.Buffer{}, Options{Color: ColorNever})

	if got := live.crumbs(walk(2)); got != ". → a. → aa." {
		t.Errorf("got %q, want the zones it went through", got)
	}
	if got, want := live.crumbs(walk(maxCrumbs+2)), elision+" → "; !strings.HasPrefix(got, want) {
		t.Errorf("got %q, want it to start %q, since only the end of a long walk fits", got, want)
	}
	if got := live.crumbs(nil); got != "" {
		t.Errorf("got %q, want nothing from a walk that has not started", got)
	}
}

// TestNewest is what a frame points at. Children are appended as they are made
// and a parent is always older than its children, so the hop that joined last
// is at the end of the chain of last children — counting only the ones the walk
// went through.
func TestNewest(t *testing.T) {
	tr := walk(3)
	deepest := tr.Root.Children[0].Children[0].Children[0]
	if got := newest(tr); got != deepest {
		t.Errorf("got %v, want the hop at the bottom of the walk", got)
	}

	// The servers a hop did not need are attached after the one that answered.
	// Pointing at those would walk the mark back up the tree every time.
	tr.Root.Children = append(tr.Root.Children, &trace.Step{Zone: ".", Kind: trace.KindSkipped})
	if got := newest(tr); got != deepest {
		t.Errorf("got %v, want the hop the walk went through", got)
	}

	// A sibling that was queried is newer than the one before it.
	sibling := &trace.Step{Zone: ".", Kind: trace.KindTimeout}
	tr.Root.Children = append(tr.Root.Children, sibling)
	if got := newest(tr); got != sibling {
		t.Errorf("got %v, want the hop that joined last", got)
	}

	if got := newest(&trace.Trace{Root: &trace.Step{Zone: "."}}); got != nil {
		t.Errorf("got %v, want nothing pointed at before the first hop", got)
	}
	if got := newest(nil); got != nil {
		t.Errorf("got %v, want nothing", got)
	}
}

// TestLiveCrumbsAside covers the detours: chasing a nameserver's address is a
// walk of its own, and the zone it is about is not how far this one has come.
func TestLiveCrumbsAside(t *testing.T) {
	live := newLive(&bytes.Buffer{}, Options{Color: ColorNever})

	tr := walk(1)
	hop := tr.Root.Children[0]
	hop.Children = append(hop.Children,
		&trace.Step{Zone: "net.", Kind: trace.KindZone, Aside: true},
		&trace.Step{Zone: "a.", Kind: trace.KindSkipped},
	)
	if got, want := live.crumbs(tr), ". → a."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
