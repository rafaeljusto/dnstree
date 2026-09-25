package tree

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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

// redrawEvery bounds how often the tree is rewritten. A walk can attach
// several hops within a millisecond, and nobody can read that.
const redrawEvery = 40 * time.Millisecond

// tickEvery is how often the bottom of the frame is rewritten on its own. The
// tree only moves when a hop lands, which can be a whole timeout away; the
// spinner, the clock and the queries in flight have to keep moving through
// that, or a walk waiting on a silent server reads as a walk that has hung.
const tickEvery = 80 * time.Millisecond

// What a terminal that will not say its size is taken to be.
const (
	fallbackWidth  = 80
	fallbackHeight = 24
)

// elision stands in for the hops that scrolled off the top of a frame too tall
// for the screen.
const elision = "⋮"

// maxPending is how many queries in flight are named before the rest are
// counted. --all can have a dozen out at once, and the footer is one line.
const maxPending = 3

// pendingIndent sets the queries in flight in from the tree, since they hang
// off the walk rather than off any branch of it.
const pendingIndent = "    "

// maxCrumbs is how many zones of the path walked so far the footer carries.
const maxCrumbs = 4

// The spinners, one per charset. Braille cycles through a single cell, which
// is what keeps the footer from jittering.
var (
	spinnerUnicode = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerASCII   = []string{"|", "/", "-", "\\"}
)

// Live draws a trace over and over in the same place, so that a walk can be
// watched while it is being made. Its frames are scratch: Clear takes the last
// one off the screen and leaves the cursor where the frame began, for the
// caller to write the finished tree exactly where it stood.
//
// A frame is a tree and a tail. The tree is redrawn when a hop joins the walk;
// the tail — the queries in flight and the footer — redraws itself on a timer,
// over those rows only, which is the whole of what moves between hops.
//
// A nil *Live draws nothing, which is what a writer nobody is watching gets.
type Live struct {
	w     io.Writer
	opts  Options
	start time.Time
	spin  []string
	arrow string
	sep   string

	stop chan struct{}
	once sync.Once

	mu      sync.Mutex
	tree    []string // the walk as it was last rendered, whole and uncut
	path    string   // the zones it has gone through
	queries int      // how many have been sent
	servers map[netip.Addr]struct{}
	pending map[int]inflight
	seq     int
	rows    int // screen lines the frame now on screen takes
	tail    int // how many of them redraw on their own
	width   int // the screen the frame on it was cut to fit
	height  int
	last    time.Time // when the tree was last redrawn
	hid     bool      // whether the cursor is ours to give back
}

// inflight is a query that has gone out and not yet come back.
type inflight struct {
	zone   string
	server trace.Server
	since  time.Time
	seq    int
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
	if ColorEnabled(w, opts.Color) {
		color = ColorAlways
	}
	opts.Color = color

	live := newLive(w, opts)
	go live.run()
	return live
}

// newLive builds a drawing that moves only when it is drawn on, which is how
// the tests watch it frame by frame.
func newLive(w io.Writer, opts Options) *Live {
	live := &Live{
		w:       w,
		opts:    opts,
		start:   time.Now(),
		spin:    spinnerUnicode,
		arrow:   "→",
		sep:     separator(opts.Charset),
		stop:    make(chan struct{}),
		servers: make(map[netip.Addr]struct{}),
		pending: make(map[int]inflight),
	}
	if opts.Charset == ASCII {
		live.spin, live.arrow = spinnerASCII, "->"
	}
	return live
}

// run redraws the tail until the drawing is cleared.
func (l *Live) run() {
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()

	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.tick()
		}
	}
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

// Asking records a query as it goes out and returns the function that takes it
// off the screen again, which is the shape Config.Asking wants. It is called
// from several goroutines at once, and from none of them is the trace readable.
func (l *Live) Asking(zone string, server trace.Server) func() {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	id := l.seq
	l.queries++
	if server.IP.IsValid() {
		l.servers[server.IP] = struct{}{}
	}
	l.pending[id] = inflight{zone: zone, server: server, since: time.Now(), seq: id}

	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.pending, id)
	}
}

// Clear wipes the frame and gives the cursor back.
func (l *Live) Clear() {
	if l == nil {
		return
	}
	if l.stop != nil {
		l.once.Do(func() { close(l.stop) })
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
	l.rows, l.tail, l.last = 0, 0, time.Time{}
	clear(l.pending)
}

// Summary is what the drawing leaves behind: one line under the finished tree
// saying how the walk went and what it cost. It counts the queries it watched
// go out rather than reading them back off the trace, which is the one thing a
// live drawing knows better.
func (l *Live) Summary(w io.Writer, tr *trace.Trace) {
	if l == nil || tr == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	elapsed := tr.Elapsed
	if elapsed == 0 {
		elapsed = time.Since(l.start)
	}
	writeSummary(w, tr.Shown(), painter(l.opts.Color == ColorAlways), l.sep,
		l.opts.Charset, elapsed, l.counts())
}

// bogus reports whether the walk found a chain of trust that does not hold,
// which outranks having an answer at all. It is the same reading main gives
// the trace when it picks an exit code.
func bogus(tr *trace.Trace) bool {
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.State == trace.Bogus {
			return true
		}
	}
	return false
}

// draw renders the walk and puts a whole frame on the screen.
func (l *Live) draw(tr *trace.Trace) {
	opts := l.opts
	opts.Highlight = newest(tr)

	var buf bytes.Buffer
	if err := Render(&buf, tr, opts); err != nil {
		return
	}
	l.tree = strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	l.path = l.crumbs(tr)
	l.paint()
}

// tick rewrites the tail where it stands, which is the cheap redraw: the tree
// above it has not changed, so the cursor goes up over the tail alone. A screen
// that has been resized gets a whole frame instead, since the cut and the width
// every line was drawn to have both just changed.
func (l *Live) tick() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.rows == 0 {
		return // nothing drawn yet, and a tail alone would be a frame of its own
	}

	width, height := terminalSize(l.w)
	tail := l.tailLines()
	if width != l.width || height != l.height || l.rows-l.tail+len(tail) > height-1 {
		l.paint()
		return
	}

	var out strings.Builder
	out.WriteString(strings.Repeat(cursorUp, l.tail) + "\r")
	for _, line := range tail {
		out.WriteString(truncate(line, width-1) + eraseLine + "\n")
	}
	out.WriteString(eraseBelow) // whatever a longer tail left behind

	if _, err := io.WriteString(l.w, out.String()); err != nil {
		return
	}
	l.rows, l.tail = l.rows-l.tail+len(tail), len(tail)
}

// paint writes one whole frame. Every line is cut to the width of the screen,
// since a line that wrapped would take two rows and the next frame would come
// back up one row short, smearing the drawing down the terminal.
func (l *Live) paint() {
	width, height := terminalSize(l.w)
	tail := l.tailLines()

	// The tail is the part worth keeping: it says where the walk is now, while
	// the top of a tree too tall to fit is where it has already been.
	tree := l.tree
	room := height - 1
	if len(tree)+len(tail) > room {
		tree = append([]string{elision}, tree[len(tree)-max(room-len(tail)-1, 0):]...)
	}
	lines := append(append([]string{}, tree...), tail...)
	if len(lines) > room {
		lines = lines[len(lines)-max(room, 1):]
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
	l.rows, l.tail = len(lines), min(len(tail), len(lines))
	l.width, l.height = width, height
	l.last = time.Now()
}

// tailLines are the rows that move on their own: the queries waiting for an
// answer, and the footer saying how the walk is doing.
func (l *Live) tailLines() []string {
	paint := painter(l.opts.Color == ColorAlways)
	spinner := l.spinner()

	waiting := slices.SortedFunc(maps.Values(l.pending), func(a, b inflight) int {
		return a.seq - b.seq
	})

	var lines []string
	for _, query := range waiting[:min(len(waiting), maxPending)] {
		lines = append(lines, pendingIndent+paint.dim(fmt.Sprintf("%s asking %s  %s  %s",
			spinner, describe(query.server), trace.Shown(query.zone), clock(time.Since(query.since)))))
	}
	if more := len(waiting) - maxPending; more > 0 {
		lines = append(lines, pendingIndent+paint.dim(fmt.Sprintf("  and %d more in flight", more)))
	}

	fields := l.counts()
	if l.path != "" {
		fields = append(fields, l.path)
	}
	status := spinner + "  " + paint.dim(clock(time.Since(l.start))+l.sep+strings.Join(fields, l.sep))
	return append(lines, "", status)
}

// counts are what the walk has spent so far.
func (l *Live) counts() []string {
	return counts(l.queries, len(l.servers))
}

// spinner is the frame the clock has reached. It is read off the clock rather
// than counted, so that it turns at the same rate however often it is drawn.
func (l *Live) spinner() string {
	return l.spin[int(time.Since(l.start)/tickEvery)%len(l.spin)]
}

// crumbs is the path the walk has taken, zone by zone, down the branch it is
// working on now.
func (l *Live) crumbs(tr *trace.Trace) string {
	if tr == nil || tr.Root == nil {
		return ""
	}

	// An aside is a walk of its own — a nameserver's address, a zone's own NS
	// set — and the zone it is about is not how far down this one has come.
	down := func(step *trace.Step) bool { return queried(step) && !step.Aside }

	var zones []string
	for step := tr.Root; step != nil; step = deeper(step, down) {
		zone := step.Zone
		if step.Delegation != nil {
			zone = step.Delegation.Zone
		}
		zone = trace.Shown(zone)
		if zone != "" && (len(zones) == 0 || zones[len(zones)-1] != zone) {
			zones = append(zones, zone)
		}
	}
	if len(zones) > maxCrumbs {
		zones = append([]string{elision}, zones[len(zones)-maxCrumbs:]...)
	}
	return strings.Join(zones, " "+l.arrow+" ")
}

// newest is the hop that joined the walk last, which is the one worth pointing
// at. A step is only ever appended to its parent, and a parent is always older
// than its children, so the freshest hop is at the end of the chain of last
// children.
func newest(tr *trace.Trace) *trace.Step {
	if tr == nil || tr.Root == nil {
		return nil
	}

	var found *trace.Step
	for step := deeper(tr.Root, queried); step != nil; step = deeper(step, queried) {
		found = step
	}
	return found
}

// deeper is the child a walk went on through: the last one that keep holds
// for. The servers a hop did not need are attached after the one that answered,
// so the plain last child is as often a road not taken as it is the way down.
func deeper(step *trace.Step, keep func(*trace.Step) bool) *trace.Step {
	for _, child := range slices.Backward(step.Children) {
		if keep(child) {
			return child
		}
	}
	return nil
}

// queried is a hop the walk made, as against a server it only listed.
func queried(step *trace.Step) bool { return step.Kind != trace.KindSkipped }

// describe is who a query went to, unpainted: a footer is dim all through.
func describe(server trace.Server) string {
	server.Name = trace.Shown(server.Name)
	switch {
	case server.Name != "" && server.IP.IsValid():
		return server.Name + " " + server.IP.String()
	case server.Name != "":
		return server.Name
	case server.IP.IsValid():
		return server.IP.String()
	}
	return "a server"
}

// clock is a duration at the precision somebody watching it can read: tenths
// of a second once there is a second to divide, milliseconds below that.
func clock(d time.Duration) string {
	if d >= time.Second {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
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
	case r == 0x200d:
		// A joiner may weld the glyphs either side of it into one, or may not:
		// that is the terminal's call. Counting both is the safe side, and a
		// width that went down would let text as long as it likes through.
		return 0
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
	case r >= 0x1f000 && r <= 0x1f2ff: // mahjong, cards, enclosed, regional indicators
		return true
	case r >= 0x20000 && r <= 0x3fffd: // CJK extensions B onwards
		return true
	default:
		return false
	}
}
