package tree

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// bars are the glyphs a waterfall is drawn with: the walk's own queries solid,
// and the asides, which answer another question on the way, lighter.
var bars = map[Charset][2]string{
	Unicode: {"█", "░"},
	Emoji:   {"█", "░"},
	ASCII:   {"#", "."},
}

// The widest a column of names grows before it is cut, and the least room the
// bars are left however narrow the screen: fewer cells than that cannot show
// two queries apart.
const (
	maxWho      = 28
	minBars     = 12
	whatReserve = 18
)

// Waterfall writes the trace to w as a timeline: one row per query, a bar from
// when it went out to when the last of its answers came back, all on the one
// scale the whole walk spans. The tree shows how the walk got where it did;
// this shows where the time went, what waited for what, and what was in
// flight together.
func Waterfall(w io.Writer, tr *trace.Trace, opts Options) error {
	if tr == nil {
		return nil
	}
	if !tr.Timed {
		return trace.ErrUntimed
	}
	glyphs, ok := bars[cmp.Or(opts.Charset, Unicode)]
	if !ok {
		return fmt.Errorf("tree: unknown charset %q", opts.Charset)
	}

	tr = tr.Shown()
	width := opts.Width
	cut := false
	if width <= 0 {
		width, _ = terminalSize(w)
		// Laid out to the screen, a line that wrapped would pull its bar under
		// the next row's. The ellipsis a cut ends in is not ASCII, and a file
		// is not a screen.
		cut = opts.Charset != ASCII && IsTerminal(w)
	}

	fall := &waterfall{
		glyphs: glyphs,
		paint:  painter(ColorEnabled(w, opts.Color)),
		tree:   &renderer{glyphs: charsets[cmp.Or(opts.Charset, Unicode)]},
		trace:  tr,
		rows:   tr.Timeline(),
	}
	fall.layout(width)

	out := bufio.NewWriter(w)
	for _, line := range fall.lines() {
		if cut {
			line = truncate(line, width)
		}
		_, _ = out.WriteString(line + "\n")
	}
	return out.Flush()
}

type waterfall struct {
	glyphs [2]string
	paint  painter
	tree   *renderer // for the durations, drawn the way the tree draws them
	trace  *trace.Trace
	rows   []trace.Span

	span                  time.Duration // what the axis runs to
	who, took, cells, gap int
}

// layout decides the columns: the names as wide as the widest of them, the
// durations likewise, and the bars whatever the line has left.
func (f *waterfall) layout(width int) {
	f.span = f.trace.Elapsed
	for _, row := range f.rows {
		f.who = max(f.who, cells(f.label(row)))
		f.took = max(f.took, cells(f.duration(row)))
		f.span = max(f.span, row.End)
	}
	f.who = min(f.who, maxWho)
	f.gap = 2
	f.cells = max(minBars, width-f.who-f.took-3*f.gap-whatReserve)
}

func (f *waterfall) lines() []string {
	if len(f.rows) == 0 {
		return append([]string{f.paint.dim("no server was asked")}, f.warnings()...)
	}
	lines := []string{strings.Repeat(" ", f.who+f.gap) + f.paint.dim(strings.TrimRight(f.axis(), " "))}
	for _, row := range f.rows {
		lines = append(lines, f.line(row))
	}
	return append(lines, f.warnings()...)
}

func (f *waterfall) line(row trace.Span) string {
	label := f.label(row)
	if cells(label) > f.who {
		label = clip(label, f.who)
	}
	padding := strings.Repeat(" ", f.who-cells(label))
	if row.Step.Server.Name != "" || row.Step.Server.IP.IsValid() {
		label = f.paint.server(label)
	} else {
		label = f.paint.dim(label)
	}
	label += padding

	bar := strings.Repeat(" ", f.cells)
	if row.Step.Queried() {
		from, to := f.cell(row.Start), f.cell(row.End)
		to = min(max(to, from+1), f.cells)
		from = min(from, to-1)
		glyph := f.glyphs[0]
		if row.Aside {
			glyph = f.glyphs[1]
		}
		bar = strings.Repeat(" ", from) + f.paint.paint(strings.Repeat(glyph, to-from), tone(row)) +
			strings.Repeat(" ", f.cells-to)
	}

	took := f.duration(row)
	took = strings.Repeat(" ", f.took-cells(took)) + f.paint.dim(took)

	space := strings.Repeat(" ", f.gap)
	return strings.TrimRight(label+space+bar+space+took+space+f.what(row), " ")
}

// cell is where a moment falls on the bars.
func (f *waterfall) cell(at time.Duration) int {
	if f.span <= 0 {
		return 0
	}
	return int(math.Round(float64(at) / float64(f.span) * float64(f.cells)))
}

// axis is the scale over the bars: round numbers, far enough apart to read.
// The marks are counted rather than stepped through, so that a span read from
// a hostile file cannot wrap the clock round and keep the loop going.
func (f *waterfall) axis() string {
	step := tick(f.span, f.cells)
	marks := min(int64(f.span/step), int64(f.cells))
	line := []byte(strings.Repeat(" ", f.cells))
	end := 0 // where the last label put down ends, so the next cannot run into it
	for i := range marks + 1 {
		at := time.Duration(i) * step
		label := f.tickLabel(at)
		pos := min(f.cell(at), f.cells-len(label))
		if pos < end || pos < 0 {
			continue
		}
		copy(line[pos:], label)
		end = pos + len(label) + 1
	}
	return string(line)
}

// tick is the round distance between two marks on an axis of this many cells,
// leaving room for a label of up to eight between them.
func tick(span time.Duration, cells int) time.Duration {
	most := time.Duration(max(cells/8, 1))
	for unit := time.Microsecond; unit <= math.MaxInt64/10; unit *= 10 {
		for _, step := range []time.Duration{unit, 2 * unit, 5 * unit} {
			if span/step < most {
				return step
			}
		}
	}
	return max(span/most, 1)
}

func (f *waterfall) tickLabel(at time.Duration) string {
	if at == 0 {
		return "0"
	}
	text := at.String()
	if f.glyphs[0] == bars[ASCII][0] {
		text = strings.ReplaceAll(text, "µ", "u")
	}
	return text
}

// label is who was asked, or the zone the walk gave up in.
func (f *waterfall) label(row trace.Span) string {
	server := row.Step.Server
	switch {
	case server.Name != "":
		return server.Name
	case server.IP.IsValid():
		return server.IP.String()
	}
	return row.Step.Zone
}

func (f *waterfall) duration(row trace.Span) string {
	if !row.Step.Queried() {
		return ""
	}
	return f.tree.duration(row.Step.RTT)
}

// what is how the query went, and what it asked where that was not the
// question itself: the keys of a zone, the address of a nameserver, a name
// cut short to find the next zone.
func (f *waterfall) what(row trace.Span) string {
	step := row.Step
	var said string
	switch step.Kind {
	case trace.KindReferral:
		zone := step.Zone
		if step.Delegation != nil {
			zone = step.Delegation.Zone
		}
		said = "referral " + f.tree.glyphs.arrow + " " + zone
	case trace.KindNoData:
		said = "no data"
	case trace.KindError:
		said = "error"
		if step.Err != "" {
			said += ": " + step.Err
		}
	default:
		said = string(step.Kind)
	}

	fields := []string{f.paint.paint(said, tone(row))}
	if f.trace.Asks(step) {
		fields = append(fields, f.paint.dim(step.Asked.Type+" "+step.Asked.Name))
	}
	if len(step.Notes) > 0 {
		fields = append(fields, f.paint.dim("("+strings.Join(step.Notes, "; ")+")"))
	}
	return strings.Join(fields, "  ")
}

func (f *waterfall) warnings() []string {
	var lines []string
	for _, warning := range f.trace.Warnings {
		lines = append(lines, f.paint.paint("warning: "+warning, yellow))
	}
	return lines
}

// tone colours a bar by how the query went, following the tree: an answer is
// green, a denial a warning, a failure a failure. An answer about a shorter
// name than the question is only a way down, and is not coloured as one.
func tone(row trace.Span) string {
	step := row.Step
	if step.Minimised && (step.Kind == trace.KindAnswer || step.Kind == trace.KindNoData) {
		return ""
	}
	switch step.Kind {
	case trace.KindAnswer, trace.KindCNAME:
		return green
	case trace.KindNoData, trace.KindNXDomain, trace.KindLame:
		return yellow
	case trace.KindFiltered, trace.KindTimeout, trace.KindError:
		return red
	}
	return ""
}

// cells is how many columns text takes on screen.
func cells(text string) int {
	var (
		width    int
		previous rune
	)
	for i := 0; i < len(text); {
		if skip := escape(text[i:]); skip > 0 {
			i += skip
			continue
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		width += cellWidth(r, previous)
		previous, i = r, i+size
	}
	return width
}

// clip cuts a name to fit its column, keeping its start: the servers of one
// zone differ in their first label and share the rest.
func clip(text string, width int) string {
	runes := []rune(text)
	for len(runes) > 0 && cells(string(runes)) > width-1 {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "~"
}
