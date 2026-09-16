// Package tree renders a trace as an indented tree, with Unicode or ASCII
// branches and optional colour.
package tree

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// Charset picks the branch glyphs.
type Charset string

const (
	Unicode Charset = "unicode" // the default
	ASCII   Charset = "ascii"   // for documentation and markdown
)

// Options configure a rendering.
type Options struct {
	Charset Charset
	Color   ColorMode
}

// glyphs are the pieces a tree is drawn with.
type glyphs struct {
	branch, lastBranch string // in front of a node
	vertical, blank    string // carried down to its children
	arrow              string
}

var charsets = map[Charset]glyphs{
	Unicode: {branch: "├── ", lastBranch: "└── ", vertical: "│   ", blank: "    ", arrow: "→"},
	ASCII:   {branch: "|-- ", lastBranch: "`-- ", vertical: "|   ", blank: "    ", arrow: "->"},
}

// Render writes the trace to w as a tree.
func Render(w io.Writer, tr *trace.Trace, opts Options) error {
	set, ok := charsets[opts.Charset]
	if !ok {
		if opts.Charset != "" {
			return fmt.Errorf("tree: unknown charset %q", opts.Charset)
		}
		set = charsets[Unicode]
	}

	renderer := &renderer{
		glyphs: set,
		paint:  painter(colorEnabled(w, opts.Color)),
		out:    bufio.NewWriter(w),
	}
	if tr != nil {
		renderer.render(tr)
	}
	return renderer.out.Flush()
}

type renderer struct {
	glyphs glyphs
	paint  painter
	out    *bufio.Writer
}

func (r *renderer) render(tr *trace.Trace) {
	if tr.Root != nil {
		r.out.WriteString(r.label(tr.Root) + "\n")
		r.children(tr.Root, "")
	}
	for _, warning := range tr.Warnings {
		r.out.WriteString(r.paint.paint("warning: "+warning, yellow) + "\n")
	}
}

// step draws one hop and everything it led to.
func (r *renderer) step(step *trace.Step, prefix string, last bool) {
	r.out.WriteString(prefix + r.branch(last) + r.label(step) + "\n")
	r.children(step, prefix+r.continuation(last))
}

// children draws the records a step returned and then the hops it led to, both
// hanging off the same prefix.
func (r *renderer) children(step *trace.Step, prefix string) {
	total := len(step.Records) + len(step.Children)
	drawn := 0

	for _, record := range step.Records {
		drawn++
		r.out.WriteString(prefix + r.branch(drawn == total) + r.recordLabel(record) + "\n")
	}
	for _, child := range step.Children {
		drawn++
		r.step(child, prefix, drawn == total)
	}
}

func (r *renderer) branch(last bool) string {
	if last {
		return r.glyphs.lastBranch
	}
	return r.glyphs.branch
}

func (r *renderer) continuation(last bool) string {
	if last {
		return r.glyphs.blank
	}
	return r.glyphs.vertical
}

// label draws a node, which is either a hop or the zone a walk starts from.
// Chasing an alias or a nameserver's name starts a walk of its own, so a zone
// node can turn up anywhere in the tree.
func (r *renderer) label(step *trace.Step) string {
	if step.Kind == trace.KindZone {
		zone := step.Zone
		if zone == "." {
			zone = ". (root)"
		}
		return join(r.paint.dim(zone), r.dnssec(step.DNSSEC), r.notes(step))
	}
	return r.stepLabel(step)
}

// stepLabel is one hop: who was asked, how it went, and what it said.
func (r *renderer) stepLabel(step *trace.Step) string {
	var fields []string

	// The name and the address are one identity, so they stay together.
	if who := r.who(step.Server); who != "" {
		fields = append(fields, who)
	}
	if step.Server.ASN != nil {
		fields = append(fields, r.paint.dim(fmt.Sprintf("AS%d", step.Server.ASN.Number)))
	}
	if step.RTT > 0 {
		fields = append(fields, r.paint.dim(r.duration(step.RTT)))
	}
	if rcode := r.paint.rcode(step.Rcode); rcode != "" {
		fields = append(fields, rcode)
	}
	if flags := r.flags(step.Flags); flags != "" {
		fields = append(fields, flags)
	}
	if note := r.note(step); note != "" {
		fields = append(fields, note)
	}
	if dnssec := r.dnssec(step.DNSSEC); dnssec != "" {
		fields = append(fields, dnssec)
	}
	if notes := r.notes(step); notes != "" {
		fields = append(fields, notes)
	}
	return strings.Join(fields, "  ")
}

// notes are what the hop took, in the margin where they belong.
func (r *renderer) notes(step *trace.Step) string {
	if len(step.Notes) == 0 {
		return ""
	}
	return r.paint.dim("(" + strings.Join(step.Notes, "; ") + ")")
}

// join puts two fields together, dropping an empty one.
func join(fields ...string) string {
	var set []string
	for _, field := range fields {
		if field != "" {
			set = append(set, field)
		}
	}
	return strings.Join(set, "  ")
}

func (r *renderer) who(server trace.Server) string {
	switch {
	case server.Name != "" && server.IP.IsValid():
		return r.paint.server(server.Name) + " " + r.paint.dim(server.IP.String())
	case server.Name != "":
		return r.paint.server(server.Name)
	case server.IP.IsValid():
		return r.paint.server(server.IP.String())
	}
	return ""
}

// flags are the header bits worth showing, in the order dig prints them.
func (r *renderer) flags(flags trace.Flags) string {
	var set []string
	for _, flag := range []struct {
		on   bool
		name string
	}{
		{flags.AA, "AA"},
		{flags.TC, "TC"},
		{flags.AD, "AD"},
		{flags.DO, "DO"},
	} {
		if flag.on {
			set = append(set, flag.name)
		}
	}
	return strings.Join(set, " ")
}

// note says what the hop meant, when the rcode does not say it already.
func (r *renderer) note(step *trace.Step) string {
	switch step.Kind {
	case trace.KindReferral:
		zone := step.Zone
		if step.Delegation != nil {
			zone = step.Delegation.Zone
		}
		return "referral " + r.glyphs.arrow + " " + zone
	case trace.KindNoData:
		return r.paint.paint("no data", yellow)
	case trace.KindLame:
		return r.paint.paint("lame", yellow)
	case trace.KindSkipped:
		return r.paint.dim("(not queried)")
	case trace.KindTimeout:
		return r.paint.paint("timeout", red)
	case trace.KindError:
		note := "error"
		if step.Err != "" {
			note += ": " + step.Err
		}
		return r.paint.paint(note, red)
	}
	return ""
}

// dnssec is the state of the chain at this zone cut. The algorithm and the
// digest always come with it: an algorithm this build cannot check has to read
// differently from a signature that genuinely does not verify.
func (r *renderer) dnssec(status *trace.DNSSECStatus) string {
	if status == nil {
		return ""
	}

	label := string(status.State)
	switch {
	case status.Algorithm != "" && status.Digest != "":
		label += " " + status.Algorithm + "/" + status.Digest
	case status.Algorithm != "":
		label += " " + status.Algorithm
	}
	switch status.State {
	case trace.Bogus, trace.Indeterminate:
		if status.Reason != "" {
			label += ": " + status.Reason
		}
	}
	label = "[" + label + "]"

	switch status.State {
	case trace.Secure:
		return r.paint.paint(label, green)
	case trace.Insecure:
		return r.paint.paint(label, yellow)
	case trace.Bogus:
		return r.paint.paint(label, red)
	default:
		return r.paint.dim(label)
	}
}

func (r *renderer) recordLabel(record trace.RR) string {
	return fmt.Sprintf("%s %s %s %s",
		record.Name, r.paint.dim(fmt.Sprint(record.TTL)), r.paint.rrtype(record.Type), record.Data)
}

// duration keeps a round trip readable: milliseconds for anything a network
// does, finer only when the answer came from next door.
func (r *renderer) duration(d time.Duration) string {
	var rounded time.Duration
	switch {
	case d >= time.Second:
		rounded = d.Round(10 * time.Millisecond)
	case d >= 10*time.Millisecond:
		rounded = d.Round(time.Millisecond)
	case d >= time.Millisecond:
		rounded = d.Round(100 * time.Microsecond)
	default:
		rounded = d.Round(10 * time.Microsecond)
	}

	text := rounded.String()
	if r.glyphs.arrow == "->" { // the ASCII charset promises ASCII
		text = strings.ReplaceAll(text, "µ", "u")
	}
	return text
}
