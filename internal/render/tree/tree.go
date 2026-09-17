// Package tree renders a trace as an indented tree, with Unicode or ASCII
// branches and optional colour.
package tree

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// Charset picks the branch glyphs.
type Charset string

// The charsets a tree can be drawn with.
const (
	Unicode Charset = "unicode" // the default
	ASCII   Charset = "ascii"   // for documentation and markdown
	Emoji   Charset = "emoji"   // for the fun of it
)

// Options configure a rendering.
type Options struct {
	Charset Charset
	Color   ColorMode

	// Highlight is the hop to point at, which a live drawing sets to the one
	// that just joined the walk. Its branch grows an arrowhead, so the eye
	// catches what landed without waiting for colour. Nil points at nothing.
	Highlight *trace.Step
}

// glyphs are the pieces a tree is drawn with. Every branch is four cells wide,
// marked or not, so that pointing at a hop does not shift the lines under it.
type glyphs struct {
	branch, lastBranch string // in front of a node
	mark, lastMark     string // in front of the node being pointed at
	vertical, blank    string // carried down to its children
	arrow              string
	icons              bool // whether a hop is introduced by an emoji
}

var charsets = map[Charset]glyphs{
	Unicode: {branch: "├── ", lastBranch: "└── ", mark: "├─▸ ", lastMark: "└─▸ ",
		vertical: "│   ", blank: "    ", arrow: "→"},
	ASCII: {branch: "|-- ", lastBranch: "`-- ", mark: "|-> ", lastMark: "`-> ",
		vertical: "|   ", blank: "    ", arrow: "->"},
	Emoji: {branch: "├── ", lastBranch: "└── ", mark: "├─▸ ", lastMark: "└─▸ ",
		vertical: "│   ", blank: "    ", arrow: "→", icons: true},
}

// The emoji a walk is told in. They sit in the label rather than in the
// branches, where a two cell wide glyph would pull the tree out of line.
var (
	kindIcons = map[trace.StepKind]string{
		trace.KindZone:     "🌍",
		trace.KindReferral: "🛰️",
		trace.KindAnswer:   "🎯",
		trace.KindCNAME:    "🔗",
		trace.KindNoData:   "🕳️",
		trace.KindNXDomain: "👻",
		trace.KindLame:     "🦥",
		trace.KindFiltered: "🚫",
		trace.KindTimeout:  "⏳",
		trace.KindError:    "💥",
		trace.KindSkipped:  "💤",
	}
	recordIcons = map[string]string{
		"A": "📍", "AAAA": "🌐", "CNAME": "🔗", "MX": "📬",
		"TXT": "📝", "NS": "🗂️", "SOA": "📜", "DS": "🔑", "DNSKEY": "🔑",
		"HTTPS": "🔐", "SVCB": "🔐",
	}
	dnssecIcons = map[trace.DNSSECState]string{
		trace.Secure: "🔒", trace.Insecure: "🔓", trace.Bogus: "☠️", trace.Indeterminate: "❓",
	}
)

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
		glyphs:    set,
		paint:     painter(colorEnabled(w, opts.Color)),
		highlight: opts.Highlight,
		out:       bufio.NewWriter(w),
	}
	if tr != nil {
		renderer.render(tr)
	}
	return renderer.out.Flush()
}

type renderer struct {
	glyphs    glyphs
	paint     painter
	highlight *trace.Step
	out       *bufio.Writer
}

func (r *renderer) render(tr *trace.Trace) {
	if tr.Root != nil {
		r.write(r.label(tr.Root) + "\n")
		r.children(tr.Root, "")
	}
	if line := r.difference(tr); line != "" {
		r.write(line + "\n")
	}
	for _, warning := range tr.Warnings {
		mark := "warning: "
		if r.glyphs.icons {
			mark = spaced("⚠️")
		}
		r.write(r.paint.paint(mark+warning, yellow) + "\n")
	}
}

// step draws one hop and everything it led to.
func (r *renderer) step(step *trace.Step, prefix string, last bool) {
	r.write(prefix + r.branch(last, step == r.highlight) + r.label(step) + "\n")
	r.children(step, prefix+r.continuation(last))
}

// children draws the records a step returned and then the hops it led to, both
// hanging off the same prefix.
func (r *renderer) children(step *trace.Step, prefix string) {
	total := len(step.Records) + len(step.Children)
	drawn := 0

	for _, record := range step.Records {
		drawn++
		r.write(prefix + r.branch(drawn == total, false) + r.recordLabel(record) + "\n")
	}
	for _, child := range step.Children {
		drawn++
		r.step(child, prefix, drawn == total)
	}
}

// write adds a line to the output. A bufio writer holds the first error it
// meets until Flush, which is what Render returns, so the way there needs no
// checking of its own.
func (r *renderer) write(text string) {
	_, _ = r.out.WriteString(text)
}

func (r *renderer) branch(last, marked bool) string {
	switch {
	case last && marked:
		return r.glyphs.lastMark
	case last:
		return r.glyphs.lastBranch
	case marked:
		return r.glyphs.mark
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
		return join(r.icon(step.Kind), r.paint.dim(zone), r.dnssec(step.DNSSEC), r.notes(step))
	}
	return r.stepLabel(step)
}

// stepLabel is one hop: who was asked, how it went, and what it said.
func (r *renderer) stepLabel(step *trace.Step) string {
	var fields []string

	if icon := r.icon(step.Kind); icon != "" {
		fields = append(fields, icon)
	}

	// The name and the address are one identity, so they stay together.
	if who := r.who(step.Server); who != "" {
		fields = append(fields, who)
	}
	if step.Server.ASN != nil {
		fields = append(fields, r.paint.dim(fmt.Sprintf("AS%d", step.Server.ASN.Number)))
	}
	if step.RTT > 0 {
		fields = append(fields, r.paint.dim(r.pace(step.RTT)+r.duration(step.RTT)))
	}
	if rcode := r.paint.rcode(step.Rcode); rcode != "" {
		fields = append(fields, rcode)
	}
	if flags := r.flags(step.Flags); flags != "" {
		fields = append(fields, flags)
	}
	if subnet := r.subnet(step.Subnet); subnet != "" {
		fields = append(fields, subnet)
	}
	if note := r.note(step); note != "" {
		fields = append(fields, note)
	}
	if extended := r.extended(step.Extended); extended != "" {
		fields = append(fields, extended)
	}
	if dnssec := r.dnssec(step.DNSSEC); dnssec != "" {
		fields = append(fields, dnssec)
	}
	if notes := r.notes(step); notes != "" {
		fields = append(fields, notes)
	}
	return strings.Join(fields, "  ")
}

// icon is the emoji a kind is told by, when the charset asks for them.
func (r *renderer) icon(kind trace.StepKind) string {
	if !r.glyphs.icons {
		return ""
	}
	return kindIcons[kind]
}

// pace marks the hops worth noticing: the ones that flew, and the ones that
// somebody waited through.
func (r *renderer) pace(rtt time.Duration) string {
	switch {
	case !r.glyphs.icons:
		return ""
	case rtt < 50*time.Millisecond:
		return spaced("⚡")
	case rtt > 500*time.Millisecond:
		return spaced("🐢")
	}
	return ""
}

// notes are what the hop took, in the margin where they belong.
func (r *renderer) notes(step *trace.Step) string {
	if len(step.Notes) == 0 {
		return ""
	}
	return r.paint.dim("(" + strings.Join(step.Notes, "; ") + ")")
}

// spaced sets an icon off from what it introduces. A symbol from before the
// emoji blocks is only drawn as one by the variation selector after it, and a
// terminal that keeps the one cell such a symbol has always had lets the glyph
// spill over the space that follows, so it is given another.
func spaced(icon string) string {
	if r, _ := utf8.DecodeRuneInString(icon); r < 0x1f000 && strings.ContainsRune(icon, 0xfe0f) {
		return icon + "  "
	}
	return icon + " "
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
	case trace.KindFiltered:
		return r.paint.paint("filtered", red)
	case trace.KindSkipped:
		if step.Server.Name == "" && !step.Server.IP.IsValid() {
			return "" // a summary of the rest; its note says what it stands for
		}
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
	if r.glyphs.icons {
		if icon := dnssecIcons[status.State]; icon != "" {
			label = spaced(icon) + label
		}
	}

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
	label := fmt.Sprintf("%s %s %s %s",
		record.Name, r.paint.dim(fmt.Sprint(record.TTL)), r.paint.rrtype(record.Type), record.Data)

	// The rdata already spells every parameter out. ECH is called out again
	// because it is the one a reader is meant to do something about: it only
	// hides anything if this record reached the client as the zone wrote it.
	if record.Service != nil && record.Service.ECH {
		label += "  " + r.paint.paint("[ech]", green)
	}
	if !r.glyphs.icons {
		return label
	}

	icon := recordIcons[record.Type]
	if icon == "" {
		icon = "📄"
	}
	return spaced(icon) + label
}

// subnet is what the server made of the client subnet it was sent. The scope
// is the part of the prefix that shaped this answer, so a zero scope is a
// server saying it answers the same for everybody.
func (r *renderer) subnet(subnet *trace.Subnet) string {
	if subnet == nil {
		return ""
	}
	return r.paint.dim(fmt.Sprintf("ecs scope /%d", subnet.Scope))
}

// extended is what the server said about its own answer, in the codes of RFC
// 8914. A code that admits the answer was withheld is the reader's business;
// the rest is background, and dimmed.
func (r *renderer) extended(errors []trace.ExtendedError) string {
	if len(errors) == 0 {
		return ""
	}

	set := make([]string, 0, len(errors))
	withheld := false
	for _, ede := range errors {
		set = append(set, ede.String())
		withheld = withheld || ede.Withheld()
	}

	label := "ede " + strings.Join(set, "; ")
	if withheld {
		return r.paint.paint(label, yellow)
	}
	return r.paint.dim(label)
}

// difference sets the resolver's answer beside the walk's, and only when the
// two disagree. Agreement is worth no room: it is what the reader expects, and
// the summary already says the comparison was made.
//
// A difference is not by itself a wrong answer. The two questions were asked
// from different places and a server that answers by where the question came
// from will honestly answer them differently; so will a name whose TTL turned
// over between them. It is what the difference might instead be — a resolver
// answering out of a policy rather than out of the zone — that earns the line.
func (r *renderer) difference(tr *trace.Trace) string {
	if tr.Resolver == nil || tr.Resolver.Match != trace.MatchDiffers {
		return ""
	}
	result := tr.Result()
	if result == nil {
		return ""
	}

	who := "the resolver"
	if tr.Resolver.Server.IP.IsValid() {
		who = tr.Resolver.Server.IP.String()
	}

	var text string
	ours := trace.Answers(result.Records, tr.Question.Type)
	theirs := trace.Answers(tr.Resolver.Records, tr.Question.Type)
	switch {
	case result.Rcode != tr.Resolver.Rcode:
		text = fmt.Sprintf("%s answers %s where the walk found %s",
			who, tr.Resolver.Rcode, result.Rcode)
	default:
		text = fmt.Sprintf("%s answers %s, the walk found %s",
			who, list(theirs), list(ours))
	}

	mark := "differs: "
	if r.glyphs.icons {
		mark = spaced("🔀")
	}
	return r.paint.paint(mark+text, yellow)
}

// list is a set of rdata as a reader wants it, kept short: a round robin of a
// dozen addresses says nothing more than the first few of them and a count.
func list(data []string) string {
	const most = 3
	if len(data) == 0 {
		return "nothing"
	}
	if len(data) <= most {
		return strings.Join(data, ", ")
	}
	return strings.Join(data[:most], ", ") + fmt.Sprintf(" (and %d more)", len(data)-most)
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
