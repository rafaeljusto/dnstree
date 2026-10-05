// Package tree renders a trace for a terminal: as an indented tree, with
// Unicode or ASCII branches and optional colour, or as a waterfall of the time
// each query took.
package tree

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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

	// Width is how many columns a waterfall is laid out in. Zero asks the
	// terminal, and takes 80 where there is none.
	Width int
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
		glyphs: set,
		paint:  painter(ColorEnabled(w, opts.Color)),
		out:    bufio.NewWriter(w),
	}
	if tr != nil {
		shown := tr.Shown()
		renderer.highlight = twin(tr.Root, shown.Root, opts.Highlight)
		renderer.render(shown)
	}
	return renderer.out.Flush()
}

type renderer struct {
	glyphs    glyphs
	paint     painter
	highlight *trace.Step
	out       *bufio.Writer

	// trace is what is being drawn, which says when the walk was made: the
	// lifetime of a signature is read against that.
	trace *trace.Trace
}

func (r *renderer) render(tr *trace.Trace) {
	r.trace = tr
	if tr.Root != nil {
		r.write(r.label(tr.Root) + "\n")
		r.children(tr.Root, "")
	}
	for _, line := range r.differences(tr) {
		r.write(line + "\n")
	}
	for _, line := range r.kept(tr) {
		r.write(line + "\n")
	}
	for _, line := range r.designations(tr) {
		r.write(line + "\n")
	}
	for _, line := range r.authorities(tr.CAA) {
		r.write(line + "\n")
	}
	for _, line := range r.policy(tr.SPF) {
		r.write(line + "\n")
	}
	if line := r.reported(tr.Report); line != "" {
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

// twin is the step of a copy that stands where want stands in the original.
// The copy is drawn, and the hop to point at was picked out of the original.
func twin(original, copied, want *trace.Step) *trace.Step {
	if original == nil || copied == nil || want == nil {
		return nil
	}
	if original == want {
		return copied
	}
	for i, child := range original.Children {
		if found := twin(child, copied.Children[i], want); found != nil {
			return found
		}
	}
	return nil
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
	if step.NSID != "" {
		fields = append(fields, r.paint.dim("@"+step.NSID))
	}
	if step.Server.ASN != nil {
		fields = append(fields, r.paint.dim(fmt.Sprintf("AS%d", step.Server.ASN.Number)))
	}
	if step.RTT > 0 {
		fields = append(fields, r.paint.dim(r.pace(step.RTT)+r.duration(step.RTT)))
	}
	if size := r.size(step); size != "" {
		fields = append(fields, size)
	}
	if rcode := r.paint.rcode(step.Rcode); rcode != "" {
		fields = append(fields, rcode)
	}
	if flags := r.flags(step.Flags); flags != "" {
		fields = append(fields, flags)
	}
	if dangling := r.dangling(step.Dangling); dangling != "" {
		fields = append(fields, dangling)
	}
	if step.ReportTo != "" {
		fields = append(fields, r.paint.dim("report "+r.glyphs.arrow+" "+step.ReportTo))
	}
	if probe := r.probe(step.Probe); probe != "" {
		fields = append(fields, probe)
	}
	if edns := r.edns(step.EDNS); edns != "" {
		fields = append(fields, edns)
	}
	if subnet := r.subnet(step.Subnet); subnet != "" {
		fields = append(fields, subnet)
	}
	if note := r.note(step); note != "" {
		fields = append(fields, note)
	}
	if cookie := r.cookie(step.Cookie); cookie != "" {
		fields = append(fields, cookie)
	}
	if extended := r.extended(step.Extended); extended != "" {
		fields = append(fields, extended)
	}
	if dnssec := r.dnssec(step.DNSSEC); dnssec != "" {
		fields = append(fields, dnssec)
	}
	if step.DNSSEC != nil {
		if signal := r.signal(step.DNSSEC.Signal); signal != "" {
			fields = append(fields, signal)
		}
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

	// A chain that holds today and breaks in two days is the one outage a walk
	// can see coming, so the time left is said wherever a signature is late in
	// the life it was made for.
	left, expiring := r.trace.Expiring(status)
	expiring = expiring && status.State == trace.Secure
	if expiring {
		label += ", expires in " + short(left)
	}

	label = "[" + label + "]"
	if r.glyphs.icons {
		if icon := dnssecIcons[status.State]; icon != "" {
			label = spaced(icon) + label
		}
	}

	switch status.State {
	case trace.Secure:
		if expiring {
			return r.paint.paint(label, yellow)
		}
		return r.paint.paint(label, green)
	case trace.Insecure:
		return r.paint.paint(label, yellow)
	case trace.Bogus:
		return r.paint.paint(label, red)
	default:
		return r.paint.dim(label)
	}
}

// signal is what the zone asks its parent to publish, beside the verdict the
// parent's DS was checked to. Only a request the parent should do something
// about, or cannot, is worth the colour.
func (r *renderer) signal(signal *trace.Signal) string {
	if signal == nil {
		return ""
	}
	switch signal.State {
	case trace.SignalNone:
		return r.paint.dim("no cds")
	case trace.SignalMatch:
		return r.paint.dim("cds matches the ds")
	case trace.SignalPending:
		return r.paint.paint("cds asks for "+tags(signal.Requested)+", the ds is for "+tags(signal.Held), yellow)
	case trace.SignalDelete:
		return r.paint.paint("cds asks for no ds", yellow)
	case trace.SignalInconsistent:
		return r.paint.paint("cds and cdnskey disagree", yellow)
	}
	return r.paint.dim("cds unchecked")
}

// tags names keys by their tags.
func tags(keys []uint16) string {
	if len(keys) == 0 {
		return "no key"
	}
	named := make([]string, len(keys))
	for i, tag := range keys {
		named[i] = fmt.Sprint(tag)
	}
	if len(named) == 1 {
		return "key " + named[0]
	}
	return "keys " + strings.Join(named[:len(named)-1], ", ") + " and " + named[len(named)-1]
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
// size is how big the answer was, and it is drawn only for the hops where that
// is worth a line's room: the ones that had almost none left. Every other
// answer arrived with space behind it, and a byte count beside each of them
// would be a column to learn to ignore. The whole of it reaches --format json,
// where something reading a trace can hold every hop against the limit itself.
func (r *renderer) size(step *trace.Step) string {
	if !step.Tight() {
		return ""
	}
	return r.paint.paint(fmt.Sprintf("%d of %d bytes", step.Size, step.Limit), yellow)
}

// dangling marks the hop that showed a name left pointing at something nobody
// holds. What it would take to claim is --explain's to say.
func (r *renderer) dangling(dangling *trace.Dangling) string {
	if dangling == nil {
		return ""
	}
	switch dangling.Kind {
	case trace.DanglingNameserver, trace.DanglingAlias:
		return r.paint.paint(fmt.Sprintf("dangling %s: %s is missing", dangling.Kind, dangling.Missing), yellow)
	case trace.DanglingLame:
		return r.paint.paint("dangling: every nameserver lame", yellow)
	}
	return ""
}

// probe is what a nameserver gave when asked for what it should keep from
// strangers. Only an open one is worth the colour of a fault.
func (r *renderer) probe(probe *trace.Probe) string {
	if probe == nil {
		return ""
	}
	label := "axfr "
	if probe.Kind == trace.ProbeRecursion {
		label = "recursion "
	}
	label += string(probe.State)
	switch probe.State {
	case trace.ProbeOpen:
		return r.paint.paint(label, red)
	case trace.ProbeUnchecked:
		return r.paint.paint(label, yellow)
	}
	return r.paint.dim(label)
}

// edns is how a nameserver answered one of the shapes --check-edns asks in,
// named by what was sent, and by what it got wrong where it did.
func (r *renderer) edns(test *trace.EDNSTest) string {
	if test == nil {
		return ""
	}
	label := map[trace.EDNSKind]string{
		trace.EDNSPlain:   "edns0",
		trace.EDNSVersion: "edns version 1",
		trace.EDNSOption:  "edns option 100",
		trace.EDNSFlag:    "edns flag 0x40",
	}[test.Kind] + " " + string(test.State)
	switch test.State {
	case trace.EDNSBroken:
		return r.paint.paint(label+": "+ednsFault(test), red)
	case trace.EDNSUnchecked:
		return r.paint.paint(label, yellow)
	}
	return r.paint.dim(label)
}

// ednsFault says what a broken answer got wrong. The rcode it came with is
// drawn beside it, so a wrong one says only which was wanted.
func ednsFault(test *trace.EDNSTest) string {
	switch test.Fault {
	case trace.EDNSSilent:
		return "no answer"
	case trace.EDNSRcode:
		if test.Kind == trace.EDNSVersion {
			return "not BADVERS"
		}
		return "not NOERROR"
	case trace.EDNSNoOPT:
		return "no opt record"
	case trace.EDNSBadVers:
		return "opt not version 0"
	case trace.EDNSNoSOA:
		return "no soa"
	case trace.EDNSEchoed:
		return "copied back"
	case trace.EDNSAnswer:
		return "answered anyway"
	}
	return string(test.Fault)
}

func (r *renderer) subnet(subnet *trace.Subnet) string {
	if subnet == nil {
		return ""
	}
	return r.paint.dim(fmt.Sprintf("ecs scope /%d", subnet.Scope))
}

// cookie is how the server answered the DNS cookie it was sent. Answering
// without one is allowed, so only a server that got it wrong is coloured.
func (r *renderer) cookie(state trace.CookieState) string {
	switch state {
	case trace.CookieSupported:
		return r.paint.dim("cookie")
	case trace.CookieAbsent:
		return r.paint.dim("no cookie")
	case trace.CookieMismatch:
		return r.paint.paint("cookie not ours", red)
	case trace.CookieMalformed:
		return r.paint.paint("cookie malformed", yellow)
	case trace.CookieRejected:
		return r.paint.paint("cookie rejected", red)
	}
	return ""
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
func (r *renderer) differences(tr *trace.Trace) []string {
	result := tr.Result()
	if result == nil {
		return nil
	}

	// One line each: several resolvers are several places the question was
	// asked from, and two of them disagreeing with the walk for two different
	// reasons is two things to read rather than one.
	var lines []string
	for _, answer := range tr.Resolvers {
		if answer.Match == trace.MatchDiffers {
			lines = append(lines, r.difference(result, answer, tr.Question.Type))
		}
	}
	return lines
}

// kept is what each resolver's TTL said of the copy it serves, one line each,
// and only where it said something: a resolver holding the walk's answer longer
// than the zone allows, or serving one that looks stale.
func (r *renderer) kept(tr *trace.Trace) []string {
	zone := tr.Allowed()

	var lines []string
	for _, answer := range tr.Resolvers {
		if answer == nil || answer.Kept == "" {
			continue
		}
		who := "the resolver"
		if answer.Server.IP.IsValid() {
			who = answer.Server.IP.String()
		}
		cached := trace.TTL(answer.Records, tr.Question.Type)

		var text string
		switch answer.Kept {
		case trace.KeptLonger:
			text = fmt.Sprintf("%s keeps this with ttl %d, the zone gives %d", who, cached, zone)
		case trace.KeptStale:
			text = fmt.Sprintf("%s looks stale: no server of the zone gave its answer, and ttl %d is what serve-stale hands out", who, cached)
		default:
			continue
		}
		mark := "ttl: "
		if r.glyphs.icons {
			mark = spaced("🧊")
		}
		lines = append(lines, r.paint.paint(mark+text, yellow))
	}
	return lines
}

// designations are what each resolver said of its encrypted selves, one line
// each, and only where --ddr asked. None of it was connected to, and the line
// says so: an offer is the plain resolver's claim.
func (r *renderer) designations(tr *trace.Trace) []string {
	var lines []string
	for _, answer := range tr.Resolvers {
		if answer == nil || answer.DDR == nil {
			continue
		}
		mark := "ddr: "
		if r.glyphs.icons {
			mark = spaced("🔐")
		}
		who, found := "the resolver", answer.DDR
		if answer.Server.IP.IsValid() {
			who = answer.Server.IP.String()
		}
		switch {
		case found.Err != "":
			lines = append(lines, r.paint.dim(mark+who+" could not be asked for its encrypted resolvers: "+found.Err))
		case found.Rcode != "NOERROR" && found.Rcode != "NXDOMAIN":
			lines = append(lines, r.paint.dim(mark+who+" would not say which encrypted resolvers it has: "+found.Rcode))
		case len(found.Designated) == 0:
			lines = append(lines, r.paint.dim(mark+who+" designates no encrypted resolver"))
		default:
			offers := make([]string, 0, len(found.Designated))
			for _, offer := range found.Designated {
				offers = append(offers, offered(offer)...)
			}
			lines = append(lines, r.paint.paint(mark+who+" offers "+strings.Join(offers, ", "), green)+
				r.paint.dim(" (not verified)"))
		}
	}
	return lines
}

// authorities say who may issue certificates for the name and which set
// decided it, only where --caa asked. The climb itself is in the tree.
// reported is the line that says what came of the report --report sent.
func (r *renderer) reported(report *trace.Report) string {
	if report == nil {
		return ""
	}
	mark := "report: "
	if r.glyphs.icons {
		mark = spaced("📮")
	}
	switch {
	case report.Name == "":
		return r.paint.paint(mark+"not sent to "+report.Agent+": "+report.Err, yellow)
	case report.Err != "":
		return r.paint.paint(mark+report.Agent+" was not reached: "+report.Err, yellow)
	}
	return r.paint.dim(mark + "told " + report.Agent + " the chain of trust is bogus, as " + report.Name + " (" + report.Rcode + ")")
}

func (r *renderer) authorities(caa *trace.CAA) []string {
	if caa == nil {
		return nil
	}
	mark := "caa: "
	if r.glyphs.icons {
		mark = spaced("📜")
	}

	var none []string
	for _, lookup := range caa.Asked {
		if lookup.Found == trace.CAANone {
			none = append(none, lookup.Name)
		}
	}
	found := ""
	switch {
	case caa.Owner != "":
		found = caa.Owner + " decides it"
		if len(none) > 0 {
			found = "none at " + strings.Join(none, ", ") + "; " + found
		}
		for _, lookup := range caa.Asked {
			if lookup.Name == caa.Owner && lookup.Alias != "" {
				found += ", as an alias for " + lookup.Alias
			}
		}
	case caa.Refused == "" && caa.Undecided == "" && len(caa.Asked) > 0:
		found = "none from " + caa.Asked[0].Name + " up, so any authority may issue"
	}

	var lines []string
	if found != "" {
		line := r.paint.dim(mark + found)
		if verdict := r.dnssec(caa.DNSSEC); verdict != "" {
			line += " " + verdict
		}
		lines = append(lines, line)
	}
	if caa.Refused != "" {
		return append(lines, r.paint.paint(mark+"every authority refuses: "+caa.Refused, red))
	}
	if caa.Undecided != "" {
		return append(lines, r.paint.paint(mark+"an authority may refuse: "+caa.Undecided, yellow))
	}
	if caa.Owner == "" {
		return lines
	}

	policy := []string{"may issue: " + issuers(caa.Issue), "wildcards: " + issuers(caa.Wildcard)}
	for _, record := range caa.Records {
		if strings.EqualFold(record.Tag, "iodef") {
			policy = append(policy, "reports to "+record.Value)
		}
	}
	return append(lines, r.paint.paint(mark+strings.Join(policy, "; "), green))
}

// issuers are the authorities a set lets issue, as a reader wants them.
func issuers(issuers *trace.Issuers) string {
	switch {
	case issuers == nil:
		return "any authority"
	case len(issuers.CAs) == 0:
		return "nobody"
	}
	return strings.Join(issuers.CAs, ", ")
}

// offered is one designation as a client would dial it, once per transport it
// names. A record whose ALPN names none this build knows is drawn by its ALPN.
func offered(offer trace.Designated) []string {
	host := strings.TrimSuffix(offer.Target, ".")
	if offer.Port != 0 {
		host += ":" + strconv.Itoa(int(offer.Port))
	}
	if len(offer.Protocols) == 0 {
		return []string{"alpn " + strings.Join(offer.ALPN, ",") + " at " + host}
	}
	spelled := make([]string, 0, len(offer.Protocols))
	for _, proto := range offer.Protocols {
		if proto == "doh" {
			spelled = append(spelled, "doh at https://"+host+offer.DoHPath)
			continue
		}
		spelled = append(spelled, proto+" at "+host)
	}
	return spelled
}

// difference is the one line for one resolver that did not answer as the walk
// did.
func (r *renderer) difference(result *trace.Step, answer *trace.Resolver, qtype string) string {
	who := "the resolver"
	if answer.Server.IP.IsValid() {
		who = answer.Server.IP.String()
	}

	var text string
	ours := trace.Answers(result.Records, qtype)
	theirs := trace.Answers(answer.Records, qtype)
	switch {
	case result.Rcode != answer.Rcode:
		text = fmt.Sprintf("%s answers %s where the walk found %s",
			who, answer.Rcode, result.Rcode)
	default:
		text = fmt.Sprintf("%s answers %s, the walk found %s",
			who, List(theirs), List(ours))
	}

	mark := "differs: "
	if r.glyphs.icons {
		mark = spaced("🔀")
	}
	return r.paint.paint(mark+text, yellow)
}

// List is a set of rdata as a reader wants it, kept short: a round robin of a
// dozen addresses says nothing more than the first few of them and a count.
func List(data []string) string {
	const most = 3
	if len(data) == 0 {
		return "nothing"
	}
	if len(data) <= most {
		return strings.Join(data, ", ")
	}
	return strings.Join(data[:most], ", ") + fmt.Sprintf(" (and %d more)", len(data)-most)
}

// short is how long a signature has left, in the two largest units it fills.
func short(d time.Duration) string {
	days, hours := d/(24*time.Hour), d%(24*time.Hour)/time.Hour
	switch {
	case days > 0 && hours > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dm", d/time.Minute)
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
