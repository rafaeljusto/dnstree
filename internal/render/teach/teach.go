// Package teach tells a walk as a story, one hop at a time, for somebody
// learning how DNS finds a name: who was asked, why that server, what it said
// and what that meant for the next step. It says only what the walk recorded,
// so it cannot come to disagree with the tree.
package teach

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/render/diagram"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// width is where paragraphs are wrapped. The text is meant to be pasted into
// teaching material as often as read in a terminal, so it does not follow the
// terminal's width.
const width = 76

// Render writes the story of the walk. The path to the answer is told hop by
// hop; the work beside it (a nameserver's address, a zone's keys, the other
// servers --all asked) is said in a sentence inside the hop that needed it,
// and the lookups the checks make apart from the walk are left out.
func Render(w io.Writer, tr *trace.Trace) error {
	out := bufio.NewWriter(w)
	if tr != nil && tr.Root != nil {
		tr = tr.Shown()
		s := &story{trace: tr, path: path(tr.Root, tr.Result()), said: map[string]trace.DNSSECState{}, told: map[string]bool{}}
		s.servers(tr.Root)
		fmt.Fprintf(out, "how dnstree found %s, one hop at a time\n", question(tr.Question))
		for _, p := range s.paragraphs {
			fmt.Fprintln(out)
			fmt.Fprint(out, p)
		}
		fmt.Fprintln(out)
		fmt.Fprint(out, wrap(s.ending(), "", ""))
	}
	return out.Flush()
}

type story struct {
	trace      *trace.Trace
	path       map[*trace.Step]bool
	paragraphs []string
	hops       int

	// told is the explanations given already: a term is explained the first
	// time it comes up, and named after that.
	told map[string]bool

	// said is the chain of trust each zone was last said to be in, so that a
	// zone is not called insecure again on every hop below it.
	said map[string]trace.DNSSECState
}

// path is the result and every step above it, nil where there is no result.
func path(root, result *trace.Step) map[*trace.Step]bool {
	if result == nil {
		return nil
	}
	on := map[*trace.Step]bool{}
	var find func(*trace.Step) bool
	find = func(step *trace.Step) bool {
		if step == result {
			on[step] = true
			return true
		}
		if slices.ContainsFunc(step.Children, find) {
			on[step] = true
			return true
		}
		return false
	}
	find(root)
	return on
}

// mainline is whether a step is one of the walk's own questions to a server.
func mainline(step *trace.Step) bool {
	return step.Queried() && !step.Aside && !step.Apart
}

// servers tells what the servers under parent were asked: the one on the way
// to the answer in full, with those tried before it and beside it in a
// sentence. Where nothing below leads to an answer, every one is told, since
// the failures are the story.
func (s *story) servers(parent *trace.Step) {
	var asked []*trace.Step
	for _, child := range parent.Children {
		if mainline(child) {
			asked = append(asked, child)
		}
	}
	next := -1
	for i, step := range asked {
		if s.path[step] {
			next = i
			break
		}
	}
	if next < 0 {
		for i, step := range asked {
			s.hop(parent, step, nil, nil, i > 0)
		}
		return
	}
	var before, beside []*trace.Step
	for i, step := range asked {
		switch {
		case i < next && failed(step):
			before = append(before, step)
		case i != next:
			beside = append(beside, step)
		}
	}
	s.hop(parent, asked[next], before, beside, len(before) > 0)
}

func failed(step *trace.Step) bool {
	switch step.Kind {
	case trace.KindLame, trace.KindFiltered, trace.KindTimeout, trace.KindError:
		return true
	}
	return false
}

// hop writes one numbered paragraph, then goes on to the servers it led to.
func (s *story) hop(parent, step *trace.Step, before, beside []*trace.Step, again bool) {
	s.hops++
	var p []string
	for i, tried := range before {
		then := "first"
		if i > 0 {
			then = "next"
		}
		p = append(p, end(then+" it asked "+server(tried)+", which "+failure(tried)+", so it moved on"))
	}
	p = append(p, s.opening(parent, step, again))
	if step.Minimised {
		p = append(p, end("it asked about "+step.Asked.Name+" alone, not the whole name")+s.once("qmin",
			" with --qmin a server is told no more of the name than it needs to say where the next zone starts (RFC 9156), and what comes back is about that shorter name, not yet the answer.", ""))
	}
	p = append(p, notes(step)...)
	p = append(p, s.outcome(step)...)
	if sentence := s.dnssec(step); sentence != "" {
		p = append(p, sentence)
	}
	p = append(p, s.asides(step)...)
	if sentence := others(step, beside); sentence != "" {
		p = append(p, sentence)
	}

	number := strconv.Itoa(s.hops) + ". "
	s.paragraphs = append(s.paragraphs, wrap(strings.Join(p, " "), number, strings.Repeat(" ", len(number))))

	s.servers(step)
	for _, child := range step.Children {
		if restart(child) {
			s.servers(child)
		}
	}
}

// restart is the root an alias starts the walk again from.
func restart(step *trace.Step) bool {
	return step.Kind == trace.KindZone && !step.Aside && !step.Apart
}

// opening says who was asked and why that server.
func (s *story) opening(parent, step *trace.Step, again bool) string {
	who := server(step)
	what := question(step.Asked)
	if again {
		return end("then it asked " + who + " for " + what)
	}
	switch {
	case parent == s.trace.Root:
		line := end(fmt.Sprintf("dnstree starts at the root, the zone at the top of every name. it knows the addresses of the root servers from the list it starts with, and asked %s for %s%s",
			who, what, carried(step.Proto)))
		if status := parent.DNSSEC; status != nil && status.State == trace.Secure {
			line += " the root's key is the one every validating resolver is set up to trust (the trust anchor), so the chain of trust starts here."
		}
		return line
	case parent.Kind == trace.KindZone:
		return end("back at the root, it asked " + who + " for " + what)
	case parent.Delegation != nil && len(parent.Delegation.NS) == 1:
		return end("it asked " + who + ", the one server the referral named for " + parent.Delegation.Zone + ", for " + what)
	case parent.Delegation != nil:
		return end(fmt.Sprintf("it asked %s, one of the %d servers the referral named for %s, for %s",
			who, len(parent.Delegation.NS), parent.Delegation.Zone, what))
	}
	return end("it asked " + who + " for " + what)
}

func carried(proto string) string {
	switch proto {
	case "tcp":
		return ", over tcp"
	case "dot":
		return ", over tls (DNS over TLS, RFC 7858)"
	case "doh":
		return ", over https (DNS over HTTPS, RFC 8484)"
	}
	return ""
}

// notes says in words what it took to get the answer.
func notes(step *trace.Step) []string {
	var said []string
	for _, note := range step.Notes {
		switch {
		case strings.HasPrefix(note, "minimised to "):
		case strings.HasPrefix(note, "truncated over "):
			said = append(said, "the answer did not fit in a udp datagram (the server set the TC bit), so it asked again over tcp, which has no such limit.")
		case note == "asked again after a silence":
			said = append(said, "the first query went unanswered, so it asked again.")
		case note == "retried without EDNS0":
			said = append(said, "the server could not read the EDNS0 options the query carried, so it asked again without them.")
		default:
			said = append(said, end("it notes: "+note))
		}
	}
	return said
}

// outcome says what the server answered and what that means for the walk.
func (s *story) outcome(step *trace.Step) []string {
	zone := called(step.Zone)
	switch step.Kind {
	case trace.KindReferral:
		if step.Delegation == nil {
			return []string{zone + " does not hold the answer, and referred the walk further down."}
		}
		return s.referral(zone, step.Delegation)
	case trace.KindAnswer:
		line := zone + " holds the answer"
		if len(step.Records) > 0 {
			line += ": " + records(step.Records)
		}
		lines := []string{end(line)}
		if step.Flags.AA {
			lines = append(lines, "it said so with authority (the AA flag), since it serves the zone itself.")
		}
		return lines
	case trace.KindCNAME:
		target := alias(step)
		lines := []string{end(step.Asked.Name + " is an alias: " + zone + " answered with a CNAME record that points at " + target + ", so the question is now about " + target)}
		if slices.ContainsFunc(step.Children, restart) {
			lines = append(lines, "the target can be in any zone at all, so the walk starts again at the root for it.")
		}
		return lines
	case trace.KindNoData:
		return []string{zone + " says " + step.Asked.Name + " exists, but has no " + step.Asked.Type + " records (NODATA)." + soa(step)}
	case trace.KindNXDomain:
		line := zone + " says " + step.Asked.Name + " does not exist at all (NXDOMAIN)."
		if step.Compact {
			line += " it said so the way a zone that signs as it answers does: NOERROR, and a signed record that lists NXNAME (RFC 9824)."
		}
		return []string{line + soa(step)}
	case trace.KindLame, trace.KindFiltered, trace.KindTimeout, trace.KindError:
		return []string{"it " + failure(step) + "."}
	}
	return nil
}

func (s *story) referral(zone string, d *trace.Delegation) []string {
	if len(d.NS) == 0 {
		return []string{zone + " does not hold the answer, and referred the walk to " + d.Zone + " without naming a server for it."}
	}
	lines := []string{end(fmt.Sprintf("%s does not hold the answer, but knows who runs %s: it answered with a referral to %s: %s",
		zone, d.Zone, plural(len(d.NS), "server", "servers"), few(d.NS)))}

	var glued int
	for _, ns := range d.NS {
		if len(d.Glue[ns]) > 0 {
			glued++
		}
	}
	switch {
	case glued > 0 && glued == len(d.NS):
		lines = append(lines, s.once("glue", "it gave their addresses along with their names (glue), so there was nothing more to look up.",
			"it gave their addresses too."))
	case glued > 0:
		lines = append(lines, fmt.Sprintf("it gave addresses (glue) for %d of them.", glued))
	}
	if len(d.OutOfBailiwick) > 0 {
		lines = append(lines, "it gave no address for "+few(d.OutOfBailiwick)+", named outside "+d.Zone+s.once("bailiwick",
			": with no address for it, finding one takes a lookup of its own.", "."))
	}
	if len(d.GlueLess) > 0 {
		are := " are"
		if len(d.GlueLess) == 1 {
			are = " is"
		}
		lines = append(lines, list(d.GlueLess)+are+" named inside "+d.Zone+" yet came with no address, and nothing can find one: their address would be in the zone they serve. that part of the delegation is broken.")
	}
	if d.TTL > 0 {
		lines = append(lines, s.once("referral ttl", "a resolver may keep this referral for "+explain.Spell(d.TTL)+", so a change of nameservers takes that long to reach everyone.",
			"a resolver may keep it for "+explain.Spell(d.TTL)+"."))
	}
	return lines
}

func soa(step *trace.Step) string {
	if step.SOA == nil {
		return ""
	}
	return " it sent the zone's SOA record along, which says how long a resolver may remember that."
}

func alias(step *trace.Step) string {
	for _, record := range step.Records {
		if record.Type == "CNAME" {
			return record.Data
		}
	}
	return "another name"
}

// failure says how a server let the walk down.
func failure(step *trace.Step) string {
	switch step.Kind {
	case trace.KindTimeout:
		if step.RTT > 0 {
			return "did not answer within " + diagram.Duration(step.RTT)
		}
		return "did not answer"
	case trace.KindLame:
		return "answered, but not for " + called(step.Zone) + ": it does not serve the zone it was named for (a lame server)"
	case trace.KindFiltered:
		line := "turned the question away without consulting the zone"
		if len(step.Extended) > 0 {
			line += " (" + step.Extended[0].String() + ")"
		}
		return line
	}
	if step.Err != "" {
		return "failed: " + step.Err
	}
	return "failed"
}

// dnssec says where the chain of trust stands, where the walk checked it and
// the zone has not been said to be in that state already.
func (s *story) dnssec(step *trace.Step) string {
	status := step.DNSSEC
	if status == nil {
		return ""
	}
	zone := status.Zone
	if zone == "" {
		zone = step.Zone
		if step.Delegation != nil {
			zone = step.Delegation.Zone
		}
	}
	if s.said[zone] == status.State {
		return ""
	}
	s.said[zone] = status.State
	because := ""
	if status.Reason != "" {
		because = ": " + status.Reason
	}
	switch status.State {
	case trace.Secure:
		if step.Delegation != nil {
			return s.once("ds", "the chain of trust reaches "+zone+": the zone above signed a DS record, a digest of "+zone+"'s key, and the key matched it. that is how one zone vouches for the next.",
				"the chain of trust reaches "+zone+": the DS the zone above signed matched its key.")
		}
		return "the chain of trust holds: the records are signed with " + zone + "'s key, which the zone above vouched for, and the signatures checked out."
	case trace.Insecure:
		return zone + " is not signed" + because + "." + s.once("insecure", " nothing vouches for what is below it, and a validating resolver takes its answers as they come.", "")
	case trace.Bogus:
		return end("the chain of trust breaks at "+zone+because) + " a validating resolver refuses these answers, and answers SERVFAIL instead."
	case trace.Indeterminate:
		return "this build could not check the chain of trust at " + zone + because + ", which is not the same as broken."
	}
	return ""
}

// asides says what the hop needed asked on the side: the address of a
// nameserver named elsewhere, and the keys and DS the chain is checked with.
func (s *story) asides(step *trace.Step) []string {
	var lines, keys, ds, other []string
	for _, child := range step.Children {
		if !child.Aside || child.Apart {
			continue
		}
		if child.Kind == trace.KindZone {
			for _, note := range child.Notes {
				if name, ok := strings.CutPrefix(note, "resolving "); ok {
					lines = append(lines, detour(child, name))
				}
			}
			continue
		}
		if !child.Queried() {
			continue
		}
		// What a query was for is its last note: what it took to get the
		// answer, a retry over tcp, goes ahead of it.
		if len(child.Notes) == 0 {
			other = append(other, question(child.Asked))
			continue
		}
		note := child.Notes[len(child.Notes)-1]
		if zone, ok := strings.CutPrefix(note, "DNSKEY of "); ok {
			keys = append(keys, called(zone))
		} else if zone, ok := strings.CutPrefix(note, "DS of "); ok {
			ds = append(ds, called(zone))
		} else {
			other = append(other, note)
		}
	}
	if len(keys) > 0 {
		lines = append(lines, s.once("dnskey", "to check signatures, it also asked the same server for the keys of "+list(keys)+" (DNSKEY).",
			"it asked for the keys of "+list(keys)+" too."))
	}
	if len(ds) > 0 {
		lines = append(lines, "it also asked for the DS of "+list(ds)+", the record the zone above signs to vouch for a key.")
	}
	if len(other) > 0 {
		lines = append(lines, end("it asked "+plural(len(other), "more question", "more questions")+" on the side: "+list(other)))
	}
	return lines
}

// detour says what the walk did to find a nameserver's address.
func detour(root *trace.Step, name string) string {
	var queries int
	var found []string
	var look func(*trace.Step)
	look = func(step *trace.Step) {
		if step.Queried() {
			queries++
		}
		if step.Kind == trace.KindAnswer && !step.Minimised {
			for _, record := range step.Records {
				if (record.Type == "A" || record.Type == "AAAA") && strings.EqualFold(record.Name, name) {
					found = append(found, record.Data)
				}
			}
		}
		for _, child := range step.Children {
			look(child)
		}
	}
	look(root)
	line := "before it could go on, it had to find the address of " + name + ": a walk of its own from the root, " + plural(queries, "query", "queries")
	if len(found) == 0 {
		return line + ", which found none."
	}
	return end(line + ", which found " + list(found))
}

// others says how the servers asked beside the one the story follows came
// back, as --all asks all of them.
func others(step *trace.Step, beside []*trace.Step) string {
	if len(beside) == 0 {
		return ""
	}
	var order []string
	count := map[string]int{}
	for _, other := range beside {
		said := result(other)
		if count[said] == 0 {
			order = append(order, said)
		}
		count[said]++
	}
	parts := make([]string, len(order))
	for i, said := range order {
		parts[i] = strconv.Itoa(count[said]) + " " + said
	}
	return end(fmt.Sprintf("it put the same question to %s of %s as well, to hold them against each other: %s",
		plural(len(beside), "more server", "more servers"), called(step.Zone), list(parts)))
}

// result is how a server answered, short enough to be counted.
func result(step *trace.Step) string {
	switch step.Kind {
	case trace.KindReferral:
		if step.Delegation != nil {
			return "referred it to " + step.Delegation.Zone
		}
		return "referred it further down"
	case trace.KindAnswer:
		return "answered"
	case trace.KindCNAME:
		return "answered with the alias"
	case trace.KindNoData:
		return "said there was no such record"
	case trace.KindNXDomain:
		return "said there was no such name"
	case trace.KindLame:
		return "did not serve the zone"
	case trace.KindTimeout:
		return "did not answer"
	case trace.KindFiltered:
		return "turned it away"
	}
	return "failed"
}

// ending says what the walk came to.
func (s *story) ending() string {
	q := s.trace.Question
	found := s.trace.Result()
	var line string
	switch {
	case found == nil:
		line = "the walk ends without an answer for " + question(q) + "."
	case found.Kind == trace.KindAnswer:
		var data []string
		for _, record := range found.Records {
			if record.Type == q.Type {
				data = append(data, record.Data)
			}
		}
		line = "that is the end of the walk: " + question(q)
		if len(data) > 0 {
			line += " is " + list(data)
		} else {
			line += " was answered"
		}
		if aliases := s.aliases(); aliases > 0 {
			line += ", reached through " + plural(aliases, "alias", "aliases")
		}
		line += "."
	case found.Kind == trace.KindNoData:
		line = "that is the end of the walk: " + found.Asked.Name + " has no " + q.Type + " records."
	case found.Kind == trace.KindNXDomain:
		line = "that is the end of the walk: " + found.Asked.Name + " does not exist."
	default:
		line = "the walk ends at an alias it could not follow."
	}
	if found != nil && s.trace.Broken() {
		line += " the chain of trust is broken, though, so a validating resolver would not give this answer at all."
	}
	return line
}

func (s *story) aliases() int {
	var n int
	for step := range s.path {
		if step.Kind == trace.KindCNAME {
			n++
		}
	}
	return n
}

func server(step *trace.Step) string {
	ip := ""
	if step.Server.IP.IsValid() {
		ip = step.Server.IP.String()
	}
	switch {
	case step.Server.Name == "":
		return ip
	case ip == "":
		return step.Server.Name
	}
	return step.Server.Name + " (" + ip + ")"
}

func question(q trace.Question) string {
	return q.Name + " " + q.Type
}

func records(rrs []trace.RR) string {
	shown := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		shown = append(shown, fmt.Sprintf("%s %d %s %s", rr.Name, rr.TTL, rr.Type, rr.Data))
	}
	return few(shown)
}

// once is long the first time it is called for what, and short after that.
func (s *story) once(what, long, short string) string {
	if s.told[what] {
		return short
	}
	s.told[what] = true
	return long
}

// end closes a sentence, which a name closes already: a.example. is drawn
// as it is spelled, and another dot after it would read as part of the name.
func end(sentence string) string {
	if strings.HasSuffix(sentence, ".") {
		return sentence
	}
	return sentence + "."
}

// called is how a zone is named in a sentence, where a bare dot would be lost.
func called(zone string) string {
	if zone == "." {
		return "the root"
	}
	return zone
}

// few lists up to three items and counts the rest.
func few(items []string) string {
	if len(items) <= 3 {
		return list(items)
	}
	return strings.Join(items[:3], ", ") + " and " + strconv.Itoa(len(items)-3) + " more"
}

// list is items as a sentence lists them: "a, b and c".
func list(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// wrap breaks text into lines of at most width columns where it can; a word
// longer than that keeps its own line. The first line starts with first, and
// the rest with rest.
func wrap(text, first, rest string) string {
	var b strings.Builder
	line := first
	empty := true
	for word := range strings.FieldsSeq(text) {
		if !empty && len(line)+1+len(word) > width {
			b.WriteString(line)
			b.WriteByte('\n')
			line, empty = rest, true
		}
		if !empty {
			line += " "
		}
		line += word
		empty = false
	}
	b.WriteString(line)
	b.WriteByte('\n')
	return b.String()
}
