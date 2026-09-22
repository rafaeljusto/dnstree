// Package explain reads a finished trace and says in sentences what the walk
// came to. It is the reasoning behind --explain, kept apart from the drawing so
// that what is said can be tested without a terminal.
//
// Nothing here works anything out for itself: every sentence is read off the
// trace the walk recorded, so the explanation and the tree above it cannot come
// to disagree.
package explain

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// Topic is what a finding is about, and the order the findings are said in:
// what the walk came to first, then what stands behind it.
type Topic int

// What a finding is about.
const (
	Outcome  Topic = iota // what the walk came to
	Cache                 // how long a cache may go on serving it
	Trust                 // the chain of trust over it
	Spread                // what the nameservers of the zone have in common
	Servers               // the servers that made the walk harder
	Resolver              // what an ordinary resolution made of the same question
	Change                // what is not what it was when this walk was last made
)

// String names the topic, for a renderer that groups the sentences by what
// they are about rather than only colouring them.
func (t Topic) String() string {
	switch t {
	case Cache:
		return "cache"
	case Trust:
		return "trust"
	case Spread:
		return "spread"
	case Servers:
		return "servers"
	case Resolver:
		return "resolver"
	case Change:
		return "change"
	default:
		return "outcome"
	}
}

// Level is how much a finding matters, which is all a renderer needs in order
// to colour it.
type Level int

// How much a finding matters.
const (
	Note  Level = iota // worth knowing
	Warn               // cost the walk work, or is worth a look
	Fault              // why there is no answer, or none to trust
)

// String names the level, for a renderer that cannot colour a sentence and has
// to say how much it matters some other way.
func (l Level) String() string {
	switch l {
	case Warn:
		return "warn"
	case Fault:
		return "fault"
	default:
		return "note"
	}
}

// Finding is one thing worth saying about a resolution.
type Finding struct {
	Topic Topic
	Level Level

	// Text is the sentence itself, lowercase and without a full stop, the way
	// the rest of the output is written.
	Text string
}

// Findings is what a finished trace says about itself. There is always an
// outcome; everything after it is there because the walk met it.
func Findings(tr *trace.Trace) []Finding {
	if tr == nil || tr.Root == nil {
		return nil
	}

	findings := []Finding{outcome(tr)}
	findings = append(findings, cache(tr)...)
	findings = append(findings, trust(tr)...)
	findings = append(findings, spread(tr)...)
	findings = append(findings, servers(tr)...)
	if finding, ok := comparison(tr); ok {
		findings = append(findings, finding)
	}
	return findings
}

// outcome is the one finding every trace has: what the walk came to, and where.
func outcome(tr *trace.Trace) Finding {
	question := tr.Question.Name + " " + tr.Question.Type
	result := tr.Result()

	// A walk that was turned away is not a walk that found nothing: something
	// did answer, and what it answered was that it would not.
	if step := tr.Filtered(); step != nil && result == nil {
		text := fmt.Sprintf("%s was withheld by %s: this answer was decided rather than served", question, at(step))
		if reason := withheld(step); reason != "" {
			text += ", and the server called it " + reason
		}
		return Finding{Topic: Outcome, Level: Fault, Text: text}
	}
	if result == nil {
		return Finding{Topic: Outcome, Level: Fault, Text: unanswered(tr, question)}
	}

	switch result.Kind {
	case trace.KindNXDomain:
		return Finding{Topic: Outcome, Level: Note, Text: fmt.Sprintf(
			"%s does not exist, and %s is the zone that says so", tr.Question.Name, result.Zone)}

	case trace.KindNoData:
		return Finding{Topic: Outcome, Level: Note, Text: fmt.Sprintf(
			"%s exists but has no %s record, which %s answered for it",
			tr.Question.Name, tr.Question.Type, result.Zone)}

	case trace.KindCNAME:
		text := fmt.Sprintf("%s is an alias, and the walk ended on it without an answer", tr.Question.Name)
		if target := first(trace.Answers(result.Records, "CNAME")); target != "" {
			text = fmt.Sprintf("%s is an alias for %s, and the walk ended there without an answer",
				tr.Question.Name, target)
		}
		return Finding{Topic: Outcome, Level: Warn, Text: text}
	}

	text := fmt.Sprintf("%s was answered by %s for %s", question, at(result), result.Zone)
	if answers := trace.Answers(result.Records, tr.Question.Type); len(answers) > 0 {
		text = fmt.Sprintf("%s is %s, answered by %s for %s",
			question, list(answers), at(result), result.Zone)
	}
	if followed := aliases(tr); followed > 0 {
		text += ", after " + plural(followed, "alias", "aliases")
	}
	return Finding{Topic: Outcome, Level: Note, Text: text}
}

// unanswered says why a walk that reached nothing stopped where it did. The
// zone it was working on when it stopped is the one worth naming: everything
// above it answered.
func unanswered(tr *trace.Trace, question string) string {
	text := "nothing answered for " + question
	zone, why := stopped(tr)
	if zone == "" {
		return text
	}
	text += ", and the walk stopped at " + zone
	if why != "" {
		text += ": " + why
	}
	return text
}

// stopped is the last hop of the resolution proper, and why it was the last
// where nothing else will say. The asides are left out: a nameserver address
// looked up on the way is work the walk did, not where it got to. A silence and
// a lame answer carry no reason here because the servers that gave them are
// named further down, and saying it twice reads as two findings.
func stopped(tr *trace.Trace) (zone, why string) {
	for step := range tr.Mainline() {
		switch step.Kind {
		case trace.KindTimeout, trace.KindLame:
			zone, why = step.Zone, ""
		case trace.KindError:
			zone, why = step.Zone, step.Err
		case trace.KindReferral:
			zone, why = step.Zone, ""
			if step.Delegation != nil {
				zone, why = step.Delegation.Zone, "the walk got no further than its delegation"
			}
		}
	}
	return zone, why
}

// cache is how long what the walk found goes on being served after it has
// changed. Every number in it is a TTL the walk recorded; what is added is the
// arithmetic nobody wants to be doing in their head with a change window open.
func cache(tr *trace.Trace) []Finding {
	var findings []Finding
	if finding, ok := lifetimes(tr); ok {
		findings = append(findings, finding)
	}
	findings = append(findings, leftover(tr)...)
	return findings
}

// lifetimes is what a cache may hold this resolution for: what the walk came
// to, and the delegation it took to get there. The two are said together
// because they are the two halves of one question and they are usually days
// apart — changing a record is over in minutes, changing the nameservers that
// serve it is not — and a resolution with neither is said nothing about.
func lifetimes(tr *trace.Trace) (Finding, bool) {
	result := tr.Result()
	if result == nil {
		return Finding{}, false
	}
	answer, what := held(result, tr.Question.Type)

	var cut uint32
	zone := ended(tr)
	if delegation := delegated(tr, zone); delegation != nil {
		cut = delegation.TTL
	}

	var text string
	switch {
	case answer > 0 && cut > 0:
		text = fmt.Sprintf("a cache may hold %s for %s, and the delegation to %s for %s",
			what, spell(answer), zone, spell(cut))
	case answer > 0:
		text = fmt.Sprintf("a cache may hold %s for %s", what, spell(answer))
	case cut > 0:
		text = fmt.Sprintf("a cache may hold the delegation to %s for %s", zone, spell(cut))
	default:
		return Finding{}, false
	}
	return Finding{Topic: Cache, Level: Note, Text: text}, true
}

// held is how long a cache may keep what the walk came to, and what to call it.
// An answer carries its lifetime on the records that answer; a denial carries
// no records to carry one, and says in the zone's SOA how long being denied
// lasts instead — the shorter of the two fields that can say so (RFC 2308).
func held(result *trace.Step, qtype string) (uint32, string) {
	switch result.Kind {
	case trace.KindNXDomain, trace.KindNoData:
		if result.SOA == nil {
			return 0, ""
		}
		return min(result.SOA.TTL, result.SOA.Minimum), "this denial"
	}
	return trace.TTL(result.Records, qtype), "this answer"
}

// leftover is the resolver's own copy, said only where it is older than the
// zone would make it. A resolver that had to go and fetch the answer hands back
// the zone's lifetime entire, which says nothing the line above it has not; one
// that hands back less is answering from a cache, and how much less is how long
// it will go on doing so.
func leftover(tr *trace.Trace) []Finding {
	result := tr.Result()
	if result == nil {
		return nil
	}
	zone := trace.TTL(result.Records, tr.Question.Type)
	if zone == 0 {
		return nil
	}

	var findings []Finding
	for _, answer := range tr.Resolvers {
		cached := trace.TTL(answer.Records, tr.Question.Type)
		if cached == 0 || cached >= zone {
			continue
		}
		findings = append(findings, Finding{Topic: Cache, Level: Note, Text: fmt.Sprintf(
			"%s is answering this from its cache, with %s left on the copy it is serving",
			answer.Server.IP, spell(cached))})
	}
	return findings
}

// trust is what the chain of trust came to, said only where one was followed.
// It claims no more than the walk checked: a zone this build could not check
// reads as unchecked, never as broken.
func trust(tr *trace.Trace) []Finding {
	var checked bool
	for step := range tr.Steps() {
		if step.DNSSEC != nil {
			checked = true
			break
		}
	}
	if !checked {
		return nil
	}

	// Bogus is read the way the exit code reads it: anywhere in the trace, and
	// ahead of everything else.
	if step := state(tr, trace.Bogus); step != nil {
		return []Finding{{Topic: Trust, Level: Fault, Text: fmt.Sprintf(
			"the chain of trust breaks at %s%s, so a resolver that validates answers SERVFAIL for this name",
			zoneOf(step), because(step.DNSSEC.Reason))}}
	}
	if step := state(tr, trace.Indeterminate); step != nil {
		return []Finding{{Topic: Trust, Level: Warn, Text: fmt.Sprintf(
			"the chain of trust at %s could not be checked%s, which is not the same as finding it broken",
			zoneOf(step), because(step.DNSSEC.Reason))}}
	}

	status, zone := final(tr)
	if status == nil {
		return nil
	}
	switch status.State {
	case trace.Insecure:
		return []Finding{{Topic: Trust, Level: Note, Text: fmt.Sprintf(
			"%s is not signed%s, so nothing here vouches for the answer", zone, because(status.Reason))}}

	case trace.Secure:
		text := "the chain of trust holds from the root to " + zone
		if status.Algorithm != "" {
			text += ", signed with " + status.Algorithm
		}
		return []Finding{{Topic: Trust, Level: Note, Text: text}}
	}
	return nil
}

// state is the first hop the chain reached this state at, nil for a state it
// never did.
func state(tr *trace.Trace, want trace.DNSSECState) *trace.Step {
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.State == want {
			return step
		}
	}
	return nil
}

// final is the state the answer itself rests on: the one recorded where the
// walk ended, or the last it reached when it ended without an answer.
func final(tr *trace.Trace) (*trace.DNSSECStatus, string) {
	step := tr.Trust()
	if step == nil {
		return nil, ""
	}
	return step.DNSSEC, zoneOf(step)
}

// zoneOf is the zone a verdict is about, which the walk recorded on the verdict
// itself. It is not the zone of the step the verdict is drawn on: a cut is
// judged from above, so a referral holds the verdict of the zone it points at,
// and naming the wrong one is naming the wrong zone as broken.
func zoneOf(step *trace.Step) string {
	if step.DNSSEC != nil && step.DNSSEC.Zone != "" {
		return step.DNSSEC.Zone
	}
	return step.Zone
}

// spread is what the nameservers of the zone the walk ended in have in common,
// which is what the zone can lose the whole of at once. It is arithmetic over
// the delegation and the origin AS lookups and nothing else, and it says
// nothing where those are not all there: a set half of which is unaccounted for
// cannot be held against itself. Only the zone the walk came to rest in is
// read — the zones above it are somebody else's to answer for, and how they are
// spread is not news.
func spread(tr *trace.Trace) []Finding {
	zone := ended(tr)
	delegation := delegated(tr, zone)
	if delegation == nil || len(delegation.NS) == 0 {
		return nil
	}

	// One name is the whole finding, and it is the parent's own word rather
	// than anything that had to be looked up.
	if len(delegation.NS) == 1 {
		return []Finding{{Topic: Spread, Level: Warn, Text: fmt.Sprintf(
			"%s is delegated to one nameserver, %s, so it has nothing to fall back on",
			zone, delegation.NS[0])}}
	}

	var findings []Finding
	if as, ok := concentrated(asked(tr, zone), delegation.NS); ok {
		findings = append(findings, Finding{Topic: Spread, Level: Warn, Text: fmt.Sprintf(
			"all %d nameservers of %s are in AS%d, so one operator's outage takes the whole zone with it",
			len(delegation.NS), zone, as)})
	}
	if glue, whole := glued(delegation); whole && !slices.ContainsFunc(glue, four) {
		findings = append(findings, Finding{Topic: Spread, Level: Warn, Text: fmt.Sprintf(
			"the delegation of %s carries no IPv4 address for any of its nameservers, so a resolver without IPv6 has no way in",
			zone)})
	}
	return findings
}

// ended is the zone the walk came to rest in: the one that answered, or the
// last it reached when nothing did.
func ended(tr *trace.Trace) string {
	if result := tr.Result(); result != nil {
		return result.Zone
	}

	var zone string
	for step := range tr.Mainline() {
		if step.Kind != trace.KindZone {
			zone = step.Zone
		}
	}
	return zone
}

// delegated is the referral that pointed the walk at zone, nil for a zone
// nothing referred it to: the root, or wherever a walk was told to start.
func delegated(tr *trace.Trace, zone string) *trace.Delegation {
	for step := range tr.Mainline() {
		if step.Delegation != nil && strings.EqualFold(step.Delegation.Zone, zone) {
			return step.Delegation
		}
	}
	return nil
}

// asked is the servers of the zone the walk actually put a question to, by the
// name the delegation gave them. Only these carry an origin AS: the lookups
// start as the walk reaches a server, so a nameserver nobody asked is a
// nameserver nobody looked up, and --all is what asks all of them.
func asked(tr *trace.Trace, zone string) map[string][]trace.Server {
	servers := make(map[string][]trace.Server)
	for step := range tr.Mainline() {
		switch {
		case step.Kind == trace.KindZone || step.Kind == trace.KindSkipped:
			continue
		case !strings.EqualFold(step.Zone, zone) || step.Server.Name == "":
			continue
		}
		name := strings.ToLower(step.Server.Name)
		servers[name] = append(servers[name], step.Server)
	}
	return servers
}

// concentrated is the one AS every nameserver of the zone sits in. It reports
// false where they sit in more than one, where one was never asked, and where
// the lookups did not answer for one that was: an address with no AS against it
// is a gap rather than a server with no AS, and a set with a gap in it is not
// one that can be called concentrated.
func concentrated(asked map[string][]trace.Server, names []string) (uint32, bool) {
	var (
		only  uint32
		found bool
	)
	for _, name := range names {
		servers := asked[strings.ToLower(name)]
		if len(servers) == 0 {
			return 0, false
		}
		for _, server := range servers {
			if server.ASN == nil {
				return 0, false
			}
			if found && server.ASN.Number != only {
				return 0, false
			}
			only, found = server.ASN.Number, true
		}
	}
	return only, found
}

// glued is every address the parent handed out for the zone, and whether it
// handed one out for every nameserver it named. The glue is the parent's own
// answer, entire: the steps of a walk are not, since a walk lists only so many
// of the servers it did not ask before counting the rest.
func glued(delegation *trace.Delegation) ([]netip.Addr, bool) {
	given := make(map[string][]netip.Addr, len(delegation.Glue))
	for name, addresses := range delegation.Glue {
		given[strings.ToLower(name)] = addresses
	}

	var addresses []netip.Addr
	for _, name := range delegation.NS {
		glue := given[strings.ToLower(name)]
		if len(glue) == 0 {
			return nil, false
		}
		addresses = append(addresses, glue...)
	}
	return addresses, true
}

// four reports whether an address is one a client with no IPv6 can reach.
func four(addr netip.Addr) bool {
	return addr.Is4() || addr.Is4In6()
}

// servers names the ones that made the walk harder, whether or not it got an
// answer in the end: a resolution that succeeded over a dead nameserver is one
// outage away from failing.
func servers(tr *trace.Trace) []Finding {
	var silent, lame []string
	for step := range tr.Steps() {
		switch step.Kind {
		case trace.KindTimeout:
			silent = add(silent, at(step))
		case trace.KindLame:
			lame = add(lame, at(step))
		}
	}

	var findings []Finding
	if len(silent) > 0 {
		findings = append(findings, Finding{Topic: Servers, Level: Warn, Text: fmt.Sprintf(
			"%s did not answer in time: %s", plural(len(silent), "server", "servers"), list(silent))})
	}
	if len(lame) > 0 {
		findings = append(findings, Finding{Topic: Servers, Level: Warn, Text: fmt.Sprintf(
			"%s answered without authority for the zone asked about, usually a delegation left pointing at a server that no longer serves it: %s",
			plural(len(lame), "server", "servers"), list(lame))})
	}
	return findings
}

// comparison is worth a line only where the two disagree. Agreement is what the
// reader is expecting, and the summary already says the walk was timed against
// an ordinary resolution.
func comparison(tr *trace.Trace) (Finding, bool) {
	var differing []string
	for _, answer := range tr.Resolvers {
		if answer.Match == trace.MatchDiffers {
			differing = add(differing, at2(answer.Server))
		}
	}
	if len(differing) == 0 {
		return Finding{}, false
	}

	return Finding{Topic: Resolver, Level: Warn,
		Text: list(differing) + " answered this question differently, " +
			"which a name whose answer is tailored to where it is asked from does honestly, and nothing else should"}, true
}

// aliases is how many times the walk followed an alias before it answered.
func aliases(tr *trace.Trace) int {
	var count int
	for step := range tr.Mainline() {
		if step.Kind == trace.KindCNAME {
			count++
		}
	}
	return count
}

// at2 is a server as a reader would name it, for the ones that are an address
// and nothing else.
func at2(server trace.Server) string {
	switch {
	case server.Name != "":
		return server.Name
	case server.IP.IsValid():
		return server.IP.String()
	}
	return "a resolver"
}

// at is the server a step went to, as a reader would name it.
func at(step *trace.Step) string {
	switch {
	case step.Server.Name != "":
		return step.Server.Name
	case step.Server.IP.IsValid():
		return step.Server.IP.String()
	}
	return step.Zone
}

// withheld is what the server called the answer it would not give, in the
// registered names of RFC 8914 alone. The text beside them is the server's own
// words, and those have no business in output that --format ascii promises to
// keep under codepoint 127.
func withheld(step *trace.Step) string {
	var names []string
	for _, extended := range step.Extended {
		if extended.Reason != "" {
			names = add(names, strings.ToLower(extended.Reason))
		}
	}
	return list(names)
}

// because reads a recorded reason into the sentence in front of it, and adds
// nothing where there is none.
func because(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}

// list is a handful of names in a sentence. A walk can meet more servers than
// anyone wants read out, so the tail is counted rather than named.
func list(items []string) string {
	const most = 3
	switch {
	case len(items) == 0:
		return ""
	case len(items) == 1:
		return items[0]
	case len(items) > most:
		return strings.Join(items[:most], ", ") + fmt.Sprintf(" and %d more", len(items)-most)
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func add(names []string, name string) []string {
	if name == "" || slices.Contains(names, name) {
		return names
	}
	return append(names, name)
}

// spell writes a lifetime out in words: the largest unit it fills, and the one
// below where there is a remainder. It is read by somebody working out whether
// to wait through it, so "2 days" earns its room over "172800" and over "48h".
func spell(seconds uint32) string {
	switch n := int(seconds); {
	case n < 60:
		return plural(n, "second", "seconds")
	case n < 3600:
		return spelled(n, 60, 1, "minute", "second")
	case n < 86400:
		return spelled(n, 3600, 60, "hour", "minute")
	default:
		return spelled(n, 86400, 3600, "day", "hour")
	}
}

// spelled is a count of one unit and, where the remainder does not divide away,
// of the one below it. Two are as far as it goes: the third would be noise
// against the first, and nobody waiting out a delegation cares about seconds.
func spelled(seconds, size, smaller int, unit, below string) string {
	whole := plural(seconds/size, unit, unit+"s")
	if rest := (seconds % size) / smaller; rest > 0 {
		return whole + " " + plural(rest, below, below+"s")
	}
	return whole
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func first(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[0]
}
