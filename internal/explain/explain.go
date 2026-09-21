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
	Trust                 // the chain of trust over it
	Spread                // what the nameservers of the zone have in common
	Servers               // the servers that made the walk harder
	Resolver              // what an ordinary resolution made of the same question
)

// Level is how much a finding matters, which is all a renderer needs in order
// to colour it.
type Level int

// How much a finding matters.
const (
	Note  Level = iota // worth knowing
	Warn               // cost the walk work, or is worth a look
	Fault              // why there is no answer, or none to trust
)

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
	if result := tr.Result(); result != nil && result.DNSSEC != nil {
		return result.DNSSEC, zoneOf(result)
	}

	var (
		status *trace.DNSSECStatus
		zone   string
	)
	for step := range tr.Mainline() {
		if step.DNSSEC != nil {
			status, zone = step.DNSSEC, zoneOf(step)
		}
	}
	return status, zone
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
	if tr.Resolver == nil || tr.Resolver.Match != trace.MatchDiffers {
		return Finding{}, false
	}
	return Finding{Topic: Resolver, Level: Warn, Text: "a recursive resolver answered this question differently, " +
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
