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
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Topic is what a finding is about, and the order the findings are said in:
// what the walk came to first, then what stands behind it.
type Topic int

// What a finding is about.
const (
	Outcome  Topic = iota // what the walk came to
	Cache                 // how long a cache may go on serving it
	Trust                 // the chain of trust over it
	Takeover              // what somebody else could take the name over with
	Spread                // what the nameservers of the zone have in common
	Servers               // the servers that made the walk harder
	Issuance              // who may issue certificates for the name
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
	case Takeover:
		return "takeover"
	case Spread:
		return "spread"
	case Servers:
		return "servers"
	case Issuance:
		return "issuance"
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
	tr = tr.Shown()

	findings := []Finding{outcome(tr)}
	findings = append(findings, cache(tr)...)
	findings = append(findings, trust(tr)...)
	findings = append(findings, hashing(tr)...)
	findings = append(findings, setup(tr)...)
	findings = append(findings, takeover(tr)...)
	findings = append(findings, spread(tr)...)
	findings = append(findings, servers(tr)...)
	findings = append(findings, cookies(tr)...)
	findings = append(findings, exposure(tr)...)
	if finding, ok := issuance(tr); ok {
		findings = append(findings, finding)
	}
	if finding, ok := comparison(tr); ok {
		findings = append(findings, finding)
	}
	findings = append(findings, designations(tr)...)
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
		text := fmt.Sprintf("%s does not exist, and %s is the zone that says so", tr.Question.Name, result.Zone)
		if result.Compact {
			text += ", answering NOERROR with a signed record that says it, the way a zone that signs as it answers does (RFC 9824)"
		}
		return Finding{Topic: Outcome, Level: Note, Text: text}

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
	if finding, ok := nameservers(tr); ok {
		findings = append(findings, finding)
	}
	findings = append(findings, leftover(tr)...)
	return findings
}

// nameservers is how long the nameservers of the zone the walk ended in go on
// being used after they change, where the parent and the zone disagree about
// it. Resolvers differ over whose copy they keep — the parent's, or the zone's
// own once they have seen it — so a change of nameservers takes the longer of
// the two to reach everybody. The parent's is often the registry's to choose,
// so a difference is the ordinary case and not a fault.
func nameservers(tr *trace.Trace) (Finding, bool) {
	zone := ended(tr)
	delegation := delegated(tr, zone)
	if delegation == nil || delegation.ZoneTTL == 0 || delegation.ZoneTTL == delegation.TTL {
		return Finding{}, false
	}
	return Finding{Topic: Cache, Level: Note, Text: fmt.Sprintf(
		"the parent hands out the nameservers of %s for %s and the zone gives its own for %s, so a change of nameservers takes up to %s to reach every resolver",
		zone, spell(delegation.TTL), spell(delegation.ZoneTTL), spell(max(delegation.TTL, delegation.ZoneTTL)))}, true
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
// zone would make it, or where the comparison read something in its TTL. A
// resolver that had to go and fetch the answer hands back the zone's lifetime
// entire, which says nothing the line above it has not; one that hands back
// less is answering from a cache, and how much less is how long it will go on
// doing so.
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
		switch {
		case answer.Kept == trace.KeptLonger:
			findings = append(findings, Finding{Topic: Cache, Level: Warn, Text: fmt.Sprintf(
				"%s keeps this for %s where the zone allows %s, so a change to it takes that long to reach the clients using it",
				answer.Server.IP, spell(cached), spell(tr.Allowed()))})
		case answer.Kept == trace.KeptStale:
			findings = append(findings, Finding{Topic: Cache, Level: Warn, Text: fmt.Sprintf(
				"%s looks to be serving a stale answer: no server of the zone gave it to the walk, "+
					"and %s left is what serve-stale hands out (RFC 8767); a resolver that cannot reach the zone does this",
				answer.Server.IP, spell(cached))})
		case cached != 0 && cached < zone:
			findings = append(findings, Finding{Topic: Cache, Level: Note, Text: fmt.Sprintf(
				"%s is answering this from its cache, with %s left on the copy it is serving",
				answer.Server.IP, spell(cached))})
		}
	}
	return findings
}

// trust is what the chain of trust came to, said only where one was followed.
// It claims no more than the walk checked: a zone this build could not check
// reads as unchecked, never as broken.
func trust(tr *trace.Trace) []Finding {
	step := tr.Chain()
	if step == nil {
		return nil
	}
	status, zone := step.DNSSEC, zoneOf(step)
	switch status.State {
	case trace.Bogus:
		return []Finding{{Topic: Trust, Level: Fault, Text: fmt.Sprintf(
			"the chain of trust breaks at %s%s, so a resolver that validates answers SERVFAIL for this name",
			zone, because(status.Reason))}}

	case trace.Indeterminate:
		return []Finding{{Topic: Trust, Level: Warn, Text: fmt.Sprintf(
			"the chain of trust at %s could not be checked%s, which is not the same as finding it broken",
			zone, because(status.Reason))}}

	case trace.Insecure:
		return []Finding{{Topic: Trust, Level: Note, Text: fmt.Sprintf(
			"%s is not signed%s, so nothing here vouches for the answer", zone, because(status.Reason))}}

	case trace.Secure:
		text := "the chain of trust holds from the root to " + zone
		if status.Algorithm != "" {
			text += ", signed with " + status.Algorithm
		}
		findings := []Finding{{Topic: Trust, Level: Note, Text: text}}
		if finding, ok := expiring(tr); ok {
			findings = append(findings, finding)
		}
		return findings
	}
	return nil
}

// expiring is the link of a chain that holds now and will not for long: a
// signature in the last fifth of the life it was made for, which a signer that
// is still working would have replaced by now. A zone that stops being
// re-signed validates to the last second and then fails all at once, which is
// why it is worth saying while there is still time to fix it.
func expiring(tr *trace.Trace) (Finding, bool) {
	step := tr.Stale()
	if step == nil {
		return Finding{}, false
	}
	left, _ := tr.Expiring(step.DNSSEC)
	return Finding{Topic: Trust, Level: Warn, Text: fmt.Sprintf(
		"a signature over %s runs out in %s, late in the life it was made for, and unless the zone is re-signed before then a resolver that validates answers SERVFAIL for this name",
		zoneOf(step), spell(uint32(left/time.Second)))}, true
}

// hashing is every zone whose NSEC3 records the walk checked and found hashed
// the way RFC 9276 asks zones to stop hashing: with extra iterations, which
// cost every validator work and let one stop trusting the proofs as the count
// grows, or with a salt, which can only be changed by re-signing the zone.
func hashing(tr *trace.Trace) []Finding {
	var (
		findings []Finding
		seen     = make(map[string]bool)
	)
	for step := range tr.Steps() {
		if step.DNSSEC == nil || step.DNSSEC.NSEC3 == nil {
			continue
		}
		hashed := step.DNSSEC.NSEC3
		zone := strings.ToLower(hashed.Zone)
		if seen[zone] || (hashed.Iterations == 0 && hashed.Salt == "") {
			continue
		}
		seen[zone] = true

		if hashed.Iterations == 0 {
			findings = append(findings, Finding{Topic: Trust, Level: Note, Text: fmt.Sprintf(
				"the NSEC3 records of %s are salted, which RFC 9276 asks zones to stop doing: it hides nothing, and changing it means re-signing the whole zone",
				hashed.Zone)})
			continue
		}
		salted := ""
		if hashed.Salt != "" {
			salted = " and salted"
		}
		findings = append(findings, Finding{Topic: Trust, Level: Warn, Text: fmt.Sprintf(
			"the NSEC3 records of %s hash each name %s%s, where RFC 9276 asks for no extra iterations and no salt: it costs every validator work, adds little against listing the zone, and a validator may stop trusting the proofs as the count grows; set the iterations to 0",
			hashed.Zone, plural(int(hashed.Iterations), "extra time", "extra times"), salted)})
	}
	return findings
}

// Where the advice comes from. It moves as the RFCs are updated, so each rule
// names its source in the sentence it writes.
var (
	// retired are the signing algorithms RFC 8624 says zones should no longer
	// sign with. The ones it forbids outright are not here: nothing here
	// validates them, so a zone signed with one is never secure.
	retired = map[string]bool{"RSASHA1": true, "RSASHA1-NSEC3-SHA1": true}

	// withdrawn are the DS digests RFC 8624 says a parent must not publish.
	withdrawn = map[string]bool{"SHA1": true, "GOST94": true}
)

// shortRSA is the length NIST has asked of an RSA signing key since 2013 (SP
// 800-131A).
const shortRSA = 2048

// setup is how each secure zone the walk entered is set up, where that falls
// short of the current advice. None of it is a verdict: the chain holds, and
// each sentence says what the walk saw rather than whose doing it is, since a
// zone at a hosting provider often cannot choose its algorithm, and a DS or a
// key with nothing to do is how a planned rollover looks halfway through.
func setup(tr *trace.Trace) []Finding {
	var (
		findings []Finding
		seen     = make(map[string]bool)
	)
	for step := range tr.Steps() {
		status := step.DNSSEC
		if status == nil || status.State != trace.Secure || len(status.Keys) == 0 {
			continue
		}
		// A walk always names the zone a verdict is about; a file that does not
		// leaves nothing for the sentences to be about.
		zone := status.Zone
		if zone == "" || seen[strings.ToLower(zone)] {
			continue
		}
		seen[strings.ToLower(zone)] = true

		var algorithms, lengths, short, idle []string
		for _, key := range status.Keys {
			if key.Revoked {
				continue
			}
			if retired[key.Algorithm] {
				algorithms = add(algorithms, key.Algorithm)
			}
			if key.Bits > 0 && key.Bits < shortRSA {
				lengths = add(lengths, strconv.Itoa(key.Bits))
				short = append(short, strconv.Itoa(int(key.Tag)))
			}
			if key.SEP && !key.Pointed && !key.Signs {
				idle = append(idle, strconv.Itoa(int(key.Tag)))
			}
		}
		if len(algorithms) > 0 {
			findings = append(findings, Finding{Topic: Trust, Level: Warn, Text: fmt.Sprintf(
				"%s signs with %s, which RFC 8624 says zones should no longer sign with and some validators already read as unsigned; rolling the zone to ECDSAP256SHA256 or ED25519 keeps it validated",
				zone, list(algorithms))})
		}
		// Short keys are common, and a zone that rolls them often is doing what
		// the advice of a decade ago asked: worth knowing, not a warning.
		if len(short) > 0 {
			keys, tags := "RSA keys", "tags"
			if len(short) == 1 {
				keys, tags = "an RSA key", "tag"
			}
			findings = append(findings, Finding{Topic: Trust, Level: Note, Text: fmt.Sprintf(
				"%s signs with %s of %s bits (%s %s), shorter than the %d bits NIST has asked of a signing key since 2013; the next rollover can make them longer",
				zone, keys, list(lengths), tags, list(short), shortRSA)})
		}
		findings = append(findings, digests(zone, status.DS)...)
		if len(idle) > 0 {
			findings = append(findings, Finding{Topic: Trust, Level: Note, Text: fmt.Sprintf(
				"%s publishes a key signing key that no DS points at and that signs none of its keys (tag %s): one waiting to be rolled in, or left by a rollover that never finished",
				zone, list(idle))})
		}
	}
	return findings
}

// digests is what the parent's DS records for a zone say about how it is set
// up: a digest RFC 8624 withdrew, and records that match none of the zone's
// keys. One whose digest could not be computed here is neither.
func digests(zone string, records []trace.DS) []Finding {
	var (
		findings  []Finding
		unmatched []string
	)
	for _, ds := range records {
		if ds.Match == trace.DSUnmatched {
			unmatched = add(unmatched, strconv.Itoa(int(ds.Tag)))
		}
		if !withdrawn[ds.Digest] {
			continue
		}
		fix := "; a SHA256 one in its place is what the advice asks for"
		if beside := slices.IndexFunc(records, func(other trace.DS) bool {
			return other.Tag == ds.Tag && other.Match == trace.DSMatched && !withdrawn[other.Digest]
		}); beside >= 0 {
			fix = fmt.Sprintf("; the %s one beside it is enough on its own", records[beside].Digest)
		}
		findings = append(findings, Finding{Topic: Trust, Level: Note, Text: fmt.Sprintf(
			"the parent of %s publishes a %s DS for it (tag %d), which RFC 8624 says a parent must not publish%s",
			zone, ds.Digest, ds.Tag, fix)})
	}
	if len(unmatched) > 0 {
		findings = append(findings, Finding{Topic: Trust, Level: Note, Text: fmt.Sprintf(
			"the parent of %s holds a DS that matches none of its keys (tag %s): left from an earlier key, or published ahead of one to come; it does no harm while another DS holds",
			zone, list(unmatched))})
	}
	return findings
}

// takeover is every name the walk found left pointing at something nobody
// holds. Each says what the walk saw and what somebody would have to create to
// take the name over, never that they can: a zone halfway through a move looks
// the same, and so does a service that does not let strangers in.
func takeover(tr *trace.Trace) []Finding {
	var (
		findings []Finding
		seen     = make(map[trace.Dangling]bool)
	)
	for step := range tr.Steps() {
		dangling := step.Dangling
		if dangling == nil || seen[*dangling] {
			continue
		}
		seen[*dangling] = true

		var text string
		switch dangling.Kind {
		case trace.DanglingNameserver:
			text = fmt.Sprintf("%s is delegated to %s, and %s: %s can answer for %s; take it out of the delegation",
				dangling.Name, dangling.Target, gone(dangling), whoever(dangling), dangling.Name)
		case trace.DanglingAlias:
			text = fmt.Sprintf("%s is an alias for %s, and %s: %s can answer for %s; remove the alias, or create its target again",
				dangling.Name, dangling.Target, gone(dangling), whoever(dangling), dangling.Name)
		case trace.DanglingLame:
			text = fmt.Sprintf("every nameserver of %s answered without authority for it, which is how a hosting service answers for a zone nobody has created there: where anybody can create one, whoever does can answer for %s; take the delegation away, or create the zone there again",
				dangling.Name, dangling.Name)
		default:
			continue
		}
		findings = append(findings, Finding{Topic: Takeover, Level: Warn, Text: text})
	}
	return findings
}

// gone is who says what is missing.
func gone(dangling *trace.Dangling) string {
	return fmt.Sprintf("%s says %s does not exist", named(dangling.Zone), dangling.Missing)
}

// whoever is who would have to create the missing name. A name missing above
// the one pointed at is a domain, which is registered; one missing where it is
// pointed at is a name inside a zone that exists, created by whoever that
// zone lets create one.
func whoever(dangling *trace.Dangling) string {
	if !strings.EqualFold(dangling.Missing, dangling.Target) {
		return "whoever registers " + dangling.Missing
	}
	return "whoever can create it in " + named(dangling.Zone)
}

// named is a zone as a sentence names it.
func named(zone string) string {
	if zone == "." {
		return "the root"
	}
	return zone
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
	glue, whole := glued(delegation)
	if !whole {
		return findings
	}
	if !slices.ContainsFunc(glue, four) {
		findings = append(findings, Finding{Topic: Spread, Level: Warn, Text: fmt.Sprintf(
			"the delegation of %s carries no IPv4 address for any of its nameservers, so a resolver without IPv6 has no way in",
			zone)})
	}
	for _, family := range []string{"IPv4", "IPv6"} {
		if network, ok := shared(glue, family == "IPv4"); ok {
			findings = append(findings, Finding{Topic: Spread, Level: Warn, Text: fmt.Sprintf(
				"every %s address of the nameservers of %s is in %s, so one route going away takes the whole zone with it",
				family, zone, network)})
		}
	}
	return findings
}

// shared is the one network every address of a family sits in, at the size
// routes are filtered at: a /24 for IPv4, a /48 for IPv6. A family with fewer
// than two addresses has no set to share one.
func shared(glue []netip.Addr, v4 bool) (netip.Prefix, bool) {
	bits := 48
	if v4 {
		bits = 24
	}
	var (
		network netip.Prefix
		count   int
	)
	for _, addr := range glue {
		if addr = addr.Unmap(); addr.Is4() != v4 {
			continue
		}
		prefix, _ := addr.Prefix(bits)
		if count > 0 && prefix != network {
			return netip.Prefix{}, false
		}
		network, count = prefix, count+1
	}
	return network, count > 1
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
	var silent, lame, tight []string
	unsigned := true
	for step := range tr.Steps() {
		switch step.Kind {
		case trace.KindTimeout:
			silent = add(silent, at(step))
		case trace.KindLame:
			lame = add(lame, at(step))
		}
		if step.Tight() {
			tight = add(tight, fmt.Sprintf("%s with %d of %d bytes", at(step), step.Size, step.Limit))
			unsigned = unsigned && !step.Flags.DO
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
	if len(tight) > 0 {
		text := fmt.Sprintf(
			"%s answered with almost nothing left of the datagram the answer had to fit in (%s), so one more record in the zone truncates it, and every resolver that asks then pays a second round trip over TCP for the whole of it",
			plural(len(tight), "server", "servers"), list(tight))
		if unsigned {
			// The walk saw what it asked for. A resolver that validates asks
			// for the signatures too and is answered with more than this, so
			// the room left is at most what is reported here and may be none.
			text += ", and this walk asked for no signatures: a resolver that does gets more than this"
		}
		findings = append(findings, Finding{Topic: Servers, Level: Warn, Text: text})
	}
	return findings
}

// cookies names the servers that answered the DNS cookie they were sent
// without one, or wrongly. One address can be many machines, so a server may
// be named under more than one of them.
func cookies(tr *trace.Trace) []Finding {
	said := map[trace.CookieState][]string{}
	for step := range tr.Steps() {
		if step.Cookie != "" {
			said[step.Cookie] = add(said[step.Cookie], at(step))
		}
	}

	var findings []Finding
	for _, about := range []struct {
		state trace.CookieState
		level Level
		text  string
	}{
		{trace.CookieMismatch, Warn, "answered with a client cookie other than the one sent, so the answer may not be the server's own"},
		{trace.CookieRejected, Warn, "answered BADCOOKIE even to the server cookie handed out, and no query carrying a cookie got an answer"},
		{trace.CookieMalformed, Warn, "answered with a dns cookie of a length no cookie has"},
		{trace.CookieAbsent, Note, "answered without a dns cookie, which is allowed and leaves nothing to tell a forged answer from a real one"},
	} {
		if servers := said[about.state]; len(servers) > 0 {
			findings = append(findings, Finding{Topic: Servers, Level: about.level, Text: fmt.Sprintf(
				"%s %s: %s", plural(len(servers), "server", "servers"), about.text, list(servers))})
		}
	}
	return findings
}

// exposure is what --check-axfr and --check-recursion found, one kind at a
// time. An open server is named with what to do about it; a sweep that found
// every server closed says so once, since that is what was being asked; and a
// server that could not be asked is named as unchecked, never as closed.
func exposure(tr *trace.Trace) []Finding {
	type about struct {
		zone string
		kind trace.ProbeKind
	}
	var (
		order []about
		held  = make(map[about]map[trace.ProbeState][]string)
	)
	for step := range tr.Steps() {
		if step.Probe == nil {
			continue
		}
		key := about{step.Zone, step.Probe.Kind}
		if held[key] == nil {
			order = append(order, key)
			held[key] = make(map[trace.ProbeState][]string)
		}
		held[key][step.Probe.State] = add(held[key][step.Probe.State], at(step))
	}

	var findings []Finding
	for _, key := range order {
		states := held[key]
		open, unchecked := states[trace.ProbeOpen], states[trace.ProbeUnchecked]
		asked := "a zone transfer"
		if key.kind == trace.ProbeRecursion {
			asked = "recursion"
		}
		switch {
		case len(open) > 0 && key.kind == trace.ProbeTransfer:
			findings = append(findings, Finding{Topic: Servers, Level: Warn, Text: fmt.Sprintf(
				"zone transfers of %s are open to anyone at %s, which lists every name in the zone to whoever asks; allow them only to the zone's own secondaries",
				key.zone, list(open))})
		case len(open) > 0:
			findings = append(findings, Finding{Topic: Servers, Level: Warn, Text: fmt.Sprintf(
				"recursion is open to anyone at %s, which makes an open resolver of a nameserver of %s that can be pointed at somebody else to flood them; turn recursion off there, or allow it only to your own clients",
				list(open), key.zone)})
		case len(unchecked) == 0 && key.kind == trace.ProbeTransfer:
			findings = append(findings, Finding{Topic: Servers, Level: Note, Text: fmt.Sprintf(
				"no nameserver of %s handed the zone to a stranger", key.zone)})
		case len(unchecked) == 0:
			findings = append(findings, Finding{Topic: Servers, Level: Note, Text: fmt.Sprintf(
				"no nameserver of %s looked up another name for a stranger", key.zone)})
		}
		if len(unchecked) > 0 {
			findings = append(findings, Finding{Topic: Servers, Level: Note, Text: fmt.Sprintf(
				"%s could not be asked for %s, so whether %s is open there is unknown",
				list(unchecked), asked, asked)})
		}
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

// designations are what --ddr learned of each resolver. An offer is only a
// claim until a client connects and finds the resolver's own address in the
// certificate (RFC 9462), and nothing here connects, so it is said as a claim.
// A resolver that could not be asked is on its own line under the tree.
func designations(tr *trace.Trace) []Finding {
	var findings []Finding
	for _, answer := range tr.Resolvers {
		if answer == nil || answer.DDR == nil || answer.DDR.Err != "" {
			continue
		}
		who := at2(answer.Server)
		switch found := answer.DDR; {
		case found.Rcode != "NOERROR" && found.Rcode != "NXDOMAIN":
		case len(found.Designated) == 0:
			findings = append(findings, Finding{Topic: Resolver, Level: Note, Text: fmt.Sprintf(
				"%s designates no encrypted resolver, so what is asked of it crosses the network readable by anyone on the way",
				who)})
		default:
			var protocols, targets []string
			for _, offer := range found.Designated {
				for _, proto := range offer.Protocols {
					protocols = add(protocols, proto)
				}
				targets = add(targets, offer.Target)
			}
			offers := "something this build cannot name"
			if len(protocols) > 0 {
				offers = list(protocols)
			}
			findings = append(findings, Finding{Topic: Resolver, Level: Note, Text: fmt.Sprintf(
				"%s says it can also be reached encrypted, over %s at %s; trust it only once the certificate there names %s, which --ddr does not check",
				who, offers, list(targets), who)})
		}
	}
	return findings
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

// issuance is who may issue certificates for the name, as the CAA set that
// decides it says, where --caa looked.
func issuance(tr *trace.Trace) (Finding, bool) {
	caa, name := tr.CAA, tr.Question.Name
	switch {
	case caa == nil:
		return Finding{}, false
	case caa.Refused != "":
		return Finding{Topic: Issuance, Level: Warn, Text: fmt.Sprintf(
			"every certificate authority has to refuse to issue for %s: %s", name, caa.Refused)}, true
	case caa.Undecided != "":
		return Finding{Topic: Issuance, Level: Warn, Text: fmt.Sprintf(
			"a certificate authority may refuse to issue for %s: %s", name, caa.Undecided)}, true
	case caa.Owner == "":
		return Finding{Topic: Issuance, Level: Note, Text: fmt.Sprintf(
			"no name from %s up has a CAA set, so any certificate authority may issue for it", name)}, true
	case caa.Issue == nil:
		return Finding{Topic: Issuance, Level: Note, Text: fmt.Sprintf(
			"the CAA set at %s names no issuer, so any certificate authority may issue for %s", caa.Owner, name)}, true
	}
	text := fmt.Sprintf("the CAA set at %s lets %s issue for %s", caa.Owner, issuers(caa.Issue), name)
	if !slices.Equal(caa.Issue.CAs, caa.Wildcard.CAs) {
		text += fmt.Sprintf(", and %s issue wildcards below it", issuers(caa.Wildcard))
	}
	return Finding{Topic: Issuance, Level: Note, Text: text}, true
}

// issuers names the authorities a set lets issue.
func issuers(issuers *trace.Issuers) string {
	switch {
	case issuers == nil:
		return "any certificate authority"
	case len(issuers.CAs) == 0:
		return "no certificate authority"
	case len(issuers.CAs) == 1:
		return "only " + issuers.CAs[0]
	}
	return "only " + strings.Join(issuers.CAs[:len(issuers.CAs)-1], ", ") + " and " + issuers.CAs[len(issuers.CAs)-1]
}
