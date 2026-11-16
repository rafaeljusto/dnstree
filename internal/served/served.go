// Package served holds what a zone's servers say against what the servers it
// is moving to say, question by question, which is what --compare-ns prints.
// It reads two finished walks and asks nothing of its own.
package served

import (
	"maps"
	"slices"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Answer is what the servers of one zone said to one question.
type Answer struct {
	// Kind is how they answered: answer, cname, nodata, nxdomain or referral.
	// It is empty where none of them did.
	Kind string

	// Records are what they gave, each as "OWNER TYPE DATA", sorted and with
	// the owner lowercased.
	Records []string

	// TTLs are the TTL of each set they gave, keyed "OWNER TYPE".
	TTLs map[string]uint32
}

// left are the types two providers serve differently by design: each signs
// with its own keys, so its signatures and denials are its own too.
var left = map[string]bool{"RRSIG": true, "NSEC": true, "NSEC3": true}

// Of is what the servers of zone said to the question the walk asked. It is
// the first of them to answer in the walk, which is the reply a resolver
// would have cached, and not where the walk ended: an alias the zone serves
// is what the zone serves, wherever its target lives.
func Of(tr *trace.Trace, zone string) Answer {
	tr = tr.Shown()
	question := tr.Question
	for step := range tr.Mainline() {
		if step.Minimised || !strings.EqualFold(step.Zone, zone) ||
			!strings.EqualFold(step.Asked.Name, question.Name) || !strings.EqualFold(step.Asked.Type, question.Type) {
			continue
		}
		switch step.Kind {
		case trace.KindAnswer, trace.KindCNAME, trace.KindNoData, trace.KindNXDomain:
			answer := Answer{Kind: string(step.Kind), TTLs: map[string]uint32{}}
			for _, record := range step.Records {
				if !left[strings.ToUpper(record.Type)] {
					answer.add(record.Name, record.Type, record.Data, record.TTL)
				}
			}
			answer.sort()
			return answer
		case trace.KindReferral:
			// A cut further down the zone is the zone's to serve too, and
			// a copy can lose it like any record.
			answer := Answer{Kind: string(step.Kind), TTLs: map[string]uint32{}}
			if delegation := step.Delegation; delegation != nil {
				for _, ns := range delegation.NS {
					answer.add(delegation.Zone, "NS", ns, delegation.TTL)
				}
			}
			answer.sort()
			return answer
		}
	}
	return Answer{}
}

func (a *Answer) add(owner, rrtype, data string, ttl uint32) {
	set := strings.ToLower(owner) + " " + strings.ToUpper(rrtype)
	a.Records = append(a.Records, set+" "+data)
	if have, ok := a.TTLs[set]; !ok || ttl < have {
		a.TTLs[set] = ttl
	}
}

func (a *Answer) sort() {
	slices.Sort(a.Records)
	a.Records = slices.Compact(a.Records)
}

// Match is one question, asked of the servers a zone is delegated to and of
// the ones it was tried at.
type Match struct {
	Question trace.Question

	// Zone is the zone tried, and Servers the servers it was tried at, as
	// --compare-ns named them.
	Zone    string
	Servers []string

	Current, Tried Answer

	// Missing are the records only the current servers gave, and Extra the
	// ones only the tried servers did.
	Missing, Extra []string

	// TTLs are the sets both gave, with the same records and another TTL.
	TTLs []TTL
}

// TTL is one set served with a TTL on each side.
type TTL struct {
	Set            string
	Current, Tried uint32
}

// Hold compares a walk of the DNS as it is with a walk of the same question
// made as though the zone were delegated as tried.Trial says.
func Hold(current, tried *trace.Trace) Match {
	shown := tried.Shown()
	match := Match{Question: shown.Question}
	if shown.Trial != nil {
		match.Zone, match.Servers = shown.Trial.Zone, shown.Trial.NS
	}
	match.Current, match.Tried = Of(current, match.Zone), Of(tried, match.Zone)
	match.compare()
	return match
}

// Filed is what a zone file says the answer to a question is, read from the
// records it holds for it.
func Filed(records []trace.RR) Answer {
	answer := Answer{Kind: string(trace.KindAnswer), TTLs: map[string]uint32{}}
	for _, record := range records {
		answer.add(trace.Shown(record.Name), trace.Shown(record.Type), trace.Shown(record.Data), record.TTL)
	}
	answer.sort()
	return answer
}

// AgainstFile compares what a zone file says of a question, as Current, with
// what the zone's servers said to it in the walk, as Tried. A serial is left
// out of both: a signer that bumps it serves the same zone, and the rest of
// the SOA still has to match.
func AgainstFile(file Answer, walked *trace.Trace, zone string) Match {
	match := Match{Question: walked.Shown().Question, Zone: zone, Current: file, Tried: Of(walked, zone)}
	switch trace.StepKind(match.Tried.Kind) {
	case trace.KindAnswer, trace.KindCNAME, trace.KindReferral:
		// An alias or a cut is how a file's records are served, not a
		// difference from them.
		match.Current.Kind = match.Tried.Kind
	}
	match.Current, match.Tried = match.Current.unserial(), match.Tried.unserial()
	match.compare()
	return match
}

// unserial is the answer with the serial of each SOA record put as "-". The
// serial is the fifth field from the end, whatever the names before it hold.
func (a Answer) unserial() Answer {
	var records []string
	for _, record := range a.Records {
		for set := range a.TTLs {
			if strings.HasSuffix(set, " SOA") && strings.HasPrefix(record, set+" ") {
				fields := strings.Split(record, " ")
				if len(fields) >= 5 {
					fields[len(fields)-5] = "-"
					record = strings.Join(fields, " ")
				}
				break
			}
		}
		records = append(records, record)
	}
	a.Records = records
	a.sort()
	return a
}

// compare fills what tells the two sides apart.
func (m *Match) compare() {
	m.Missing = without(m.Current.Records, m.Tried.Records)
	m.Extra = without(m.Tried.Records, m.Current.Records)
	for _, set := range slices.Sorted(maps.Keys(m.Current.TTLs)) {
		was := m.Current.TTLs[set]
		is, ok := m.Tried.TTLs[set]
		if ok && was != is && !changed(set, m.Missing, m.Extra) {
			m.TTLs = append(m.TTLs, TTL{Set: set, Current: was, Tried: is})
		}
	}
}

// Same reports whether both sides answered alike, TTLs included: a TTL left
// at a provider's default is how a change meant to take minutes takes a day.
func (m Match) Same() bool {
	return m.Current.Kind == m.Tried.Kind && len(m.Missing) == 0 && len(m.Extra) == 0 && len(m.TTLs) == 0
}

// without is what a holds that b does not.
func without(a, b []string) []string {
	var only []string
	for _, record := range a {
		if _, found := slices.BinarySearch(b, record); !found {
			only = append(only, record)
		}
	}
	return only
}

// changed reports whether a set's records differ already, which says more
// than its TTL does.
func changed(set string, lists ...[]string) bool {
	for _, list := range lists {
		for _, record := range list {
			if strings.HasPrefix(record, set+" ") {
				return true
			}
		}
	}
	return false
}
