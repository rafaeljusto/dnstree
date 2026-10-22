package history

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
)

// Changes is what is not what it was, said the way the rest of the explanation
// is said. It compares two remembered walks and nothing else: a fact neither of
// them kept is a fact this cannot have watched change, and a fact only one of
// them kept is not a change but a difference in what was asked for — a run
// without --dnssec is not a zone that stopped being signed.
//
// There is always something to say, because silence here reads as no change
// when it may mean no memory.
func Changes(before, now *Walk) []explain.Finding {
	question := now.Question.Name + " " + now.Question.Type
	if before == nil {
		return []explain.Finding{{Topic: explain.Change, Level: explain.Note, Text: fmt.Sprintf(
			"nothing to compare: this is the first walk of %s that was remembered", question)}}
	}

	age := ago(now.Seen.Sub(before.Seen))
	findings := Differences(before, now)
	if len(findings) == 0 {
		return []explain.Finding{{Topic: explain.Change, Level: explain.Note, Text: fmt.Sprintf(
			"nothing has changed since the walk of %s %s", question, age)}}
	}

	return slices.Insert(findings, 0, explain.Finding{
		Topic: explain.Change, Level: explain.Note,
		Text: fmt.Sprintf("the walk of %s before this one was %s", question, age),
	})
}

// Against is what [Changes] says of a walk held against one saved to a file,
// which is named in place of an age: the two may come from two machines rather
// than two times, so the framing says how far apart they were made either way.
func Against(before, now *Walk, source string) []explain.Finding {
	question := now.Question.Name + " " + now.Question.Type
	when := "at a time it does not say" // a walk saved before dnstree kept when it started
	if !before.Seen.IsZero() && !now.Seen.IsZero() {
		when = made(now.Seen.Sub(before.Seen))
	}

	findings := Differences(before, now)
	if len(findings) == 0 {
		return []explain.Finding{{Topic: explain.Change, Level: explain.Note, Text: fmt.Sprintf(
			"nothing differs from the walk of %s in %s, made %s", question, source, when)}}
	}
	return slices.Insert(findings, 0, explain.Finding{
		Topic: explain.Change, Level: explain.Note,
		Text: fmt.Sprintf("held against the walk of %s in %s, made %s", question, source, when),
	})
}

// Asks reports whether the walk was made for this question, which is the only
// thing a comparison between two walks makes sense of.
func (w *Walk) Asks(name, qtype, class string) bool {
	return strings.EqualFold(strings.TrimSuffix(w.Question.Name, "."), strings.TrimSuffix(name, ".")) &&
		strings.EqualFold(w.Question.Type, qtype) &&
		strings.EqualFold(w.Question.Class, class)
}

// Differences is what is not what it was, and nothing at all where nothing is.
// It is what [Changes] says with the framing taken off: the line naming when
// the walk before this one was made, and the line saying there was no change.
//
// A watch needs the two told apart. It says nothing for a round that found
// nothing, so it cannot use a comparison that always says something; and it is
// looking at two walks it made itself, so there is no age to put on either.
func Differences(before, now *Walk) []explain.Finding {
	if before == nil || now == nil {
		return nil
	}
	zones := compare(before, now).Zones
	return slices.Concat(answer(before, now), cuts(zones), signing(zones))
}

// answer is what became of the answer itself: the thing the question was asked
// for, and the change worth reading first.
func answer(before, now *Walk) []explain.Finding {
	change := func(level explain.Level, text string) []explain.Finding {
		return []explain.Finding{{Topic: explain.Change, Level: level, Text: text}}
	}
	name := now.Question.Name

	switch {
	case before.Kind != "" && now.Kind == "":
		return change(explain.Warn, fmt.Sprintf("%s answered then and nothing answers now", name))

	case before.Kind == "" && now.Kind != "":
		return change(explain.Note, fmt.Sprintf("nothing answered for %s then and something does now", name))

	case before.Kind == "answer" && now.Kind == "nxdomain":
		return change(explain.Warn, fmt.Sprintf("%s had an answer then and does not exist now", name))

	case before.Kind == "answer" && now.Kind == "nodata":
		// Plural, so that the sentence does not have to know whether the type
		// it names takes "a" or "an".
		return change(explain.Warn, fmt.Sprintf(
			"%s had %s records then and has none now", name, now.Question.Type))

	case before.Kind == "nxdomain" && now.Kind == "answer":
		return change(explain.Note, fmt.Sprintf("%s did not exist then and answers now", name))

	case before.Kind != now.Kind:
		return change(explain.Note, fmt.Sprintf(
			"the walk ended in %s then and ends in %s now", before.Kind, now.Kind))

	case !slices.Equal(before.Answer, now.Answer):
		return change(explain.Note, fmt.Sprintf("the answer changed: %s became %s",
			list(before.Answer), list(now.Answer)))

	// A TTL is what the zone put on the record rather than anything a walk
	// found for itself, so it holds still between walks, and a change in it is
	// usually a change that has not happened yet.
	case before.TTL != now.TTL && before.TTL != 0 && now.TTL != 0:
		return change(explain.Note, fmt.Sprintf("the answer is unchanged, and its TTL went from %s to %s",
			strconv.FormatUint(uint64(before.TTL), 10), strconv.FormatUint(uint64(now.TTL), 10)))
	}
	return nil
}

// cuts is what became of the zones on the way down: one that was not there
// before, one that is gone, and the nameservers each of them is delegated to.
func cuts(zones []ZoneDelta) []explain.Finding {
	var findings []explain.Finding
	for _, zone := range zones {
		var text string
		switch {
		case zone.Came:
			text = fmt.Sprintf("there is a zone cut at %s now, and there was none then", zone.Name)
		case zone.Went:
			text = fmt.Sprintf("the zone cut at %s is gone, and the walk crosses it no longer", zone.Name)
		case len(zone.NSCame) > 0 && len(zone.NSWent) > 0:
			text = fmt.Sprintf("the nameservers of %s changed: %s came in and %s went",
				zone.Name, list(zone.NSCame), list(zone.NSWent))
		case len(zone.NSCame) > 0:
			text = fmt.Sprintf("%s was added to the nameservers of %s", list(zone.NSCame), zone.Name)
		case len(zone.NSWent) > 0:
			text = fmt.Sprintf("%s was dropped from the nameservers of %s", list(zone.NSWent), zone.Name)
		default:
			continue
		}
		findings = append(findings, explain.Finding{Topic: explain.Change, Level: explain.Note, Text: text})
	}
	return findings
}

// signing is what became of the chain of trust over each zone. Only a zone both
// walks checked is read: a walk that followed no chain remembers no state, and
// nothing about it says the zone changed.
func signing(zones []ZoneDelta) []explain.Finding {
	var findings []explain.Finding
	for _, zone := range zones {
		if zone.DNSSECWas == "" {
			continue
		}

		// Bogus is the one that has to keep meaning something, and a zone that
		// was signed and is not any more is either a rollover that went wrong
		// or somebody turning it off.
		level := explain.Note
		switch {
		case zone.DNSSEC == "bogus":
			level = explain.Fault
		case zone.DNSSECWas == "secure" && zone.DNSSEC == "insecure":
			level = explain.Warn
		}
		findings = append(findings, explain.Finding{
			Topic: explain.Change, Level: level,
			Text: fmt.Sprintf("the chain of trust over %s read %s then and reads %s now",
				zone.Name, zone.DNSSECWas, zone.DNSSEC),
		})
	}
	return findings
}

// Delta is what [Differences] says, kept as data for a page to draw rather
// than as sentences to read. The sentences are made from it, so the two cannot
// disagree.
type Delta struct {
	// When is how far apart the two walks were made, in the words the
	// sentences use.
	When string `json:"when"`

	// Was is the answer as it was, where it is not what it is now.
	Was *Answer `json:"was,omitempty"`

	// Zones is every cut that changed, those this walk crossed first, in the
	// order it crossed them, and then those it crosses no longer.
	Zones []ZoneDelta `json:"zones,omitempty"`
}

// Answer is what ended a remembered walk.
type Answer struct {
	Kind   string   `json:"kind,omitempty"`
	Answer []string `json:"answer,omitempty"`
}

// ZoneDelta is what became of one zone cut.
type ZoneDelta struct {
	Name string `json:"name"`

	// Came is a cut that was not there before, and Went one that is gone.
	Came bool `json:"came,omitempty"`
	Went bool `json:"went,omitempty"`

	// NSCame and NSWent are the nameservers its parent delegates to now and
	// did not then, and the other way round.
	NSCame []string `json:"ns_came,omitempty"`
	NSWent []string `json:"ns_went,omitempty"`

	// DNSSECWas is the chain of trust as it read then, and DNSSEC as it reads
	// now, set only where both walks checked it and the two differ.
	DNSSECWas string `json:"dnssec_was,omitempty"`
	DNSSEC    string `json:"dnssec,omitempty"`
}

// Compare is the difference [Changes] describes, nil with nothing to compare.
func Compare(before, now *Walk) *Delta {
	if before == nil || now == nil {
		return nil
	}
	delta := compare(before, now)
	delta.When = ago(now.Seen.Sub(before.Seen))
	return delta
}

// CompareAgainst is the difference [Against] describes.
func CompareAgainst(before, now *Walk) *Delta {
	if before == nil || now == nil {
		return nil
	}
	delta := compare(before, now)
	delta.When = "at a time it does not say"
	if !before.Seen.IsZero() && !now.Seen.IsZero() {
		delta.When = made(now.Seen.Sub(before.Seen))
	}
	return delta
}

func compare(before, now *Walk) *Delta {
	delta := &Delta{}
	if before.Kind != now.Kind || !slices.Equal(before.Answer, now.Answer) {
		delta.Was = &Answer{Kind: before.Kind, Answer: before.Answer}
	}
	for _, zone := range now.Zones {
		was, known := find(before.Zones, zone.Name)
		if !known {
			delta.Zones = append(delta.Zones, ZoneDelta{Name: zone.Name, Came: true})
			continue
		}
		change := ZoneDelta{Name: zone.Name}
		// The root is not delegated to, so there is nothing to hold against it.
		if len(was.NS) > 0 && len(zone.NS) > 0 {
			change.NSCame, change.NSWent = apart(was.NS, zone.NS)
		}
		if was.DNSSEC != "" && zone.DNSSEC != "" && was.DNSSEC != zone.DNSSEC {
			change.DNSSECWas, change.DNSSEC = was.DNSSEC, zone.DNSSEC
		}
		if len(change.NSCame)+len(change.NSWent) > 0 || change.DNSSECWas != "" {
			delta.Zones = append(delta.Zones, change)
		}
	}
	for _, zone := range before.Zones {
		if _, known := find(now.Zones, zone.Name); !known {
			delta.Zones = append(delta.Zones, ZoneDelta{Name: zone.Name, Went: true})
		}
	}
	return delta
}

// find is a zone as the other walk remembered it.
func find(zones []Zone, name string) (Zone, bool) {
	for _, zone := range zones {
		if strings.EqualFold(zone.Name, name) {
			return zone, true
		}
	}
	return Zone{}, false
}

// apart is what one set has that the other does not, both ways round.
func apart(before, now []string) (came, went []string) {
	for _, name := range now {
		if !slices.ContainsFunc(before, func(was string) bool { return strings.EqualFold(was, name) }) {
			came = append(came, name)
		}
	}
	for _, name := range before {
		if !slices.ContainsFunc(now, func(is string) bool { return strings.EqualFold(is, name) }) {
			went = append(went, name)
		}
	}
	return came, went
}

// ago is how long it has been, in the coarsest unit that still says something.
// A walk remembered from a different clock, or a file copied from elsewhere,
// can be dated after this one; that is worth saying plainly rather than as a
// negative age.
func ago(since time.Duration) string {
	switch {
	case since < 0:
		return "remembered from later than this one"
	case since < time.Minute:
		return "moments ago"
	}
	return span(since) + " ago"
}

// made is how far apart two walks were made, from the side of the one drawn.
func made(since time.Duration) string {
	switch {
	case since.Abs() < time.Minute:
		return "within a minute of this one"
	case since < 0:
		return span(-since) + " after this one"
	}
	return span(since) + " before this one"
}

// span is a duration of a minute or more, in the coarsest unit that still says
// something.
func span(since time.Duration) string {
	switch {
	case since < time.Hour:
		return plural(int(since.Minutes()), "minute", "minutes")
	case since < 24*time.Hour:
		return plural(int(since.Hours()), "hour", "hours")
	}
	return plural(int(since.Hours()/24), "day", "days")
}

// list is a handful of names in a sentence, the tail of a long one counted
// rather than read out.
func list(items []string) string {
	const most = 3
	switch {
	case len(items) == 0:
		return "nothing"
	case len(items) == 1:
		return items[0]
	case len(items) > most:
		return strings.Join(items[:most], ", ") + fmt.Sprintf(" and %d more", len(items)-most)
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
