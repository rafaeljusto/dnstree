package history

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/explain"
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
	return slices.Concat(answer(before, now), cuts(before, now), signing(before, now))
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
func cuts(before, now *Walk) []explain.Finding {
	var findings []explain.Finding
	for _, zone := range now.Zones {
		was, known := find(before.Zones, zone.Name)
		if !known {
			findings = append(findings, explain.Finding{
				Topic: explain.Change, Level: explain.Note,
				Text: fmt.Sprintf("there is a zone cut at %s now, and there was none then", zone.Name),
			})
			continue
		}
		if len(was.NS) == 0 || len(zone.NS) == 0 {
			continue // the root is not delegated to, so there is nothing to hold against it
		}

		came, went := apart(was.NS, zone.NS)
		switch {
		case len(came) > 0 && len(went) > 0:
			findings = append(findings, explain.Finding{
				Topic: explain.Change, Level: explain.Note,
				Text: fmt.Sprintf("the nameservers of %s changed: %s came in and %s went",
					zone.Name, list(came), list(went)),
			})
		case len(came) > 0:
			findings = append(findings, explain.Finding{
				Topic: explain.Change, Level: explain.Note,
				Text: fmt.Sprintf("%s was added to the nameservers of %s", list(came), zone.Name),
			})
		case len(went) > 0:
			findings = append(findings, explain.Finding{
				Topic: explain.Change, Level: explain.Note,
				Text: fmt.Sprintf("%s was dropped from the nameservers of %s", list(went), zone.Name),
			})
		}
	}

	for _, zone := range before.Zones {
		if _, known := find(now.Zones, zone.Name); !known {
			findings = append(findings, explain.Finding{
				Topic: explain.Change, Level: explain.Note,
				Text: fmt.Sprintf("the zone cut at %s is gone, and the walk crosses it no longer", zone.Name),
			})
		}
	}
	return findings
}

// signing is what became of the chain of trust over each zone. Only a zone both
// walks checked is read: a walk that followed no chain remembers no state, and
// nothing about it says the zone changed.
func signing(before, now *Walk) []explain.Finding {
	var findings []explain.Finding
	for _, zone := range now.Zones {
		was, known := find(before.Zones, zone.Name)
		if !known || was.DNSSEC == "" || zone.DNSSEC == "" || was.DNSSEC == zone.DNSSEC {
			continue
		}

		// Bogus is the one that has to keep meaning something, and a zone that
		// was signed and is not any more is either a rollover that went wrong
		// or somebody turning it off.
		level := explain.Note
		switch {
		case zone.DNSSEC == "bogus":
			level = explain.Fault
		case was.DNSSEC == "secure" && zone.DNSSEC == "insecure":
			level = explain.Warn
		}
		findings = append(findings, explain.Finding{
			Topic: explain.Change, Level: level,
			Text: fmt.Sprintf("the chain of trust over %s read %s then and reads %s now",
				zone.Name, was.DNSSEC, zone.DNSSEC),
		})
	}
	return findings
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
	case since < time.Hour:
		return plural(int(since.Minutes()), "minute", "minutes") + " ago"
	case since < 24*time.Hour:
		return plural(int(since.Hours()), "hour", "hours") + " ago"
	}
	return plural(int(since.Hours()/24), "day", "days") + " ago"
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
