package history

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
)

// maxChanges is how many changes a timeline reads out before it counts the
// rest: a history with more than this is read with a narrower directory.
const maxChanges = 40

// Timeline is what walks of one question, saved one after another, say about
// how it changed. A change is only ever placed between the two walks that saw
// it, since nothing watched the time in between; a long silence in the
// history is said so, rather than read as nothing having changed; and the
// steps of a key rollover are held against the TTLs the caches were allowed
// to keep the step before for (RFC 7583).
func Timeline(walks []*Walk, source string) []explain.Finding {
	walks = slices.Clone(walks)
	slices.SortStableFunc(walks, func(a, b *Walk) int { return a.Seen.Compare(b.Seen) })
	if len(walks) == 0 {
		return nil
	}
	first, last := walks[0], walks[len(walks)-1]

	var changes []explain.Finding
	changed := 0
	for i := 1; i < len(walks); i++ {
		before, now := walks[i-1], walks[i]
		found := slices.Concat(Differences(before, now), keying(before, now))
		if len(found) == 0 {
			continue
		}
		changed++
		for _, finding := range found {
			finding.Text = between(before.Seen, now.Seen) + ", " + finding.Text
			changes = append(changes, finding)
		}
	}

	findings := []explain.Finding{{Topic: explain.Change, Level: explain.Note, Text: fmt.Sprintf(
		"%s in %s from %s to %s, %s",
		plural(len(walks), "walk of "+first.Question.Name+" "+first.Question.Type, "walks of "+first.Question.Name+" "+first.Question.Type),
		source, stamp(first.Seen), stamp(last.Seen), plural(changed, "change", "changes"))}}
	if len(changes) > maxChanges {
		changes = append(changes[:maxChanges], explain.Finding{Topic: explain.Change, Level: explain.Note,
			Text: fmt.Sprintf("%s more not read out; give --history fewer walks to see them",
				plural(len(changes)-maxChanges, "line", "lines"))})
	}
	findings = append(findings, changes...)
	findings = append(findings, gaps(walks)...)
	return append(findings, timing(walks)...)
}

// keying is which keys and DS came and went between two walks, for every zone
// both followed the chain of trust into. A zone either walk did not reach
// securely recorded no keys, and is no evidence that they changed.
func keying(before, now *Walk) []explain.Finding {
	var findings []explain.Finding
	note := func(format string, args ...any) {
		findings = append(findings, explain.Finding{Topic: explain.Change, Level: explain.Note, Text: fmt.Sprintf(format, args...)})
	}
	for _, zone := range now.Zones {
		was, ok := find(before.Zones, zone.Name)
		if !ok {
			continue
		}
		if keyed(was.Keys, was) && keyed(zone.Keys, zone) {
			came, went := moved(was.Keys, zone.Keys)
			for _, r := range came {
				note("key %d (%s) was added to %s", r.Tag, r.Algorithm, zone.Name)
			}
			for _, r := range went {
				note("key %d (%s) was removed from %s", r.Tag, r.Algorithm, zone.Name)
			}
		}
		if keyed(was.DS, was) && keyed(zone.DS, zone) {
			came, went := moved(was.DS, zone.DS)
			for _, r := range came {
				note("the parent published a DS for key %d (%s) of %s", r.Tag, r.Algorithm, zone.Name)
			}
			for _, r := range went {
				note("the parent withdrew the DS for key %d (%s) of %s", r.Tag, r.Algorithm, zone.Name)
			}
		}
	}
	return findings
}

// keyed reports whether a zone's walk recorded this set at all: only a chain
// that entered the zone and held records its keys and DS.
func keyed(records []Record, zone Zone) bool {
	return zone.DNSSEC == "secure" && len(records) > 0
}

// moved is what one set of records has that the other does not, both ways.
func moved(before, now []Record) (came, went []Record) {
	for _, r := range now {
		if !holds(before, r.Tag, r.Algorithm) {
			came = append(came, r)
		}
	}
	for _, r := range before {
		if !holds(now, r.Tag, r.Algorithm) {
			went = append(went, r)
		}
	}
	return came, went
}

func holds(records []Record, tag uint16, algorithm string) bool {
	return slices.ContainsFunc(records, func(r Record) bool { return r.Tag == tag && r.Algorithm == algorithm })
}

// gaps is every stretch of the history more than twice as long as the usual
// time between two walks. Whatever happened there and was undone before the
// next walk was never seen, and saying nothing would read as nothing.
func gaps(walks []*Walk) []explain.Finding {
	if len(walks) < 3 {
		return nil
	}
	intervals := make([]time.Duration, 0, len(walks)-1)
	for i := 1; i < len(walks); i++ {
		intervals = append(intervals, walks[i].Seen.Sub(walks[i-1].Seen))
	}
	sorted := slices.Clone(intervals)
	slices.Sort(sorted)
	usual := sorted[len(sorted)/2]
	if usual <= 0 {
		return nil
	}

	var findings []explain.Finding
	for i, interval := range intervals {
		if interval <= 2*usual {
			continue
		}
		findings = append(findings, explain.Finding{Topic: explain.Change, Level: explain.Note, Text: fmt.Sprintf(
			"nothing was saved %s, %s where the walks are usually %s apart, so a change undone inside it was not seen",
			between(walks[i].Seen, walks[i+1].Seen), about(interval), about(usual))})
	}
	return findings
}

// change is one walk to the next where a zone's key set or DS set changed:
// the set as it stood before, and how long a cache could keep it.
type change struct {
	before, after *Walk
	was           []Record
	ttl           uint32
}

// timing holds each step of a rollover against the step before it. A zone's
// keys and its parent's DS are cached apart, each for its own TTL, so a
// resolver can hold a DS set from before a change beside a key set from after
// it, or the other way round. Where none of the DS it may still hold names a
// key the zone still has, it cannot validate the zone until the older set
// runs out.
//
// The walks only bound when a change happened, so a step is only called too
// soon where it was too soon however the changes fell between the walks, and
// how long resolvers were left without a key is said as "up to".
func timing(walks []*Walk) []explain.Finding {
	var findings []explain.Finding
	for _, name := range zoneNames(walks) {
		var (
			previous         *Walk // the last walk that recorded this zone's keys
			keyMoves, dsMove []change
		)
		for _, walk := range walks {
			zone, ok := find(walk.Zones, name)
			if !ok || !keyed(zone.Keys, zone) || !keyed(zone.DS, zone) {
				continue
			}
			if previous == nil {
				previous = walk
				continue
			}
			was, _ := find(previous.Zones, name)
			keysMoved := !sameSet(was.Keys, zone.Keys)
			dsMoved := !sameSet(was.DS, zone.DS)

			// The DS moved while a cache may still hold an older key set.
			if dsMoved {
				if step, ok := lastWithin(keyMoves, walk.Seen); ok && !names(zone.DS, step.was) {
					findings = append(findings, early(name, "the DS set moved to "+tags(zone.DS),
						previous, walk, step, "key set"))
				}
				dsMove = append(dsMove, change{before: previous, after: walk, was: was.DS, ttl: was.DSTTL})
			}
			// A key went while a cache may still hold an older DS set.
			if keysMoved {
				if step, ok := lastWithin(dsMove, walk.Seen); ok && !names(step.was, zone.Keys) {
					findings = append(findings, early(name, "the keys became "+tags(zone.Keys),
						previous, walk, step, "DS set"))
				}
				keyMoves = append(keyMoves, change{before: previous, after: walk, was: was.Keys, ttl: was.KeysTTL})
			}
			previous = walk
		}
	}
	return findings
}

// lastWithin is the latest change whose older set a cache may still hold at
// the latest moment the next step can have happened. Only where that is so
// however the changes fell between the walks is the next step too soon.
func lastWithin(changes []change, by time.Time) (change, bool) {
	if len(changes) == 0 {
		return change{}, false
	}
	step := changes[len(changes)-1]
	if step.ttl == 0 || by.Sub(step.before.Seen) >= time.Duration(step.ttl)*time.Second {
		return change{}, false
	}
	return step, true
}

// early is the finding for a step taken before the caches could let go of
// the set the step before it replaced.
func early(zone, what string, before, after *Walk, step change, set string) explain.Finding {
	ttl := time.Duration(step.ttl) * time.Second
	soonest := max(before.Seen.Sub(step.after.Seen), 0)
	return explain.Finding{Topic: explain.Change, Level: explain.Warn, Text: fmt.Sprintf(
		"%s, %s of %s, at most %s after the %s changed %s, but that %s had a TTL of %s: "+
			"a resolver that still held the old %s could not validate %s for up to %s (RFC 7583)",
		between(before.Seen, after.Seen), what, zone, about(after.Seen.Sub(step.before.Seen)), set,
		between(step.before.Seen, step.after.Seen), set, about(ttl), set, zone, about(ttl-soonest))}
}

// names reports whether any DS of a set names one of the keys.
func names(ds, keys []Record) bool {
	return slices.ContainsFunc(ds, func(r Record) bool { return holds(keys, r.Tag, r.Algorithm) })
}

func sameSet(a, b []Record) bool {
	came, went := moved(a, b)
	return len(came) == 0 && len(went) == 0
}

// tags is a set of keys or DS by tag, the way an operator names them.
func tags(records []Record) string {
	items := make([]string, 0, len(records))
	for _, r := range records {
		items = append(items, fmt.Sprint(r.Tag))
	}
	return list(items)
}

// zoneNames is every zone any walk crossed, in the order first crossed.
func zoneNames(walks []*Walk) []string {
	var seen []string
	for _, walk := range walks {
		for _, zone := range walk.Zones {
			if !slices.ContainsFunc(seen, func(name string) bool { return strings.EqualFold(name, zone.Name) }) {
				seen = append(seen, zone.Name)
			}
		}
	}
	return seen
}

// stamp is a moment as the timeline writes it, in UTC so that two machines
// read it alike.
func stamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05") + " UTC"
}

// between is the stretch two walks bound, the date said once where they share
// it.
func between(a, b time.Time) string {
	a, b = a.UTC(), b.UTC()
	if a.Format(time.DateOnly) == b.Format(time.DateOnly) {
		return fmt.Sprintf("between %s and %s UTC", a.Format("2006-01-02 15:04:05"), b.Format("15:04:05"))
	}
	return fmt.Sprintf("between %s and %s", stamp(a), stamp(b))
}

// about is a duration in the coarsest unit that still says something.
func about(d time.Duration) string {
	if d < time.Minute {
		return plural(int(d.Seconds()), "second", "seconds")
	}
	return span(d)
}
