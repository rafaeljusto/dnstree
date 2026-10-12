package tree

import (
	"fmt"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// methods names each rollover method the way the block says it.
var methods = map[trace.RolloverMethod]string{
	trace.MethodDoubleDS:        "double DS",
	trace.MethodDoubleKSK:       "double KSK",
	trace.MethodDoubleRRset:     "double RRset",
	trace.MethodPrePublish:      "pre-publish",
	trace.MethodDoubleSignature: "double signature",
	trace.MethodAlgorithm:       "algorithm",
}

// kinds names each key a rollover replaces.
var kinds = map[trace.RolloverKind]string{
	trace.KindKSK: "key signing key",
	trace.KindZSK: "zone signing key",
}

// rollover draws what --rollover worked out: the keys and the DS in play, the
// step each reading of them has reached, and what the next one waits on.
func (r *renderer) rollover(ro *trace.Rollover) []string {
	if ro == nil {
		return nil
	}
	mark := "rollover: "
	if r.glyphs.icons {
		mark = spaced("🔑")
	}

	switch ro.State {
	case trace.RolloverUnchecked:
		return []string{r.paint.paint(mark+"nothing to read: "+ro.Reason, yellow)}
	case trace.RolloverIndeterminate:
		return append([]string{r.paint.paint(mark+"where the keys of "+ro.Zone+" stand cannot be told: "+ro.Reason, yellow)},
			r.rolloverKeys(mark, ro)...)
	case trace.RolloverUnrecognised:
		return append([]string{r.paint.paint(mark+"the keys of "+ro.Zone+" fit no one rollover: "+ro.Reason, yellow)},
			r.rolloverKeys(mark, ro)...)
	case trace.RolloverNone:
		return append([]string{mark + ro.Zone + " is not rolling its keys"}, r.rolloverKeys(mark, ro)...)
	}

	lines := append([]string{fmt.Sprintf("%sthe keys of %s, and the DS %s holds for them", mark, ro.Zone, ro.Parent)},
		r.rolloverKeys(mark, ro)...)
	for i := 0; i < len(ro.Readings); {
		reading := ro.Readings[i]
		if i+1 < len(ro.Readings) && ro.Readings[i+1].Kind == reading.Kind {
			lines = append(lines, r.eitherWay(mark, ro, reading, ro.Readings[i+1])...)
			i += 2
			continue
		}
		lines = append(lines, r.reading(mark, ro, reading)...)
		i++
	}
	if ro.Reason != "" {
		lines = append(lines, r.paint.dim(mark+ro.Reason))
	}
	lines = append(lines, r.rolloverHints(mark, ro)...)
	return lines
}

// rolloverKeys is one line for each key and DS in play.
func (r *renderer) rolloverKeys(mark string, ro *trace.Rollover) []string {
	var lines []string
	for _, key := range ro.Keys {
		kind := "zone signing key"
		if key.SEP || key.DS {
			kind = "key signing key"
		}
		var says []string
		if key.Published {
			says = append(says, "published")
		} else {
			says = append(says, "not published")
		}
		if key.DS {
			says = append(says, "DS at "+ro.Parent)
		}
		if key.SignsKeys {
			says = append(says, "signs the keys")
		}
		if key.SignsData {
			says = append(says, "signs the answer")
		}
		line := fmt.Sprintf("%s  %-5d  %-16s  %s", mark, key.Tag, kind, strings.Join(says, ", "))
		if seen := firstSeen(key); seen != "" {
			line += "; " + seen
		}
		lines = append(lines, r.paint.dim(line))
	}
	return lines
}

// firstSeen says when a remembered walk first saw a key and its DS.
func firstSeen(key trace.RolloverKey) string {
	switch {
	case key.KeySeen.IsZero() && key.DSSeen.IsZero():
		return ""
	case key.DSSeen.IsZero() || key.KeySeen.Equal(key.DSSeen):
		return "first seen " + moment(key.KeySeen)
	case key.KeySeen.IsZero():
		return "first seen " + moment(key.DSSeen)
	}
	return fmt.Sprintf("key first seen %s, DS %s", moment(key.KeySeen), moment(key.DSSeen))
}

// reading is one reading of the keys: what is changing, by which method, and
// what comes next.
func (r *renderer) reading(mark string, ro *trace.Rollover, reading trace.Reading) []string {
	switch {
	case reading.Kind == trace.KindAlgorithm:
		return []string{mark + ro.Zone + " publishes keys of more than one algorithm: an algorithm rollover, whose steps are not timed here"}
	case reading.Method == trace.MethodDoubleSignature:
		return []string{mark + ro.Zone + " signs the answer with two zone signing keys: a double signature rollover, or two operators signing the zone (RFC 8901)"}
	case reading.Next == "":
		return []string{mark + ro.Zone + " publishes two zone signing keys and neither signed the answer: a rollover under way, or two operators signing the zone (RFC 8901)"}
	}

	lines := []string{fmt.Sprintf("%s%s is changing its %s by %s, from %d to %d",
		mark, ro.Zone, kinds[reading.Kind], methods[reading.Method], reading.Old, reading.New)}
	lines = append(lines, mark+"  next: "+next(ro, reading))
	lines = append(lines, r.waits(mark+"  ", ro, reading)...)
	lines = append(lines, r.counted(mark+"  ", reading)...)
	return append(lines, r.shared(mark+"  ", reading)...)
}

// shared is the other reading of two keys a walk cannot rule out: a zone
// signed by several operators publishes every operator's keys, and each
// operator's DS where it signs its own key set (RFC 8901).
func (r *renderer) shared(mark string, reading trace.Reading) []string {
	switch {
	case reading.Kind == trace.KindZSK:
		return []string{r.paint.dim(mark + "a key that signs nothing may instead be another operator's, in a zone signed by several (RFC 8901)")}
	case reading.Method == trace.MethodDoubleRRset:
		return []string{r.paint.dim(mark + "two keys each with a DS may instead be two operators', in a zone signed by several (RFC 8901)")}
	}
	return nil
}

// eitherWay is two readings of one set of keys, which the walk cannot choose
// between: it does not know which key is the new one.
func (r *renderer) eitherWay(mark string, ro *trace.Rollover, first, second trace.Reading) []string {
	lines := []string{fmt.Sprintf("%s%s is changing its %s, and one walk cannot tell which key is the new one",
		mark, ro.Zone, kinds[first.Kind])}
	for _, reading := range []trace.Reading{first, second} {
		lines = append(lines, fmt.Sprintf("%s  if %d is new, by %s: next %s", mark, reading.New, methods[reading.Method], next(ro, reading)))
		lines = append(lines, r.waits(mark+"    ", ro, reading)...)
	}
	lines = append(lines, r.counted(mark+"  ", first, second)...)
	return append(lines, r.shared(mark+"  ", first)...)
}

// next says the step that comes next.
func next(ro *trace.Rollover, reading trace.Reading) string {
	incoming, _ := keyOf(ro, reading.New)
	switch reading.Next {
	case trace.NextSwapKey:
		if incoming.Published {
			return fmt.Sprintf("sign the keys with key %d in place of key %d", reading.New, reading.Old)
		}
		return fmt.Sprintf("publish key %d and sign the keys with it in place of key %d", reading.New, reading.Old)
	case trace.NextRemoveDS:
		return fmt.Sprintf("remove DS %d from %s", reading.Old, ro.Parent)
	case trace.NextSwapDS:
		if !incoming.SignsKeys {
			return fmt.Sprintf("sign the keys with key %d too, then replace DS %d at %s with DS %d",
				reading.New, reading.Old, ro.Parent, reading.New)
		}
		return fmt.Sprintf("replace DS %d at %s with DS %d", reading.Old, ro.Parent, reading.New)
	case trace.NextRemoveKey:
		return fmt.Sprintf("stop publishing key %d", reading.Old)
	case trace.NextRemoveOld:
		return fmt.Sprintf("stop publishing key %d, and remove DS %d from %s", reading.Old, reading.Old, ro.Parent)
	case trace.NextSignWith:
		return fmt.Sprintf("sign the zone with key %d in place of key %d", reading.New, reading.Old)
	}
	return string(reading.Next)
}

func keyOf(ro *trace.Rollover, tag uint16) (trace.RolloverKey, bool) {
	for _, key := range ro.Keys {
		if key.Tag == tag {
			return key, true
		}
	}
	return trace.RolloverKey{}, false
}

// waits says what the next step waits on: a TTL that has run out since the
// record was first seen, the time it runs out, or a span after a change no
// walk saw. A first sighting is at the one server the walk asked, so what is
// timed from it is said as measured, never as safe.
func (r *renderer) waits(mark string, ro *trace.Rollover, reading trace.Reading) []string {
	if len(reading.Waits) == 0 {
		return []string{r.paint.dim(fmt.Sprintf("%swait: the longest TTL of what key %d signed, after it stopped; a walk does not read every TTL in the zone, so this is not timed",
			mark, reading.Old))}
	}
	var lines []string
	for _, wait := range reading.Waits {
		held := "the DNSKEY TTL"
		if wait.Type == "DS" {
			held = "the DS TTL at " + ro.Parent
		}
		record := fmt.Sprintf("DS %d", wait.Tag)
		if wait.Type != "DS" {
			record = fmt.Sprintf("key %d", wait.Tag)
		}
		ready, known := wait.Ready()
		started := r.trace.Started
		switch {
		case !known:
			lines = append(lines, fmt.Sprintf("%swait: %s after %s was published, %s", mark, span(wait.TTL), record, held))
		case !started.IsZero() && !ready.After(started):
			lines = append(lines, fmt.Sprintf("%swaited: %s of %s has run out since %s was first seen, %s ago",
				mark, held, span(wait.TTL), record, span(seconds(started.Sub(wait.Since)))))
		default:
			lines = append(lines, fmt.Sprintf("%swait: %s runs out at %s, %s after %s was first seen",
				mark, held, moment(ready), span(wait.TTL), record))
		}
	}
	return lines
}

// counted is what a wait timed from a first sighting does not see, said once
// under the readings that have one.
func (r *renderer) counted(mark string, readings ...trace.Reading) []string {
	for _, reading := range readings {
		for _, wait := range reading.Waits {
			if !wait.Since.IsZero() {
				return []string{r.paint.dim(mark + "counted from the first server that served it: one that picked it up later, a TTL lowered for the rollover, or a record withdrawn between remembered walks makes the wait longer (RFC 7583)")}
			}
		}
	}
	return nil
}

// rolloverHints are the flags that would tell a new key from an old one,
// where the walk could not.
func (r *renderer) rolloverHints(mark string, ro *trace.Rollover) []string {
	ambiguous, timed := false, false
	for i, reading := range ro.Readings {
		if i+1 < len(ro.Readings) && ro.Readings[i+1].Kind == reading.Kind {
			ambiguous = true
		}
		for _, wait := range reading.Waits {
			timed = timed || !wait.Since.IsZero()
		}
	}
	var said []string
	if ambiguous && !r.signalled(ro.Zone) {
		said = append(said, "--check-ds reads the CDS, which names the key coming in")
	}
	if ambiguous && !timed {
		said = append(said, "--diff remembers when each key is first seen, so a key that appears after a remembered walk is known to be the new one")
	} else if !timed && len(ro.Readings) > 0 && len(ro.Readings[0].Waits) > 0 {
		said = append(said, "--diff remembers when each key was first seen, and times the next step from it")
	}
	var lines []string
	for _, hint := range said {
		lines = append(lines, r.paint.dim(mark+hint))
	}
	return lines
}

// signalled is whether --check-ds read the zone's CDS.
func (r *renderer) signalled(zone string) bool {
	for step := range r.trace.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.Signal != nil && strings.EqualFold(step.DNSSEC.Zone, zone) {
			return true
		}
	}
	return false
}

// moment is a time to the minute, in UTC.
func moment(at time.Time) string {
	return at.UTC().Format("2006-01-02 15:04 UTC")
}

// seconds is a span as span reads it, capped where it would not fit.
func seconds(d time.Duration) uint32 {
	return uint32(min(max(d, 0)/time.Second, 1<<32-1))
}
