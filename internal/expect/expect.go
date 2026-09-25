// Package expect reads what --expect asked to be true of a walk, and says which
// of it is not.
//
// It is a verdict rather than a reading, and what it decides becomes an exit
// code. That is why it is kept apart from the sentences --explain writes: those
// describe a resolution to somebody looking at it, and these answer a question
// somebody wrote down before the walk was made.
package expect

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// about is what an expectation is about.
type about int

const (
	trust   about = iota // how far the chain of trust got
	outcome              // what the walk came to
	answer               // the records that answered
	fresh                // how long the signatures have left to run
)

// Expectation is one thing the command line asked to be true of the walk.
type Expectation struct {
	about about
	want  string

	// left is how long every signature the chain rests on has to have left,
	// for an expectation about freshness. Zero asks only that none is stale.
	left time.Duration
}

// String is the expectation as it was asked for, which is what has to appear in
// a message about it: somebody who typed it has to recognise it.
func (e Expectation) String() string { return e.want }

// Parse reads one --expect value. It is either one of the words that names how
// far the chain of trust got — secure, insecure, bogus, indeterminate — or what
// the walk came to — answer, cname, nodata, nxdomain — or fresh, which asks for
// a secure chain none of whose signatures is late in the life it was made for,
// or none of which runs out within the time after a colon, such as fresh:3d; or
// else the rdata of a record that has to be among the answers.
//
// The words win, because they are what is nearly always meant. A zone that
// serves a record whose rdata reads like one of them is asked for with a
// leading "=", which expects rdata and nothing else.
func Parse(text string) (Expectation, error) {
	if rdata, escaped := strings.CutPrefix(text, "="); escaped {
		if rdata == "" {
			return Expectation{}, errors.New(`"=" on its own expects nothing`)
		}
		return Expectation{about: answer, want: rdata}, nil
	}
	if text == "" {
		return Expectation{}, errors.New("there is nothing to expect")
	}

	lower := strings.ToLower(text)
	if lower == "fresh" {
		return Expectation{about: fresh, want: lower}, nil
	}
	if within, ok := strings.CutPrefix(lower, "fresh:"); ok {
		left, err := lifetime(within)
		if err != nil {
			return Expectation{}, fmt.Errorf("%s: %w", text, err)
		}
		return Expectation{about: fresh, want: lower, left: left}, nil
	}
	switch trace.DNSSECState(lower) {
	case trace.Secure, trace.Insecure, trace.Bogus, trace.Indeterminate:
		return Expectation{about: trust, want: lower}, nil
	}
	switch trace.StepKind(lower) {
	case trace.KindAnswer, trace.KindCNAME, trace.KindNoData, trace.KindNXDomain:
		return Expectation{about: outcome, want: lower}, nil
	}
	return Expectation{about: answer, want: text}, nil
}

// Unmet is every expectation the walk does not meet, in the order they were
// asked for and said the way the rest of the output is said. An empty result
// means all of them hold, which is also what no expectations at all means.
func Unmet(tr *trace.Trace, want []Expectation) []string {
	if tr == nil {
		return nil
	}

	var unmet []string
	for _, expectation := range want {
		if got, ok := expectation.met(tr); !ok {
			// What was found is held against the octets, and said escaped: an
			// NS or a CNAME is a name the server wrote.
			unmet = append(unmet, fmt.Sprintf("expected %s, got %s", expectation.want, trace.Shown(got)))
		}
	}
	return unmet
}

// met reports whether the walk meets this expectation, and what it found where
// it does not.
func (e Expectation) met(tr *trace.Trace) (got string, ok bool) {
	switch e.about {
	case trust:
		// A walk that followed no chain has not met an expectation about one.
		// Reading it as secure would turn a run that forgot --dnssec into a
		// run that checked something.
		step := tr.Trust()
		if step == nil || step.DNSSEC == nil {
			return "a walk that followed no chain of trust", false
		}
		state := string(step.DNSSEC.State)
		return state, state == e.want

	case outcome:
		result := tr.Result()
		if result == nil {
			return "nothing", false
		}
		kind := string(result.Kind)
		return kind, kind == e.want

	case fresh:
		return e.fresh(tr)
	}

	result := tr.Result()
	if result == nil {
		return "nothing", false
	}
	answers := trace.Answers(result.Records, tr.Question.Type)
	if len(answers) == 0 {
		return "no " + tr.Question.Type + " record", false
	}
	for _, data := range answers {
		if same(data, e.want) {
			return data, true
		}
	}
	return list(answers), false
}

// fresh reports whether the chain holds and will go on holding for as long as
// was asked. Only a secure chain has signatures whose lifetime means anything: an
// insecure one has none to run out, which is not the same as having time left.
func (e Expectation) fresh(tr *trace.Trace) (got string, ok bool) {
	step := tr.Trust()
	if step == nil || step.DNSSEC == nil {
		return "a walk that followed no chain of trust", false
	}
	if step.DNSSEC.State != trace.Secure {
		return string(step.DNSSEC.State), false
	}

	soonest := tr.Soonest()
	if soonest == nil {
		return "signatures whose lifetime the trace does not record", false
	}
	if e.left == 0 {
		if stale := tr.Stale(); stale != nil {
			left, _ := tr.Expiring(stale.DNSSEC)
			return fmt.Sprintf("a signature over %s late in its life, running out in %s", zoneOf(stale), spell(left)), false
		}
		return "fresh", true
	}
	left, _ := tr.Left(soonest.DNSSEC)
	return fmt.Sprintf("signatures over %s that run out in %s", zoneOf(soonest), spell(left)), left >= e.left
}

// zoneOf is the zone a verdict is about, which is not always the zone of the
// step it sits on.
func zoneOf(step *trace.Step) string {
	if step.DNSSEC.Zone != "" {
		return step.DNSSEC.Zone
	}
	return step.Zone
}

// lifetime reads how long fresh asks for: a Go duration, with days allowed in
// front of it, since days are what zones are re-signed in.
func lifetime(text string) (time.Duration, error) {
	var days time.Duration
	if before, after, ok := strings.Cut(text, "d"); ok {
		n, err := strconv.Atoi(before)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number of days", before)
		}
		days, text = time.Duration(n)*24*time.Hour, after
	}

	var rest time.Duration
	if text != "" {
		var err error
		if rest, err = time.ParseDuration(text); err != nil {
			return 0, fmt.Errorf("%q is not a length of time", text)
		}
	}
	if days+rest <= 0 {
		return 0, errors.New("a signature has to have some time left")
	}
	return days + rest, nil
}

// spell is how long is left, in the two largest units it fills.
func spell(d time.Duration) string {
	days, hours := int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour)
	switch {
	case days > 0 && hours > 0:
		return plural(days, "day") + " " + plural(hours, "hour")
	case days > 0:
		return plural(days, "day")
	case hours > 0:
		return plural(hours, "hour")
	}
	return plural(int(d/time.Minute), "minute")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// same holds one rdata against what was expected. Names are compared the way
// DNS compares them, and an address as an address: 2001:db8::1 and
// 2001:0db8:0:0:0:0:0:1 are one address written two ways, and somebody who
// typed either of them meant the record.
func same(data, want string) bool {
	if got, err := netip.ParseAddr(data); err == nil {
		if wanted, err := netip.ParseAddr(want); err == nil {
			return got.Unmap() == wanted.Unmap()
		}
	}
	return strings.EqualFold(data, want)
}

// list is the answers in a sentence. An RRset can be longer than anyone wants
// read back at them, so the tail is counted rather than named.
func list(items []string) string {
	const most = 3
	switch {
	case len(items) == 1:
		return items[0]
	case len(items) > most:
		return strings.Join(items[:most], ", ") + fmt.Sprintf(" and %d more", len(items)-most)
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
