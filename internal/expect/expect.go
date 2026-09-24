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
	"strings"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// about is what an expectation is about.
type about int

const (
	trust   about = iota // how far the chain of trust got
	outcome              // what the walk came to
	answer               // the records that answered
)

// Expectation is one thing the command line asked to be true of the walk.
type Expectation struct {
	about about
	want  string
}

// String is the expectation as it was asked for, which is what has to appear in
// a message about it: somebody who typed it has to recognise it.
func (e Expectation) String() string { return e.want }

// Parse reads one --expect value. It is either one of the words that names how
// far the chain of trust got — secure, insecure, bogus, indeterminate — or what
// the walk came to — answer, cname, nodata, nxdomain — or else the rdata of a
// record that has to be among the answers.
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
