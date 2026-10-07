package explain

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// service is what --svcb found about where a client that reads the name's
// HTTPS or SVCB records connects.
func service(tr *trace.Trace) (Finding, bool) {
	p := tr.ServicePath
	if p == nil {
		return Finding{}, false
	}
	last := p.Name
	if n := len(p.Chain); n > 0 {
		last = p.Chain[n-1].Lookup.Name
	}

	var stray, nowhere, failed []string
	for _, target := range p.Targets {
		switch {
		case target.Failed() != "":
			failed = append(failed, target.Name)
		case target.Nowhere():
			nowhere = append(nowhere, target.Name)
		case len(target.Stray) > 0:
			stray = append(stray, target.Name)
		}
	}

	switch {
	case p.Stopped != "":
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf("the %s check of %s stopped: %s", p.Type, p.Name, p.Stopped)}, true
	case p.Cut:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the %s check of %s ran out of budget before every target was looked up, so the hints of those it did not reach are not judged", p.Type, p.Name)}, true
	case p.None:
		return Finding{Topic: Service, Level: Note, Text: fmt.Sprintf("%s says, with an alias to ., that it offers no service", last)}, true
	case len(failed) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the %s records of %s lead to %s, whose addresses could not be looked up", p.Type, p.Name, strings.Join(failed, ", "))}, true
	case len(nowhere) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the %s records of %s lead to %s, which %s no address, so a client has nothing there to connect to",
			p.Type, p.Name, strings.Join(nowhere, ", "), agrees(nowhere, "has", "have"))}, true
	case len(stray) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the %s records of %s hint at addresses %s %s not have, so a client that connects on the hints may reach another server",
			p.Type, p.Name, strings.Join(stray, ", "), agrees(stray, "does", "do"))}, true
	case p.Fallback && len(p.Chain) > 1:
		return Finding{Topic: Service, Level: Note, Text: fmt.Sprintf(
			"the %s aliases of %s end at %s, which has no records, so a client connects to it by its addresses alone", p.Type, p.Name, last)}, true
	case p.Fallback:
		return Finding{Topic: Service, Level: Note, Text: fmt.Sprintf(
			"%s publishes no %s records, so a client connects as it would without them", p.Name, p.Type)}, true
	}

	var names []string
	for _, target := range p.Targets {
		names = append(names, target.Name)
	}
	via := ""
	if aliases := len(p.Chain) - 1; aliases > 0 {
		via = " through " + plural(aliases, "alias", "aliases")
	}
	return Finding{Topic: Service, Level: Note, Text: fmt.Sprintf(
		"a client that reads the %s records of %s connects to %s%s", p.Type, p.Name, strings.Join(names, ", then "), via)}, true
}

// agrees is the form of a verb that agrees with a list of names.
func agrees(names []string, one, many string) string {
	if len(names) == 1 {
		return one
	}
	return many
}
