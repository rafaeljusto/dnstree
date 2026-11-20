package explain

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// srv is what --srv found about the servers the name's SRV records send a
// client to. It says where they resolve, never that the service answers.
func srv(tr *trace.Trace) (Finding, bool) {
	s := tr.SRV
	if s == nil {
		return Finding{}, false
	}

	var failed, bogus, nowhere, aliased, unreachable []string
	seen := map[string]bool{}
	for _, target := range s.Targets {
		if seen[target.Name] {
			continue
		}
		seen[target.Name] = true
		switch {
		case target.Failed() != "":
			failed = append(failed, target.Name)
		case slices.ContainsFunc([]*trace.Lookup{target.IPv4, target.IPv6}, func(l *trace.Lookup) bool {
			return l != nil && l.DNSSEC != nil && l.DNSSEC.State == trace.Bogus
		}):
			bogus = append(bogus, target.Name)
		case target.Nowhere():
			nowhere = append(nowhere, target.Name)
		case target.Alias() != "":
			aliased = append(aliased, target.Name)
		case len(target.Unreachable) > 0:
			unreachable = append(unreachable, target.Name)
		}
	}

	// What --tlsa found is by host and port, since each port has a TLSA set
	// of its own.
	var refused []string
	matched, said := false, map[string]bool{}
	for _, target := range s.Targets {
		at := target.Name + " port " + strconv.Itoa(int(target.Port))
		mismatch := target.DANE == trace.DANEFailed && target.TLSA != nil ||
			slices.ContainsFunc(target.Presented, func(p trace.Presented) bool { return p.State == trace.PresentedMismatch })
		if mismatch && !said[at] {
			refused = append(refused, at)
		}
		said[at] = true
		matched = matched || slices.ContainsFunc(target.Presented, func(p trace.Presented) bool { return p.State == trace.PresentedMatch })
	}

	switch {
	case s.Stopped != "":
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf("the SRV check of %s stopped: %s", s.Name, s.Stopped)}, true
	case s.Cut:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the SRV check of %s ran out of budget before every target was looked up, and left %s", s.Name, plural(s.Left, "target", "targets"))}, true
	case s.None:
		return Finding{Topic: Service, Level: Note, Text: fmt.Sprintf("%s says, with a target of ., that the service is not offered there", s.Name)}, true
	case len(s.Targets) == 0:
		return Finding{Topic: Service, Level: Note, Text: fmt.Sprintf("%s has no SRV records, so a client finds no server for the service there", s.Name)}, true
	case len(failed) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the SRV records of %s name %s, whose addresses could not be looked up", s.Name, strings.Join(failed, ", "))}, true
	case len(bogus) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the SRV records of %s name %s, whose addresses do not validate, so a client that validates has nothing to connect to there",
			s.Name, strings.Join(bogus, ", "))}, true
	case len(nowhere) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the SRV records of %s name %s, which %s no address, so a client sent there has nothing to connect to",
			s.Name, strings.Join(nowhere, ", "), agrees(nowhere, "has", "have"))}, true
	case len(aliased) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the SRV records of %s name %s, which %s an alias, so clients that keep to RFC 2782 may not follow %s",
			s.Name, strings.Join(aliased, ", "), agrees(aliased, "is", "are"), agrees(aliased, "it", "them"))}, true
	case len(unreachable) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the SRV records of %s name %s, at addresses no client on the internet can reach", s.Name, strings.Join(unreachable, ", "))}, true
	case len(refused) > 0:
		return Finding{Topic: Service, Level: Warn, Text: fmt.Sprintf(
			"the SRV records of %s name %s, which a client that checks DANE does not connect to", s.Name, strings.Join(refused, ", "))}, true
	}

	var servers []string
	for _, target := range s.Targets {
		servers = append(servers, target.Name+" port "+strconv.Itoa(int(target.Port)))
	}
	checked := "whether the service answers there was not checked"
	if matched {
		checked = "--tlsa matched the certificate of every address it reached against its TLSA set"
	}
	return Finding{Topic: Service, Level: Note, Text: fmt.Sprintf(
		"a client of the service at %s is sent to %s; %s", s.Name, strings.Join(servers, ", then "), checked)}, true
}
