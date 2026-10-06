package explain

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Check grades the zone's health one area at a time, for --check. Each grade
// is read off what the walk tagged and what --explain would say, so an area
// cannot pass here while the flag that checks it warns, or the other way round.
// It is worked out from the walk itself, before anything is saved: which area a
// warning is about is known only to the walk that raised it.
func Check(tr *trace.Trace) *trace.Check {
	if tr == nil || tr.Root == nil {
		return nil
	}
	// The zone is kept as the walk has it, like every other name the trace
	// holds; the sentences are escaped as they are drawn either way.
	check := &trace.Check{Zone: tr.Ended()}
	tr = tr.Shown()
	for _, area := range trace.Areas {
		check.Areas = append(check.Areas, grade(tr, area))
	}
	return check
}

// grade is how one area came out: broken on any fault, worth a look on any
// warning, passed where it was checked and nothing came up, and skipped where
// nothing checked it.
func grade(tr *trace.Trace, area trace.Area) trace.Graded {
	findings, ran, passed := about(tr, area)
	zone := tr.Ended()
	for _, warning := range tr.Warnings {
		concern, ok := tr.About[warning]
		if ok && concern.Area == area && (concern.Zone == "" || strings.EqualFold(concern.Zone, zone)) {
			findings = append(findings, Finding{Level: Warn, Text: warning})
			ran = true
		}
	}

	// What could not be checked is never a pass, so it is worth a look.
	var problems []Finding
	for _, finding := range findings {
		if finding.Unknown {
			finding.Level = max(finding.Level, Warn)
		}
		if finding.Level > Note && !slices.ContainsFunc(problems, func(f Finding) bool { return f.Text == finding.Text }) {
			problems = append(problems, finding)
		}
	}
	slices.SortStableFunc(problems, func(a, b Finding) int { return int(b.Level - a.Level) })
	if len(problems) > 0 {
		graded := trace.Graded{Area: area, Grade: trace.GradeLook, Text: problems[0].Text, More: len(problems) - 1}
		if problems[0].Level == Fault {
			graded.Grade = trace.GradeBroken
		}
		return graded
	}
	if !ran {
		return trace.Graded{Area: area, Grade: trace.GradeSkipped, Text: skipped[area]}
	}
	// Signing is a choice, as a CAA set is, but an unsigned zone is one
	// nothing vouches for, which is worth a look on a check of its health.
	if area == trace.AreaDNSSEC {
		if step := tr.Chain(); step != nil && step.DNSSEC.State == trace.Insecure {
			return trace.Graded{Area: area, Grade: trace.GradeLook, Text: passed}
		}
	}
	return trace.Graded{Area: area, Grade: trace.GradePassed, Text: passed}
}

// skipped says why an area was not graded, and what would grade it.
var skipped = map[trace.Area]string{
	trace.AreaDelegation:   "not checked; --check-ns compares the parent and the zone",
	trace.AreaConsistency:  "not checked; --serial asks every nameserver which copy it serves",
	trace.AreaDNSSEC:       "not checked; --dnssec follows the chain of trust",
	trace.AreaEDNS:         "not checked; --check-edns and --cookie test the nameservers",
	trace.AreaStrangers:    "not asked; --check-axfr and --check-recursion probe the nameservers, which is for your own zone",
	trace.AreaCAA:          "not checked; --caa reads the CAA set",
	trace.AreaMail:         "not checked; --mail and --spf read the mail records",
	trace.AreaRegistration: "not checked, or no registry publishes it; --rdap asks the registry",
}

// about is what --explain says about an area, whether the area was checked at
// all, and what to say when it passed.
func about(tr *trace.Trace, area trace.Area) (findings []Finding, ran bool, passed string) {
	zone := tr.Ended()
	switch area {
	case trace.AreaAnswer:
		said := outcome(tr)
		return []Finding{said}, true, said.Text

	case trace.AreaDelegation:
		findings = takeover(tr)
		delegation := delegated(tr, zone)
		if delegation == nil || (delegation.ZoneTTL == 0 && delegation.ZoneAddrs == nil) {
			return findings, false, ""
		}
		passed = fmt.Sprintf("the parent and %s agree on %s", zone, plural(len(delegation.NS), "nameserver", "nameservers"))
		if len(delegation.ZoneAddrs) > 0 {
			passed += " and their glue"
		}
		return findings, true, passed

	case trace.AreaConsistency:
		names, addrs, serials := map[string]bool{}, 0, map[uint32]bool{}
		for step := range tr.Steps() {
			if step.Aside && step.Asked.Type == "SOA" && strings.EqualFold(step.Asked.Name, zone) && step.SOA != nil {
				names[strings.ToLower(at(step))] = true
				addrs++
				serials[step.SOA.Serial] = true
			}
		}
		if addrs == 0 {
			return nil, false, ""
		}
		passed = "every nameserver asked serves one copy of " + zone
		if len(serials) == 1 {
			for serial := range serials {
				passed += fmt.Sprintf(", serial %d", serial)
			}
		}
		passed += fmt.Sprintf(" (%s, %s)", plural(len(names), "nameserver", "nameservers"), plural(addrs, "address", "addresses"))
		return nil, true, passed

	case trace.AreaDNSSEC:
		// The zones above are signed by somebody else.
		findings = slices.Concat(trust(tr), hashingOf(tr, zone), setupOf(tr, zone))
		return findings, tr.Chain() != nil, first(texts(findings))

	case trace.AreaServers:
		// The zones above are somebody else's to run, and nothing the zone's
		// owner can fix.
		findings = slices.Concat(serversOf(tr, zone), spread(tr))
		return findings, true, fmt.Sprintf("every server of %s the walk asked answered, with authority and room to spare", zone)

	case trace.AreaEDNS:
		findings = slices.Concat(ednsTests(tr), cookiesOf(tr, zone))
		for step := range tr.Steps() {
			ran = ran || step.EDNS != nil || step.Cookie != ""
		}
		return findings, ran, cmp.Or(first(texts(findings)), "every server asked handled edns and dns cookies as it should")

	case trace.AreaStrangers:
		findings = exposure(tr)
		for step := range tr.Steps() {
			ran = ran || step.Probe != nil
		}
		return findings, ran, strings.Join(texts(findings), ", and ")

	case trace.AreaCAA:
		if finding, ok := issuance(tr); ok {
			findings = append(findings, finding)
		}
		return findings, tr.CAA != nil, first(texts(findings))

	case trace.AreaMail:
		if finding, ok := sender(tr); ok {
			findings = append(findings, finding)
		}
		findings = append(findings, delivery(tr)...)
		return findings, tr.Mail != nil || tr.SPF != nil, cmp.Or(first(texts(findings)), "nothing to look at in the mail records")

	case trace.AreaRegistration:
		reg := tr.Registration
		// A TLD that publishes no RDAP leaves nothing to check, which is not
		// a registration that passed.
		if reg == nil || reg.State == trace.Unpublished {
			return nil, false, ""
		}
		findings = registration(tr)
		return findings, true, cmp.Or(first(texts(findings)), "the registry holds "+reg.Domain)
	}
	return nil, false, ""
}

func texts(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Text)
	}
	return out
}
