package explain

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Below these the timers are worth a look. They are opinions, as the RFCs that
// suggest them say: RFC 1912 two to four weeks of expire, RFC 2308 one to three
// hours of negative caching and nothing past a day.
const (
	shortExpire  = 7 * 86400
	longNegative = 86400
)

// timing is the part of an SOA that says how the zone is kept, as one server
// handed it out.
type timing struct {
	refresh, retry, expire, minimum, ttl uint32
}

// timers judges how the zone the walk ended in tells its secondaries to keep
// their copies, from the SOA every nameserver gave --serial. Hosted and anycast
// services copy zones their own way and never read these, so each sentence
// says what a timer would do rather than that an outage is coming.
func timers(tr *trace.Trace) []Finding {
	zone := tr.Ended()
	var order []timing
	held := make(map[timing][]string)
	for step := range tr.Steps() {
		soa := step.SOA
		if !step.Aside || step.Asked.Type != "SOA" || !strings.EqualFold(step.Asked.Name, zone) || soa == nil {
			continue
		}
		// A walk saved before the timers were recorded reads them back as zero.
		if soa.Refresh == 0 && soa.Retry == 0 && soa.Expire == 0 {
			continue
		}
		key := timing{soa.Refresh, soa.Retry, soa.Expire, soa.Minimum, soa.TTL}
		if _, seen := held[key]; !seen {
			order = append(order, key)
		}
		held[key] = add(held[key], at(step))
	}

	var findings []Finding
	if len(order) > 1 {
		sets := make([]string, 0, len(order))
		for _, t := range order {
			sets = append(sets, fmt.Sprintf("refresh %s, retry %s, expire %s, minimum %s and TTL %s at %s",
				spell(t.refresh), spell(t.retry), spell(t.expire), spell(t.minimum), spell(t.ttl), list(held[t])))
		}
		findings = append(findings, Finding{Topic: Timers, Level: Warn, Text: fmt.Sprintf(
			"the nameservers of %s hand out different SOA timers: %s",
			zone, strings.Join(sets, "; "))})
	}
	for _, t := range order {
		where := ""
		if len(order) > 1 {
			where = " at " + list(held[t])
		}
		findings = append(findings, judge(zone, where, t)...)
	}
	return findings
}

// judge is what one set of timers would do. Only the relations between them
// are wrong whatever the zone is for; the lengths are a matter of degree.
func judge(zone, where string, t timing) []Finding {
	var findings []Finding
	say := func(format string, args ...any) {
		findings = append(findings, Finding{Topic: Timers, Level: Warn, Text: fmt.Sprintf(format, args...)})
	}
	switch {
	case t.expire <= t.refresh:
		say("the SOA of %s%s expires a copy after %s, no longer than the %s between checks, so a secondary that missed a single check would stop answering for the zone; make expire several times refresh",
			zone, where, spell(t.expire), spell(t.refresh))
	case t.expire < shortExpire:
		say("the SOA of %s%s expires a copy after %s, so a secondary that cannot reach the primary for longer would stop answering for the zone; RFC 1912 suggests two to four weeks",
			zone, where, spell(t.expire))
	}
	if t.retry > t.refresh {
		say("the SOA of %s%s retries a failed check after %s, longer than the %s between checks, so a secondary would wait longer after a check that failed than after one that worked; make retry shorter than refresh",
			zone, where, spell(t.retry), spell(t.refresh))
	}
	negative, which := t.minimum, "minimum"
	if t.ttl < t.minimum {
		negative, which = t.ttl, "TTL"
	}
	if negative >= longNegative {
		say("a name made in %s after a resolver was told it does not exist stays missing at that resolver for %s, the SOA's %s%s; RFC 2308 suggests one to three hours",
			zone, spell(negative), which, where)
	}
	return findings
}
