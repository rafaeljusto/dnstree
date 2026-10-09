package explain_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// asked is the SOA a nameserver of test. gave --serial.
func asked(server string, soa trace.SOA) *trace.Step {
	step := hop(trace.KindAnswer, server)
	step.Aside, step.Asked, step.SOA = true, trace.Question{Name: "test.", Type: "SOA"}, &soa
	return step
}

// sound is a set of timers nothing here would say a word about.
var sound = trace.SOA{Serial: 1, TTL: 3600, Minimum: 3600, Refresh: 7200, Retry: 3600, Expire: 1209600}

func TestTimers(t *testing.T) {
	with := func(change func(*trace.SOA)) trace.SOA {
		soa := sound
		change(&soa)
		return soa
	}

	for name, tt := range map[string]struct {
		soas   []trace.SOA
		want   []string
		unsaid []string
	}{
		"timers that work together say nothing": {
			soas:   []trace.SOA{sound, sound},
			unsaid: []string{"SOA", "missing"},
		},
		"an expire no longer than refresh drops the zone after one missed check": {
			soas: []trace.SOA{with(func(s *trace.SOA) { s.Expire = 3600 })},
			want: []string{"the SOA of test. expires a copy after 1 hour, no longer than the 2 hours between checks"},
			// One sentence about expire is enough.
			unsaid: []string{"RFC 1912"},
		},
		"an expire of a few days loses the secondaries over a long outage": {
			soas: []trace.SOA{with(func(s *trace.SOA) { s.Expire = 3 * 86400 })},
			want: []string{"expires a copy after 3 days", "RFC 1912 suggests two to four weeks"},
		},
		"an expire of a week is what large providers use and passes": {
			soas:   []trace.SOA{with(func(s *trace.SOA) { s.Expire = 7 * 86400 })},
			unsaid: []string{"expires"},
		},
		"a retry longer than refresh waits longer after a failure": {
			soas: []trace.SOA{with(func(s *trace.SOA) { s.Retry = 10800 })},
			want: []string{"retries a failed check after 3 hours, longer than the 2 hours between checks"},
		},
		"a minimum of a day keeps a new name missing for a day": {
			soas: []trace.SOA{with(func(s *trace.SOA) { s.Minimum, s.TTL = 86400, 86400 })},
			want: []string{"stays missing at that resolver for 1 day, the SOA's minimum"},
		},
		"a short TTL on the SOA caps a long minimum": {
			soas:   []trace.SOA{with(func(s *trace.SOA) { s.Minimum, s.TTL = 86400, 900 })},
			unsaid: []string{"missing"},
		},
		"a long TTL with a long minimum names the TTL when it is the shorter": {
			soas: []trace.SOA{with(func(s *trace.SOA) { s.Minimum, s.TTL = 3*86400, 2*86400 })},
			want: []string{"for 2 days, the SOA's TTL"},
		},
		"nameservers that disagree are named with what each holds": {
			soas: []trace.SOA{sound, with(func(s *trace.SOA) { s.Expire = 3600 })},
			want: []string{
				"the nameservers of test. hand out different SOA timers",
				"expire 14 days, minimum 1 hour and TTL 1 hour at ns1.test.",
				"expire 1 hour, minimum 1 hour and TTL 1 hour at ns2.test.",
				"the SOA of test. at ns2.test. expires a copy after 1 hour",
			},
		},
		"a walk saved before the timers were recorded says nothing about them": {
			soas:   []trace.SOA{{Serial: 1, TTL: 3600, Minimum: 3600}},
			unsaid: []string{"SOA", "expires"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			answer := answered(300)
			for i, soa := range tt.soas {
				answer.Children = append(answer.Children, asked([]string{"ns1.test.", "ns2.test."}[i], soa))
			}
			got := said(walk(answer))
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("got %q, want it to say %q", got, want)
				}
			}
			for _, unsaid := range tt.unsaid {
				if strings.Contains(got, unsaid) {
					t.Errorf("got %q, want nothing about %q", got, unsaid)
				}
			}
		})
	}
}

// TestTimersAreWorthALook keeps a timer from breaking --check: hosted
// secondaries never read them, so what they would do is worth a look at most.
func TestTimersAreWorthALook(t *testing.T) {
	answer := answered(300)
	soa := sound
	soa.Expire = 3600
	answer.Children = []*trace.Step{asked("ns1.test.", soa)}

	check := explain.Check(walk(answer))
	for _, graded := range check.Areas {
		if graded.Area != trace.AreaConsistency {
			continue
		}
		if graded.Grade != trace.GradeLook || !strings.Contains(graded.Text, "expires a copy after 1 hour") {
			t.Errorf("got %+v, want the timers worth a look", graded)
		}
		return
	}
	t.Fatal("got no consistency area")
}

// TestTimersGiveWayToCopiesApart keeps a secondary left behind at the head of
// the area, over what a timer would one day do.
func TestTimersGiveWayToCopiesApart(t *testing.T) {
	answer := answered(300)
	soa := sound
	soa.Expire = 3600
	answer.Children = []*trace.Step{asked("ns1.test.", soa)}
	tr := walk(answer)
	behind := "the nameservers of test. are serving different copies of it: 2 at ns1.test., 1 at ns2.test."
	tr.Warnings = []string{behind}
	tr.About = map[string]trace.Concern{behind: {Area: trace.AreaConsistency}}

	for _, graded := range explain.Check(tr).Areas {
		if graded.Area == trace.AreaConsistency && (graded.Text != behind || graded.More != 1) {
			t.Errorf("got %+v, want the copies apart first and the timer behind it", graded)
		}
	}
}
