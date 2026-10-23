package recursive_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/recursive"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestBehaveDNS64(t *testing.T) {
	t.Parallel()

	aaaa := func(data ...string) *trace.Resolver {
		answer := &trace.Resolver{Rcode: "NOERROR"}
		for _, d := range data {
			answer.Records = append(answer.Records, trace.RR{Name: "ipv4only.arpa.", Type: "AAAA", Data: d})
		}
		return answer
	}

	tests := map[string]struct {
		answer      *trace.Resolver
		synthesises trace.Observed
		prefixes    []string
	}{
		"both known addresses under the well-known prefix name it once": {
			answer:      aaaa("64:ff9b::c000:aa", "64:ff9b::c000:ab"),
			synthesises: trace.ObservedYes,
			prefixes:    []string{"64:ff9b::/96"},
		},
		"a network's own /64 skips the octet at bits 64 to 71": {
			answer:      aaaa("2001:db8:1:2:c0:0:aa00:0"),
			synthesises: trace.ObservedYes,
			prefixes:    []string{"2001:db8:1:2::/64"},
		},
		"a /32 carries the address straight after it": {
			answer:      aaaa("2001:db8:c000:aa::"),
			synthesises: trace.ObservedYes,
			prefixes:    []string{"2001:db8::/32"},
		},
		"an AAAA that carries neither known address is made up under no prefix that can be named": {
			answer:      aaaa("2001:db8::1"),
			synthesises: trace.ObservedYes,
		},
		"no AAAA is a resolver that makes none up": {
			answer:      aaaa(),
			synthesises: trace.ObservedNo,
		},
		"an NXDOMAIN for a name that exists says nothing": {
			answer:      &trace.Resolver{Rcode: "NXDOMAIN"},
			synthesises: trace.ObservedUnknown,
		},
		"a resolver that did not answer says nothing": {
			answer:      &trace.Resolver{Err: "timeout"},
			synthesises: trace.ObservedUnknown,
		},
		"a walk saved before it was asked says nothing": {
			synthesises: trace.ObservedUnknown,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			behaviour := trace.Behaviour{DNS64: test.answer}
			recursive.Behave(&trace.Trace{Resolvers: []*trace.Resolver{{Behaviour: &behaviour}}})
			var prefixes []string
			for _, prefix := range behaviour.Prefixes {
				prefixes = append(prefixes, prefix.String())
			}
			if behaviour.Synthesises != test.synthesises || !slices.Equal(prefixes, test.prefixes) {
				t.Errorf("got %q under %v, want %q under %v",
					behaviour.Synthesises, prefixes, test.synthesises, test.prefixes)
			}
		})
	}
}

func TestCompareDNS64(t *testing.T) {
	t.Parallel()

	wellKnown := &trace.Behaviour{Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}}
	aaaa := func(seen *trace.Behaviour, data ...string) *trace.Resolver {
		answer := &trace.Resolver{Rcode: "NOERROR", Behaviour: seen}
		for _, d := range data {
			answer.Records = append(answer.Records, trace.RR{Name: "www.test.", Type: "AAAA", Data: d})
		}
		return answer
	}

	tests := map[string]struct {
		ours        []string
		answer      *trace.Resolver
		synthesised bool
		match       trace.Match
	}{
		"an AAAA made up under the resolver's prefix where the zone has none is not a difference": {
			answer:      aaaa(wellKnown, "64:ff9b::c000:219"),
			synthesised: true,
		},
		"an AAAA outside the prefix still differs": {
			answer: aaaa(wellKnown, "2001:db8::1"),
			match:  trace.MatchDiffers,
		},
		"one AAAA outside the prefix among made-up ones still differs": {
			answer: aaaa(wellKnown, "64:ff9b::c000:219", "2001:db8::1"),
			match:  trace.MatchDiffers,
		},
		"an AAAA the zone does publish is compared as it is": {
			ours:   []string{"2001:db8::1"},
			answer: aaaa(wellKnown, "64:ff9b::c000:219"),
			match:  trace.MatchDiffers,
		},
		"without --check-resolver no prefix is known and it differs": {
			answer: aaaa(nil, "64:ff9b::c000:219"),
			match:  trace.MatchDiffers,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tr := traceOf("NOERROR", nil, test.answer)
			tr.Question.Type = "AAAA"
			for _, data := range test.ours {
				result := tr.Root.Children[0]
				result.Records = append(result.Records, trace.RR{Name: "www.test.", Type: "AAAA", Data: data})
			}
			recursive.Compare(tr)
			if test.answer.Synthesised != test.synthesised || test.answer.Match != test.match {
				t.Errorf("got synthesised %t and match %q, want %t and %q",
					test.answer.Synthesised, test.answer.Match, test.synthesised, test.match)
			}
		})
	}
}
