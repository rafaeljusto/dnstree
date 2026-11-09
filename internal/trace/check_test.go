package trace_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestNSAgree(t *testing.T) {
	tests := map[string]struct {
		delegation  *trace.Delegation
		agree, know bool
	}{
		"no delegation says nothing": {},
		"a zone that gave no list says nothing": {
			delegation: &trace.Delegation{NS: []string{"ns1.test."}},
		},
		"the same names in another order and case agree": {
			delegation: &trace.Delegation{NS: []string{"ns1.test.", "ns2.test."}, ZoneNS: []string{"NS2.test.", "ns1.TEST."}},
			agree:      true, know: true,
		},
		"a name only the zone lists disagrees": {
			delegation: &trace.Delegation{NS: []string{"ns1.test."}, ZoneNS: []string{"ns1.test.", "ns2.test."}},
			know:       true,
		},
		"a name only the parent lists disagrees": {
			delegation: &trace.Delegation{NS: []string{"ns1.test.", "ns2.test."}, ZoneNS: []string{"ns1.test."}},
			know:       true,
		},
		"case folds only over ASCII, as DNS does": {
			delegation: &trace.Delegation{NS: []string{"\xc3\xa9.test."}, ZoneNS: []string{"\xc3\x89.test."}},
			know:       true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			agree, know := test.delegation.NSAgree()
			if agree != test.agree || know != test.know {
				t.Errorf("got agree %t, known %t, want %t, %t", agree, know, test.agree, test.know)
			}
		})
	}
}
