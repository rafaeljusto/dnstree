package recursive_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/recursive"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestBehave(t *testing.T) {
	t.Parallel()

	address := []trace.RR{{Name: "x.", Type: "A", Data: "198.51.100.1"}}
	answered := &trace.Resolver{Rcode: "NOERROR", Records: address}
	plainRoot := &trace.Resolver{Rcode: "NOERROR"}
	authenticRoot := &trace.Resolver{Rcode: "NOERROR", Authentic: true}
	nxdomain := &trace.Resolver{Rcode: "NXDOMAIN"}

	tests := map[string]struct {
		behaviour           trace.Behaviour
		validates, rewrites trace.Observed
	}{
		"a resolver that fails the broken name and answers it unchecked validates": {
			behaviour: trace.Behaviour{
				Broken: &trace.Resolver{Rcode: "SERVFAIL", Unchecked: answered},
				Root:   authenticRoot, Missing: nxdomain,
			},
			validates: trace.ObservedYes, rewrites: trace.ObservedNo,
		},
		"a resolver that fails the broken name and says it is bogus validates": {
			behaviour: trace.Behaviour{
				Broken: &trace.Resolver{Rcode: "SERVFAIL", Extended: []trace.ExtendedError{{Code: 6}}},
				Root:   authenticRoot, Missing: nxdomain,
			},
			validates: trace.ObservedYes, rewrites: trace.ObservedNo,
		},
		"a resolver that fails the broken name unchecked too cannot be told apart": {
			behaviour: trace.Behaviour{
				Broken: &trace.Resolver{Rcode: "SERVFAIL", Unchecked: &trace.Resolver{Rcode: "SERVFAIL"}},
				Root:   authenticRoot, Missing: nxdomain,
			},
			validates: trace.ObservedUnknown, rewrites: trace.ObservedNo,
		},
		"a resolver that answers the broken name and marks nothing authentic does not validate": {
			behaviour: trace.Behaviour{Broken: answered, Root: plainRoot, Missing: nxdomain},
			validates: trace.ObservedNo, rewrites: trace.ObservedNo,
		},
		"a resolver that answers the broken name but marks the root authentic cannot be told apart": {
			behaviour: trace.Behaviour{Broken: answered, Root: authenticRoot, Missing: nxdomain},
			validates: trace.ObservedUnknown, rewrites: trace.ObservedNo,
		},
		"a resolver that answers the broken name with no root to read it against cannot be told apart": {
			behaviour: trace.Behaviour{Broken: answered, Root: &trace.Resolver{Err: "timeout"}, Missing: nxdomain},
			validates: trace.ObservedUnknown, rewrites: trace.ObservedNo,
		},
		"a name that cannot exist answered with an address is rewritten": {
			behaviour: trace.Behaviour{Broken: answered, Root: plainRoot, Missing: answered},
			validates: trace.ObservedNo, rewrites: trace.ObservedYes,
		},
		"a name that cannot exist answered with nothing cannot be told apart": {
			behaviour: trace.Behaviour{Broken: answered, Root: plainRoot, Missing: plainRoot},
			validates: trace.ObservedNo, rewrites: trace.ObservedUnknown,
		},
		"a resolver that answered nothing cannot be told apart": {
			behaviour: trace.Behaviour{
				Broken: &trace.Resolver{Err: "timeout"}, Root: &trace.Resolver{Err: "timeout"},
				Missing: &trace.Resolver{Err: "timeout"},
			},
			validates: trace.ObservedUnknown, rewrites: trace.ObservedUnknown,
		},
		"a resolver that refused cannot be told apart": {
			behaviour: trace.Behaviour{
				Broken: &trace.Resolver{Rcode: "REFUSED"}, Root: &trace.Resolver{Rcode: "REFUSED"},
				Missing: &trace.Resolver{Rcode: "REFUSED"},
			},
			validates: trace.ObservedUnknown, rewrites: trace.ObservedUnknown,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			behaviour := test.behaviour
			tr := &trace.Trace{Resolvers: []*trace.Resolver{{Behaviour: &behaviour}, nil, {}}}
			recursive.Behave(tr)
			if behaviour.Validates != test.validates || behaviour.Rewrites != test.rewrites {
				t.Errorf("got validates %q and rewrites %q, want %q and %q",
					behaviour.Validates, behaviour.Rewrites, test.validates, test.rewrites)
			}
		})
	}
}
