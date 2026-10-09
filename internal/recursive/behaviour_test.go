package recursive_test

import (
	"slices"
	"strings"
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

func TestBehaveEchoes(t *testing.T) {
	t.Parallel()

	txt := func(data ...string) *trace.Resolver {
		answer := &trace.Resolver{Rcode: "NOERROR"}
		for _, d := range data {
			answer.Records = append(answer.Records, trace.RR{Name: "x.", Type: "TXT", Data: d})
		}
		return answer
	}
	googleSent := txt(`"172.68.199.12"`, `"edns0-client-subnet 198.51.100.0/24"`)
	googleNone := txt(`"172.68.199.12"`)
	akamaiSent := txt(`"ns" "172.68.199.106"`, `"ecs" "198.51.100.0/24/24"`, `"ip" "198.51.100.235"`)
	akamaiNone := txt(`"ns" "2a00:1450:4009:c0f::123"`)
	hooray := txt(`"v=spf1 -all"`, `"HOORAY - QNAME minimisation is enabled on your resolver :)!"`)
	nope := txt(`"NO - QNAME minimisation is NOT enabled on your resolver :("`)

	tests := map[string]struct {
		behaviour trace.Behaviour
		subnet    trace.Observed
		echoes    []trace.Echo
		minimises trace.Observed
	}{
		"a subnet google saw is sent": {
			behaviour: trace.Behaviour{Google: googleSent, Akamai: akamaiNone, Minimisation: hooray},
			subnet:    trace.ObservedYes,
			echoes: []trace.Echo{
				{Operator: "google", Sent: trace.ObservedYes, Bits: 24},
				{Operator: "akamai", Sent: trace.ObservedNo},
			},
			minimises: trace.ObservedYes,
		},
		"a subnet akamai saw is sent, with the scope after it left off": {
			behaviour: trace.Behaviour{Google: googleNone, Akamai: akamaiSent, Minimisation: nope},
			subnet:    trace.ObservedYes,
			echoes: []trace.Echo{
				{Operator: "google", Sent: trace.ObservedNo},
				{Operator: "akamai", Sent: trace.ObservedYes, Bits: 24},
			},
			minimises: trace.ObservedNo,
		},
		"neither zone seeing a subnet is a no": {
			behaviour: trace.Behaviour{Google: googleNone, Akamai: akamaiNone, Minimisation: hooray},
			subnet:    trace.ObservedNo,
			echoes: []trace.Echo{
				{Operator: "google", Sent: trace.ObservedNo},
				{Operator: "akamai", Sent: trace.ObservedNo},
			},
			minimises: trace.ObservedYes,
		},
		"a zone that did not answer leaves only the other": {
			behaviour: trace.Behaviour{Google: &trace.Resolver{Err: "timeout"}, Akamai: akamaiNone},
			subnet:    trace.ObservedNo,
			echoes:    []trace.Echo{{Operator: "akamai", Sent: trace.ObservedNo}},
			minimises: trace.ObservedUnknown,
		},
		"answers in a shape nobody writes cannot be told apart": {
			behaviour: trace.Behaviour{
				Google:       txt(`"edns0-client-subnet nowhere"`),
				Akamai:       txt(`"ecs" "nowhere"`, `"ns" "172.68.199.106"`),
				Minimisation: txt(`"maybe"`),
			},
			subnet: trace.ObservedUnknown, minimises: trace.ObservedUnknown,
		},
		"an address beside text the reader does not know is no evidence of an absence": {
			behaviour: trace.Behaviour{
				Google: txt(`"172.68.199.12"`, `"client-subnet 198.51.100.0/24"`),
				Akamai: txt(`"ns" "172.68.199.106"`, `"subnet" "198.51.100.0/24"`),
			},
			subnet: trace.ObservedUnknown, minimises: trace.ObservedUnknown,
		},
		"a /0 carries no address and is none sent": {
			behaviour: trace.Behaviour{
				Google: txt(`"172.68.199.12"`, `"edns0-client-subnet 0.0.0.0/0"`),
				Akamai: txt(`"ns" "172.68.199.106"`, `"ecs" "0.0.0.0/0/0"`),
			},
			subnet: trace.ObservedNo,
			echoes: []trace.Echo{
				{Operator: "google", Sent: trace.ObservedNo},
				{Operator: "akamai", Sent: trace.ObservedNo},
			},
			minimises: trace.ObservedUnknown,
		},
		"an answer without the resolver's own address is no evidence of an absence": {
			behaviour: trace.Behaviour{Google: txt(`"hello"`), Akamai: txt(`"ip" "198.51.100.235"`)},
			subnet:    trace.ObservedUnknown, minimises: trace.ObservedUnknown,
		},
		"a resolver whose answers were redirected cannot be told apart": {
			behaviour: trace.Behaviour{
				Google: &trace.Resolver{Rcode: "NXDOMAIN"}, Akamai: &trace.Resolver{Rcode: "REFUSED"},
				Minimisation: &trace.Resolver{Rcode: "SERVFAIL"},
			},
			subnet: trace.ObservedUnknown, minimises: trace.ObservedUnknown,
		},
		"escaped strings are read as their octets": {
			behaviour: trace.Behaviour{Google: txt(`"192.0.2.53"`), Akamai: txt(`"\101cs" "198.51.100.0\/20/0"`)},
			subnet:    trace.ObservedYes,
			echoes: []trace.Echo{
				{Operator: "google", Sent: trace.ObservedNo},
				{Operator: "akamai", Sent: trace.ObservedYes, Bits: 20},
			},
			minimises: trace.ObservedUnknown,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			behaviour := test.behaviour
			recursive.Behave(&trace.Trace{Resolvers: []*trace.Resolver{{Behaviour: &behaviour}}})
			if behaviour.Subnet != test.subnet || behaviour.Minimises != test.minimises {
				t.Errorf("got subnet %q and minimises %q, want %q and %q",
					behaviour.Subnet, behaviour.Minimises, test.subnet, test.minimises)
			}
			if !slices.Equal(behaviour.Echoes, test.echoes) {
				t.Errorf("got echoes %+v, want %+v", behaviour.Echoes, test.echoes)
			}
		})
	}
}

// FuzzBehaveEchoes reads TXT written by zones somebody else runs. Whatever
// they write, a yes rests on the marker its operator writes, and a prefix
// length is one an address can have.
func FuzzBehaveEchoes(f *testing.F) {
	for _, seed := range []string{
		`"edns0-client-subnet 198.51.100.0/24"`, `"ecs" "198.51.100.0/24/24"`, `"ns" "192.0.2.1"`,
		`"HOORAY - QNAME minimisation is enabled"`, `"NO - QNAME minimisation is NOT enabled"`,
		`"\101cs" "2001:db8::/56/0"`, `"unterminated`, `\"`, `"\999"`, `"a\`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		answer := &trace.Resolver{Rcode: "NOERROR", Records: []trace.RR{{Type: "TXT", Data: data}}}
		behaviour := trace.Behaviour{Google: answer, Akamai: answer, Minimisation: answer}
		recursive.Behave(&trace.Trace{Resolvers: []*trace.Resolver{{Behaviour: &behaviour}}})

		if behaviour.Minimises == trace.ObservedYes && !strings.Contains(data, "HOORAY") {
			t.Errorf("got minimisation from %q", data)
		}
		for _, echo := range behaviour.Echoes {
			if echo.Sent == trace.ObservedYes && !strings.Contains(data, "/") {
				t.Errorf("got a subnet sent from %q, which names no prefix", data)
			}
			if (echo.Sent == trace.ObservedYes) != (echo.Bits > 0) {
				t.Errorf("got %+v from %q, want a prefix length exactly where one was sent", echo, data)
			}
			if echo.Bits < 0 || echo.Bits > 128 {
				t.Errorf("got /%d from %q", echo.Bits, data)
			}
		}
		if (behaviour.Subnet == trace.ObservedUnknown) != (len(behaviour.Echoes) == 0) {
			t.Errorf("got subnet %q with echoes %+v from %q", behaviour.Subnet, behaviour.Echoes, data)
		}
	})
}
