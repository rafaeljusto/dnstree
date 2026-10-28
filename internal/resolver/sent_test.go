package resolver_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestSent covers what each hop records it sent, which --format dig repeats.
// It is read off the query that got the answer the hop kept, so a retry shows
// as the retry and a probe as the probe.
func TestSent(t *testing.T) {
	t.Parallel()

	subnet := netip.MustParsePrefix("198.51.100.0/24")
	probe := func(kind trace.ProbeKind) func(*trace.Trace) *trace.Step {
		return func(tr *trace.Trace) *trace.Step {
			for step := range tr.Steps() {
				if step.Probe != nil && step.Probe.Kind == kind {
					return step
				}
			}
			return nil
		}
	}
	edns := func(kind trace.EDNSKind) func(*trace.Trace) *trace.Step {
		return func(tr *trace.Trace) *trace.Step { return ednsTests(tr)["ns1.test. "+string(kind)] }
	}
	answer := (*trace.Trace).Result
	root := func(tr *trace.Trace) *trace.Step { return tr.Root.Children[0] }

	tests := map[string]struct {
		setup func(testing.TB) (harness, resolver.Config)
		pick  func(*trace.Trace) *trace.Step
		want  *trace.Sent
	}{
		"a hop of a validating walk asks without recursion, with the buffer and the DO bit": {
			setup: func(tb testing.TB) (harness, resolver.Config) { return service(tb, true, fakens.Behaviour{}) },
			pick:  answer,
			want:  &trace.Sent{EDNS: true, UDPSize: 1232, DO: true},
		},
		"a server that cannot parse EDNS0 is recorded as asked without it": {
			setup: func(tb testing.TB) (harness, resolver.Config) {
				return service(tb, false, fakens.Behaviour{FormErrEDNS: true})
			},
			pick: answer,
			want: &trace.Sent{},
		},
		"the options the run asks for ride on every hop": {
			setup: func(tb testing.TB) (harness, resolver.Config) {
				h, cfg := service(tb, false, fakens.Behaviour{})
				cfg.NSID, cfg.Cookie, cfg.Subnet = true, true, subnet
				return h, cfg
			},
			pick: root,
			want: &trace.Sent{EDNS: true, UDPSize: 1232, NSID: true, Cookie: true, Subnet: subnet},
		},
		"the version test sends the version it tests": {
			setup: ednsChecked,
			pick:  edns(trace.EDNSVersion),
			want:  &trace.Sent{EDNS: true, Version: 1, UDPSize: 1232},
		},
		"the option test sends the option it tests": {
			setup: ednsChecked,
			pick:  edns(trace.EDNSOption),
			want:  &trace.Sent{EDNS: true, UDPSize: 1232, Options: []uint16{100}},
		},
		"the flag test sends the flag it tests": {
			setup: ednsChecked,
			pick:  edns(trace.EDNSFlag),
			want:  &trace.Sent{EDNS: true, UDPSize: 1232, Flags: 0x40},
		},
		"the probe for open recursion asks for recursion": {
			setup: func(tb testing.TB) (harness, resolver.Config) {
				h, cfg := exposed(tb, fakens.Behaviour{}, fakens.Behaviour{})
				cfg.CheckRecursion = true
				return h, cfg
			},
			pick: probe(trace.ProbeRecursion),
			want: &trace.Sent{Recursion: true, EDNS: true, UDPSize: 1232},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := tt.setup(t)
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			step := tt.pick(tr)
			if step == nil {
				t.Fatalf("got no such hop: %s", format(steps(tr)))
			}
			if !reflect.DeepEqual(step.Sent, tt.want) {
				t.Errorf("got %+v, want %+v", step.Sent, tt.want)
			}
		})
	}
}

func ednsChecked(tb testing.TB) (harness, resolver.Config) {
	h, cfg := exposed(tb, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.CheckEDNS = true
	return h, cfg
}
