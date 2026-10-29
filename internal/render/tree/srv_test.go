package tree_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderSRV(t *testing.T) {
	secure := &trace.DNSSECStatus{State: trace.Secure}
	answered := &trace.Lookup{Name: "chat.example."}
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	for name, tt := range map[string]struct {
		srv  *trace.SRV
		want []string
	}{
		"targets that resolve, by priority": {
			srv: &trace.SRV{Name: "_xmpp._tcp.test.", Lookup: trace.Lookup{Name: "_xmpp._tcp.test.", DNSSEC: secure},
				Targets: []trace.SRVTarget{
					{Name: "chat.example.", Priority: 10, Weight: 50, Port: 5222, IPv4: answered, Addrs: addrs},
					{Name: "chat2.example.", Priority: 20, Weight: 50, Port: 5222, IPv4: answered},
				}},
			want: []string{
				"srv: 2 SRV records at _xmpp._tcp.test.  [secure]",
				"srv:   10 50 5222 chat.example. 192.0.2.10, 2001:db8::10",
				"srv:   20 50 5222 chat2.example. no address",
			},
		},
		"an alias, an unreachable address and a failed lookup": {
			srv: &trace.SRV{Name: "_sip._udp.test.", Lookup: trace.Lookup{Name: "_sip._udp.test."},
				Targets: []trace.SRVTarget{
					{Name: "a.example.", Priority: 1, Port: 5060, IPv4: &trace.Lookup{Name: "a.example.", Alias: "b.example."}, Addrs: addrs[:1]},
					{Name: "c.example.", Priority: 2, Port: 5060, IPv4: answered, Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.5")},
						Unreachable: []netip.Addr{netip.MustParseAddr("10.0.0.5")}},
					{Name: "d.example.", Priority: 3, Port: 5060, IPv4: &trace.Lookup{Name: "d.example.", Err: "SERVFAIL"}},
				}},
			want: []string{
				"srv: 3 SRV records at _sip._udp.test.",
				"srv:   1 0 5060 a.example. 192.0.2.10; an alias for b.example.",
				"srv:   2 0 5060 c.example. 10.0.0.5; 10.0.0.5 cannot be reached from the internet",
				"srv:   3 0 5060 d.example. address lookup failed: SERVFAIL",
			},
		},
		"a set reached through an alias": {
			srv:  &trace.SRV{Name: "_x._tcp.test.", Lookup: trace.Lookup{Name: "_x._tcp.test.", Alias: "_y._tcp.test."}},
			want: []string{"srv: no SRV records at _y._tcp.test."},
		},
		"a target of . alone": {
			srv:  &trace.SRV{Name: "_x._tcp.test.", None: true},
			want: []string{"srv: _x._tcp.test. says the service is not offered there"},
		},
		"a check that stopped": {
			srv:  &trace.SRV{Name: "_x._tcp.test.", Stopped: "the SRV lookup failed: SERVFAIL", Lookup: trace.Lookup{Err: "SERVFAIL"}},
			want: []string{"srv: stopped: the SRV lookup failed: SERVFAIL"},
		},
		"a budget that left targets": {
			srv: &trace.SRV{Name: "_x._tcp.test.", Cut: true, Left: 2,
				Targets: []trace.SRVTarget{{Name: "chat.example.", Priority: 1, Port: 80, IPv4: answered, Addrs: addrs[:1]}}},
			want: []string{
				"srv: 3 SRV records at _x._tcp.test.",
				"srv:   1 0 80 chat.example. 192.0.2.10",
				"srv: the budget ran out before 2 targets were looked up",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.SRV = tt.srv
			var got []string
			for line := range strings.Lines(draw(t, tr)) {
				if strings.HasPrefix(line, "srv: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
