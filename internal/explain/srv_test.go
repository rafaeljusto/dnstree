package explain_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestSRV(t *testing.T) {
	asked := &trace.Lookup{Name: "chat.example."}
	addr := []netip.Addr{netip.MustParseAddr("192.0.2.7")}
	for name, tt := range map[string]struct {
		srv  *trace.SRV
		want string
	}{
		"targets that resolve": {
			srv: &trace.SRV{Name: "_xmpp._tcp.test.", Targets: []trace.SRVTarget{
				{Name: "chat.example.", Port: 5222, IPv4: asked, Addrs: addr},
				{Name: "chat2.example.", Port: 5222, IPv4: asked, Addrs: addr},
			}},
			want: "a client of the service at _xmpp._tcp.test. is sent to chat.example. port 5222, then chat2.example. port 5222; whether the service answers there was not checked",
		},
		"a target with no address": {
			srv:  &trace.SRV{Name: "_xmpp._tcp.test.", Targets: []trace.SRVTarget{{Name: "chat.example.", IPv4: asked}}},
			want: "name chat.example., which has no address, so a client sent there has nothing to connect to",
		},
		"a target whose address lookups failed": {
			srv: &trace.SRV{Name: "_xmpp._tcp.test.", Targets: []trace.SRVTarget{
				{Name: "chat.example.", IPv4: &trace.Lookup{Name: "chat.example.", Err: "SERVFAIL"}}}},
			want: "name chat.example., whose addresses could not be looked up",
		},
		"a target whose addresses do not validate": {
			srv: &trace.SRV{Name: "_xmpp._tcp.test.", Targets: []trace.SRVTarget{
				{Name: "chat.example.", IPv4: &trace.Lookup{Name: "chat.example.", DNSSEC: &trace.DNSSECStatus{State: trace.Bogus}}}}},
			want: "name chat.example., whose addresses do not validate, so a client that validates has nothing to connect to there",
		},
		"a target that is an alias": {
			srv: &trace.SRV{Name: "_xmpp._tcp.test.", Targets: []trace.SRVTarget{
				{Name: "chat.example.", IPv4: &trace.Lookup{Name: "chat.example.", Alias: "host.example."}, Addrs: addr}}},
			want: "name chat.example., which is an alias, so clients that keep to RFC 2782 may not follow it",
		},
		"a target nobody can reach": {
			srv: &trace.SRV{Name: "_xmpp._tcp.test.", Targets: []trace.SRVTarget{
				{Name: "chat.example.", IPv4: asked, Addrs: addr, Unreachable: addr}}},
			want: "at addresses no client on the internet can reach",
		},
		"a target of . alone": {
			srv:  &trace.SRV{Name: "_xmpp._tcp.test.", None: true},
			want: "_xmpp._tcp.test. says, with a target of ., that the service is not offered there",
		},
		"no records": {
			srv:  &trace.SRV{Name: "_xmpp._tcp.test."},
			want: "_xmpp._tcp.test. has no SRV records, so a client finds no server for the service there",
		},
		"a check the budget cut short": {
			srv:  &trace.SRV{Name: "_xmpp._tcp.test.", Cut: true, Left: 2},
			want: "ran out of budget before every target was looked up, and left 2 targets",
		},
		"a check that stopped": {
			srv:  &trace.SRV{Name: "_xmpp._tcp.test.", Stopped: "the SRV lookup failed: SERVFAIL"},
			want: "the SRV check of _xmpp._tcp.test. stopped: the SRV lookup failed: SERVFAIL",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := walk(answered(300))
			tr.SRV = tt.srv
			if got := said(tr); !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want it to say %q", got, tt.want)
			}
		})
	}
}
