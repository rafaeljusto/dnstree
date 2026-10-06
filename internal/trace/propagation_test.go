package trace_test

import (
	"reflect"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// walked is a walk from the root to example.com., which the given steps of
// the zone end. The referral to it is shaped by delegation and verdict.
func walked(delegation *trace.Delegation, verdict *trace.DNSSECStatus, ended ...*trace.Step) *trace.Trace {
	referral := &trace.Step{Zone: "com.", Kind: trace.KindReferral, Delegation: delegation, DNSSEC: verdict,
		Children: ended}
	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
			{Zone: ".", Kind: trace.KindReferral, Children: []*trace.Step{referral}},
		}},
	}
}

func answered(ttl uint32) *trace.Step {
	return &trace.Step{Zone: "example.com.", Kind: trace.KindAnswer, Records: []trace.RR{
		{Name: "www.example.com.", TTL: ttl, Type: "A", Data: "192.0.2.1"},
	}}
}

func TestPropagated(t *testing.T) {
	delegation := &trace.Delegation{Zone: "example.com.", TTL: 172800}
	secure := &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.", DSTTL: 86400, KeysTTL: 3600}

	tests := map[string]struct {
		tr   *trace.Trace
		want []trace.Wait
	}{
		"an answer and the delegation to it": {
			tr: walked(delegation, nil, answered(300)),
			want: []trace.Wait{
				{Change: trace.ChangeAnswer, Seconds: 300, Type: "A", Held: []trace.Held{{Zone: "example.com.", TTL: 300}}},
				{Change: trace.ChangeNameservers, Seconds: 172800, Type: "NS", Held: []trace.Held{{Zone: "com.", TTL: 172800}}},
			},
		},
		"the zone's own NS set kept longer than the parent's": {
			tr: walked(&trace.Delegation{Zone: "example.com.", TTL: 3600, ZoneTTL: 86400}, nil, answered(300)),
			want: []trace.Wait{
				{Change: trace.ChangeAnswer, Seconds: 300, Type: "A", Held: []trace.Held{{Zone: "example.com.", TTL: 300}}},
				{Change: trace.ChangeNameservers, Seconds: 86400, Type: "NS", Held: []trace.Held{
					{Zone: "com.", TTL: 3600}, {Zone: "example.com.", TTL: 86400}}},
			},
		},
		"a denial is kept for the shorter of the SOA's ttl and minimum": {
			tr: walked(delegation, nil, &trace.Step{Zone: "example.com.", Kind: trace.KindNXDomain,
				SOA: &trace.SOA{TTL: 3600, Minimum: 900}}),
			want: []trace.Wait{
				{Change: trace.ChangeDenial, Seconds: 900, Type: "SOA", Held: []trace.Held{
					{Zone: "example.com.", TTL: 3600}, {Zone: "example.com.", TTL: 900, Field: "minimum"}}},
				{Change: trace.ChangeNameservers, Seconds: 172800, Type: "NS", Held: []trace.Held{{Zone: "com.", TTL: 172800}}},
			},
		},
		"the longest of the SOAs --serial read": {
			tr: walked(nil, nil, answered(300),
				&trace.Step{Zone: "example.com.", Kind: trace.KindAnswer, Aside: true, SOA: &trace.SOA{TTL: 600, Minimum: 600}},
				&trace.Step{Zone: "example.com.", Kind: trace.KindAnswer, Aside: true, SOA: &trace.SOA{TTL: 1800, Minimum: 1800}}),
			want: []trace.Wait{
				{Change: trace.ChangeAnswer, Seconds: 300, Type: "A", Held: []trace.Held{{Zone: "example.com.", TTL: 300}}},
				{Change: trace.ChangeDenial, Seconds: 1800, Type: "SOA", Held: []trace.Held{
					{Zone: "example.com.", TTL: 1800}, {Zone: "example.com.", TTL: 1800, Field: "minimum"}}},
			},
		},
		"the DS and keys of a secure zone": {
			tr: walked(delegation, secure, answered(300)),
			want: []trace.Wait{
				{Change: trace.ChangeAnswer, Seconds: 300, Type: "A", Held: []trace.Held{{Zone: "example.com.", TTL: 300}}},
				{Change: trace.ChangeNameservers, Seconds: 172800, Type: "NS", Held: []trace.Held{{Zone: "com.", TTL: 172800}}},
				{Change: trace.ChangeDS, Seconds: 86400, Type: "DS", Held: []trace.Held{{Zone: "com.", TTL: 86400}}},
				{Change: trace.ChangeKeys, Seconds: 3600, Type: "DNSKEY", Held: []trace.Held{{Zone: "example.com.", TTL: 3600}}},
			},
		},
		"no DS or keys from a chain that did not hold": {
			tr: walked(delegation, &trace.DNSSECStatus{State: trace.Bogus, Zone: "example.com.", DSTTL: 86400, KeysTTL: 3600},
				answered(300)),
			want: []trace.Wait{
				{Change: trace.ChangeAnswer, Seconds: 300, Type: "A", Held: []trace.Held{{Zone: "example.com.", TTL: 300}}},
				{Change: trace.ChangeNameservers, Seconds: 172800, Type: "NS", Held: []trace.Held{{Zone: "com.", TTL: 172800}}},
			},
		},
		"no answer from a minimised hop": {
			tr: walked(delegation, nil, &trace.Step{Zone: "example.com.", Kind: trace.KindAnswer, Minimised: true,
				Records: []trace.RR{{Name: "www.example.com.", TTL: 300, Type: "A"}}}),
			want: []trace.Wait{
				{Change: trace.ChangeNameservers, Seconds: 172800, Type: "NS", Held: []trace.Held{{Zone: "com.", TTL: 172800}}},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := test.tr.Propagated()
			if got == nil || got.Zone != "example.com." {
				t.Fatalf("got %+v, want the waits of example.com.", got)
			}
			if !reflect.DeepEqual(got.Waits, test.want) {
				t.Errorf("got %+v\nwant %+v", got.Waits, test.want)
			}
		})
	}
}

func TestPropagatedWithoutAZone(t *testing.T) {
	got := (&trace.Trace{}).Propagated()
	if got == nil || got.Zone != "" || len(got.Waits) != 0 {
		t.Errorf("got %+v, want no waits for a walk that reached no zone", got)
	}
}
