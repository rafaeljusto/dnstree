package served_test

import (
	"reflect"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/served"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// walk is a walk of www.example.com. A that the servers of example.com.
// answered with the steps given, under a referral from com.
func walk(trial bool, steps ...*trace.Step) *trace.Trace {
	question := trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"}
	for _, step := range steps {
		if step.Asked == (trace.Question{}) {
			step.Asked = question
		}
		if step.Zone == "" {
			step.Zone = "example.com."
		}
	}
	tr := &trace.Trace{Question: question, Root: &trace.Step{Kind: trace.KindZone, Children: []*trace.Step{{
		Zone: "com.", Asked: question, Kind: trace.KindReferral,
		Delegation: &trace.Delegation{Zone: "example.com.", NS: []string{"ns.example.com."}},
		Children:   steps,
	}}}}
	if trial {
		tr.Trial = &trace.Trial{Zone: "example.com.", NS: []string{"ns1.new.net."}}
	}
	return tr
}

func answered(records ...trace.RR) *trace.Step {
	return &trace.Step{Kind: trace.KindAnswer, Records: records}
}

func a(data string, ttl uint32) trace.RR {
	return trace.RR{Name: "www.example.com.", Type: "A", TTL: ttl, Data: data}
}

func TestHold(t *testing.T) {
	signature := trace.RR{Name: "www.example.com.", Type: "RRSIG", TTL: 300, Data: "A 13 3 300 ..."}

	tests := map[string]struct {
		current, tried *trace.Trace
		want           served.Match
		same           bool
	}{
		"the same records at both, signed by each with its own keys": {
			current: walk(false, answered(a("192.0.2.1", 300), signature)),
			tried:   walk(true, answered(a("192.0.2.1", 300), trace.RR{Name: "www.example.com.", Type: "RRSIG", Data: "other"})),
			same:    true,
		},
		"a record left behind and one only the new servers have": {
			current: walk(false, answered(a("192.0.2.1", 300), a("192.0.2.2", 300))),
			tried:   walk(true, answered(a("192.0.2.1", 300), a("192.0.2.9", 300))),
			want: served.Match{
				Missing: []string{"www.example.com. A 192.0.2.2"},
				Extra:   []string{"www.example.com. A 192.0.2.9"},
			},
		},
		"the same records with a longer TTL": {
			current: walk(false, answered(a("192.0.2.1", 300))),
			tried:   walk(true, answered(a("192.0.2.1", 86400))),
			want: served.Match{TTLs: []served.TTL{
				{Set: "www.example.com. A", Current: 300, Tried: 86400}}},
		},
		"an alias flattened into the address it led to": {
			current: walk(false, &trace.Step{Kind: trace.KindCNAME, Records: []trace.RR{
				{Name: "www.example.com.", Type: "CNAME", TTL: 300, Data: "cdn.example.net."}}}),
			tried: walk(true, answered(a("192.0.2.1", 300))),
			want: served.Match{
				Missing: []string{"www.example.com. CNAME cdn.example.net."},
				Extra:   []string{"www.example.com. A 192.0.2.1"},
			},
		},
		"a server that failed before one that answered": {
			current: walk(false, answered(a("192.0.2.1", 300))),
			tried:   walk(true, &trace.Step{Kind: trace.KindTimeout}, answered(a("192.0.2.1", 300))),
			same:    true,
		},
		"new servers that do not answer for the zone yet": {
			current: walk(false, answered(a("192.0.2.1", 300))),
			tried:   walk(true, &trace.Step{Kind: trace.KindLame}),
			want:    served.Match{Missing: []string{"www.example.com. A 192.0.2.1"}},
		},
		"a name only the new servers know": {
			current: walk(false, &trace.Step{Kind: trace.KindNXDomain}),
			tried:   walk(true, answered(a("192.0.2.1", 300))),
			want:    served.Match{Extra: []string{"www.example.com. A 192.0.2.1"}},
		},
		"a minimised hop, which is about another name": {
			current: walk(false, &trace.Step{Kind: trace.KindNoData, Minimised: true}, answered(a("192.0.2.1", 300))),
			tried:   walk(true, answered(a("192.0.2.1", 300))),
			same:    true,
		},
		"a cut below the zone, delegated alike": {
			current: walk(false, &trace.Step{Kind: trace.KindReferral, Delegation: &trace.Delegation{
				Zone: "www.example.com.", TTL: 3600, NS: []string{"ns.www.example.com."}}}),
			tried: walk(true, &trace.Step{Kind: trace.KindReferral, Delegation: &trace.Delegation{
				Zone: "www.example.com.", TTL: 3600, NS: []string{"ns.www.example.com."}}}),
			same: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := served.Hold(test.current, test.tried)
			if got.Same() != test.same {
				t.Errorf("got same %t, want %t: %+v", got.Same(), test.same, got)
			}
			if got.Zone != "example.com." || !reflect.DeepEqual(got.Servers, []string{"ns1.new.net."}) {
				t.Errorf("got %s at %v, want example.com. at ns1.new.net.", got.Zone, got.Servers)
			}
			if !reflect.DeepEqual(got.Missing, test.want.Missing) || !reflect.DeepEqual(got.Extra, test.want.Extra) ||
				!reflect.DeepEqual(got.TTLs, test.want.TTLs) {
				t.Errorf("got missing %q, extra %q, ttls %v; want %q, %q, %v",
					got.Missing, got.Extra, got.TTLs, test.want.Missing, test.want.Extra, test.want.TTLs)
			}
		})
	}
}

func TestOfEscapes(t *testing.T) {
	tr := walk(false, answered(trace.RR{Name: "www.example.com.", Type: "TXT", TTL: 300, Data: "\x1b[2J"}))
	tr.Question.Type = "TXT"
	tr.Root.Children[0].Children[0].Asked.Type = "TXT"
	got := served.Of(tr, "example.com.")
	if want := []string{`www.example.com. TXT \027[2J`}; !reflect.DeepEqual(got.Records, want) {
		t.Errorf("got %q, want %q", got.Records, want)
	}
}
