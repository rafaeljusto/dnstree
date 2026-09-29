package resolver

import (
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestUnowned(t *testing.T) {
	denial := func(soa string, answer ...string) *dns.Msg {
		msg := dns.NewMsg("x.", dns.TypeA)
		msg.Rcode = dns.RcodeNameError
		for _, text := range answer {
			msg.Answer = append(msg.Answer, mustRR(t, text))
		}
		if soa != "" {
			msg.Ns = append(msg.Ns, mustRR(t, soa+" 3600 IN SOA ns.test. hostmaster.test. 1 7200 3600 1209600 3600"))
		}
		return msg
	}

	tests := map[string]struct {
		resp  *dns.Msg
		zone  string
		qname string
		want  *trace.Dangling
	}{
		"the name directly below the zone that denied it is what is missing": {
			resp: denial("com."), zone: "com.", qname: "ns1.gone.com.",
			want: &trace.Dangling{Target: "ns1.gone.com.", Missing: "gone.com.", Zone: "com."},
		},
		"a denial across the cut is the child's, not the parent's": {
			resp: denial("sub.example.com."), zone: "example.com.", qname: "a.b.sub.example.com.",
			want: &trace.Dangling{Target: "a.b.sub.example.com.", Missing: "b.sub.example.com.", Zone: "sub.example.com."},
		},
		"an alias chain in the answer names the end of it, and the alias": {
			resp: denial("cloud.test.",
				"www.example.test. 300 IN CNAME mid.example.test.",
				"mid.example.test. 300 IN CNAME gone.cloud.test."),
			zone: "test.", qname: "www.example.test.",
			want: &trace.Dangling{Kind: trace.DanglingAlias, Name: "mid.example.test.",
				Target: "gone.cloud.test.", Missing: "gone.cloud.test.", Zone: "cloud.test."},
		},
		"a denial with no soa names no zone": {
			resp: denial(""), zone: "com.", qname: "ns1.gone.com.",
		},
		"a soa above the zone asked is not the server's to give": {
			resp: denial("."), zone: "com.", qname: "ns1.gone.com.",
		},
		"a soa the name is not under says nothing about it": {
			resp: denial("other.com."), zone: "com.", qname: "ns1.gone.com.",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := unowned(tt.resp, tt.zone, tt.qname)
			switch {
			case tt.want == nil && got != nil:
				t.Errorf("got %+v, want nothing read as missing", *got)
			case tt.want != nil && got == nil:
				t.Errorf("got nothing, want %+v", *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Errorf("got %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

func mustRR(tb testing.TB, text string) dns.RR {
	tb.Helper()
	rr, err := dns.New(text)
	if err != nil {
		tb.Fatalf("dns.New(%q): %v", text, err)
	}
	return rr
}
