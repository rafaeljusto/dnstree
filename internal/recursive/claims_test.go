package recursive_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/recursive"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestClaims(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		text     []string
		qnamemin bool
		exterr   []trace.CodeRange
		infoURL  string
	}{
		"the RFC's example reads as its three claims": {
			text:     []string{"qnamemin", "exterr=15-17", "infourl=https://resolver.example.com/guide"},
			qnamemin: true, exterr: []trace.CodeRange{{From: 15, To: 17}}, infoURL: "https://resolver.example.com/guide",
		},
		"single codes and ranges mix in one list": {
			text:   []string{"exterr=1,15-17,20"},
			exterr: []trace.CodeRange{{From: 1, To: 1}, {From: 15, To: 17}, {From: 20, To: 20}},
		},
		"keys are read without regard to case": {
			text: []string{"QNAMEMIN", "InfoURL=https://x.example"}, qnamemin: true, infoURL: "https://x.example",
		},
		"only the first of a key counts": {
			text: []string{"exterr=1", "exterr=2-3"}, exterr: []trace.CodeRange{{From: 1, To: 1}},
		},
		"a bad first exterr is not replaced by a later one": {
			text: []string{"exterr=x", "exterr=2"},
		},
		"qnamemin with a value is not the boolean the RFC defines": {
			text: []string{"qnamemin=1"},
		},
		"a list with one item that cannot be read claims nothing": {
			text: []string{"exterr=15-17,x"},
		},
		"a range that runs backwards claims nothing": {
			text: []string{"exterr=17-15"},
		},
		"a code past 65535 claims nothing": {
			text: []string{"exterr=65536"},
		},
		"a signed code claims nothing": {
			text: []string{"exterr=+15"},
		},
		"an empty list claims nothing": {
			text: []string{"exterr="},
		},
		"a link that is not https is left out": {
			text: []string{"infourl=http://x.example"},
		},
		"a link with no host is left out": {
			text: []string{"infourl=https:///guide"},
		},
		"a link with an escaped byte is left out": {
			text: []string{`infourl=https://x.example/\027[2J`},
		},
		"a link with a space is left out": {
			text: []string{"infourl=https://x.example/a b"},
		},
		"keys this build does not know are ignored": {
			text: []string{"temp-dnssecval", "qnamemin"}, qnamemin: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			qnamemin, exterr, infoURL := recursive.Claims(tt.text)
			if qnamemin != tt.qnamemin || !slices.Equal(exterr, tt.exterr) || infoURL != tt.infoURL {
				t.Errorf("got %v %v %q, want %v %v %q", qnamemin, exterr, infoURL, tt.qnamemin, tt.exterr, tt.infoURL)
			}
		})
	}
}

func TestBehaveClaims(t *testing.T) {
	t.Parallel()

	blocked := []trace.ExtendedError{{Code: 15}}
	missing := []trace.ExtendedError{{Code: 9}}
	minimising := &trace.Resolver{Rcode: "NOERROR", Records: []trace.RR{{Type: "TXT", Data: `"HOORAY - QNAME minimisation is enabled on your resolver :)!"`}}}
	whole := &trace.Resolver{Rcode: "NOERROR", Records: []trace.RR{{Type: "TXT", Data: `"NO - QNAME minimisation is NOT enabled on your resolver :("`}}}

	tests := map[string]struct {
		text      []string
		answer    trace.Resolver
		minimises trace.Observed
		unlisted  []uint16
	}{
		"a resolver that minimises as it claims holds to it": {
			text: []string{"qnamemin"}, answer: trace.Resolver{Behaviour: &trace.Behaviour{Minimisation: minimising}},
			minimises: trace.ObservedYes,
		},
		"a resolver that asks for the whole name does not": {
			text: []string{"qnamemin"}, answer: trace.Resolver{Behaviour: &trace.Behaviour{Minimisation: whole}},
			minimises: trace.ObservedNo,
		},
		"a test that could not tell leaves the claim unknown": {
			text: []string{"qnamemin"}, answer: trace.Resolver{Behaviour: &trace.Behaviour{}},
			minimises: trace.ObservedUnknown,
		},
		"no qnamemin claim is not held against anything": {
			answer: trace.Resolver{Behaviour: &trace.Behaviour{Minimisation: whole}},
		},
		"a code returned and listed is no mismatch": {
			text:   []string{"exterr=15-17"},
			answer: trace.Resolver{Extended: blocked, Behaviour: &trace.Behaviour{}},
		},
		"a code returned on a recheck and not listed is one": {
			text: []string{"exterr=15-17"},
			answer: trace.Resolver{Behaviour: &trace.Behaviour{
				Broken: &trace.Resolver{Rcode: "SERVFAIL", Unchecked: &trace.Resolver{Extended: missing}},
			}},
			unlisted: []uint16{9},
		},
		"a code returned to a sentinel question counts as well": {
			text: []string{"exterr=15"},
			answer: trace.Resolver{Extended: blocked, Behaviour: &trace.Behaviour{
				Sentinels: []trace.Sentinel{{Not: &trace.Resolver{Extended: missing}}},
			}},
			unlisted: []uint16{9},
		},
		"a code returned twice is said once": {
			text:     []string{"exterr=15"},
			answer:   trace.Resolver{Extended: missing, Behaviour: &trace.Behaviour{Missing: &trace.Resolver{Extended: missing}}},
			unlisted: []uint16{9},
		},
		"a code listed and never returned is no mismatch": {
			text: []string{"exterr=1-30"}, answer: trace.Resolver{Behaviour: &trace.Behaviour{}},
		},
		"without an exterr claim no code is held against it": {
			answer: trace.Resolver{Extended: missing, Behaviour: &trace.Behaviour{}},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			answer := tt.answer
			answer.DDR = &trace.Discovery{Info: &trace.ResolverInfo{Target: "dns.test.", Text: tt.text}}
			recursive.Behave(&trace.Trace{Resolvers: []*trace.Resolver{&answer}})

			info := answer.DDR.Info
			if info.Minimises != tt.minimises || !slices.Equal(info.Unlisted, tt.unlisted) {
				t.Errorf("got %q %v, want %q %v", info.Minimises, info.Unlisted, tt.minimises, tt.unlisted)
			}
		})
	}
}

// FuzzClaims holds the reading of a stranger's record to what the renderers
// rely on: a link is https and drawable as it stands, and ranges run forwards.
func FuzzClaims(f *testing.F) {
	f.Add("qnamemin\x00exterr=15-17\x00infourl=https://resolver.example.com/guide")
	f.Add("exterr=1,2-3,,4\x00EXTERR=5")
	f.Add("infourl=HTTPS://x\x00infourl=https://y")
	f.Fuzz(func(t *testing.T, joined string) {
		_, exterr, infoURL := recursive.Claims(strings.Split(joined, "\x00"))
		for _, r := range exterr {
			if r.From > r.To {
				t.Errorf("range %d-%d runs backwards", r.From, r.To)
			}
		}
		if infoURL == "" {
			return
		}
		if !strings.HasPrefix(strings.ToLower(infoURL), "https://") {
			t.Errorf("link %q is not https", infoURL)
		}
		if trace.Shown(infoURL) != infoURL || strings.ContainsAny(infoURL, " \\\"<>`") {
			t.Errorf("link %q is not drawable as it stands", infoURL)
		}
	})
}
