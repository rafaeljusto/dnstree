package spf_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/spf"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// zone answers "name TYPE" from a map, the way a resolver would: a name it does
// not hold is not there. Text is written the way the codec writes TXT rdata.
type zone map[string][]string

func (z zone) lookup(asked *int) spf.Lookup {
	return func(_ context.Context, name, qtype string) *trace.Resolver {
		*asked++
		key := strings.ToLower(name) + " " + qtype
		data, ok := z[key]
		if !ok {
			if failure, ok := z[strings.ToLower(name)+" FAIL"]; ok {
				return &trace.Resolver{Rcode: failure[0]}
			}
			return &trace.Resolver{Rcode: "NXDOMAIN"}
		}
		answer := &trace.Resolver{Rcode: "NOERROR"}
		for _, d := range data {
			if qtype == "TXT" && !strings.HasPrefix(d, `"`) {
				d = fmt.Sprintf("%q", d)
			}
			answer.Records = append(answer.Records, trace.RR{Name: name, Type: qtype, Data: d})
		}
		return answer
	}
}

// chain is a policy at example.com that includes n others, each of which
// includes nothing.
func chain(n int) zone {
	z := zone{}
	record := "v=spf1"
	for i := range n {
		name := fmt.Sprintf("s%d.example.net.", i)
		record += " include:" + name
		z[name+" TXT"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
	}
	z["example.com. TXT"] = []string{record + " -all"}
	return z
}

// exchangers are n MX records.
func exchangers(n int) []string {
	var records []string
	for i := range n {
		records = append(records, fmt.Sprintf("%d mx%d.example.com.", i, i))
	}
	return records
}

func TestCheck(t *testing.T) {
	for _, tt := range []struct {
		name    string
		zone    zone
		result  trace.SPFResult
		lookups int
		void    int
		why     string
	}{{
		name:   "a policy with no lookups",
		zone:   zone{"example.com. TXT": {"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"}},
		result: trace.SPFOK,
	}, {
		name:    "ten lookups is the limit and still holds",
		zone:    chain(10),
		result:  trace.SPFOK,
		lookups: 10,
	}, {
		name:    "the eleventh lookup is a permerror, and the count goes on past it",
		zone:    chain(12),
		result:  trace.SPFPermError,
		lookups: 12,
		why:     "lookup 11, past the limit of 10",
	}, {
		name:   "no policy at the name",
		zone:   zone{"example.com. TXT": {"google-site-verification=abc"}},
		result: trace.SPFNone,
	}, {
		name:   "two policies at the name",
		zone:   zone{"example.com. TXT": {"v=spf1 -all", "v=spf1 mx -all"}},
		result: trace.SPFPermError,
		why:    "2 SPF policies",
	}, {
		name:   "an include of a name with no policy",
		zone:   zone{"example.com. TXT": {"v=spf1 include:gone.example.net -all"}},
		result: trace.SPFPermError, lookups: 1, void: 1,
		why: "gone.example.net. publishes no SPF policy",
	}, {
		name:   "a third lookup that finds nothing",
		zone:   zone{"example.com. TXT": {"v=spf1 a:x.example.com a:y.example.com mx:z.example.com -all"}},
		result: trace.SPFPermError, lookups: 3, void: 3,
		why: "lookup 3 to find nothing, past the limit of 2",
	}, {
		name: "an include loop",
		zone: zone{
			"example.com. TXT": {"v=spf1 include:example.net -all"},
			"example.net. TXT": {"v=spf1 include:EXAMPLE.com -all"},
		},
		result: trace.SPFPermError, lookups: 2,
		why: "EXAMPLE.com. is already being checked",
	}, {
		name: "a redirect is followed after the mechanisms",
		zone: zone{
			"example.com. TXT":      {"v=spf1 mx redirect=_spf.example.net"},
			"example.com. MX":       {"10 mail.example.com."},
			"_spf.example.net. TXT": {"v=spf1 a -all"},
			"_spf.example.net. A":   {"192.0.2.1"},
		},
		result: trace.SPFOK, lookups: 3,
	}, {
		name:   "a redirect beside an all is never followed",
		zone:   zone{"example.com. TXT": {"v=spf1 -all redirect=_spf.example.net"}},
		result: trace.SPFOK,
	}, {
		name:   "terms after all are never reached",
		zone:   zone{"example.com. TXT": {"v=spf1 ~all include:never.example.net"}},
		result: trace.SPFOK,
	}, {
		name:   "a macro is counted and not looked up",
		zone:   zone{"example.com. TXT": {"v=spf1 exists:%{i}._spf.example.com include:%{d}.example.net -all"}},
		result: trace.SPFOK, lookups: 2,
	}, {
		name:   "a mechanism nobody defined",
		zone:   zone{"example.com. TXT": {"v=spf1 mx include:x.example.net ipv4:192.0.2.1 -all"}},
		result: trace.SPFPermError,
		why:    "ipv4 is no mechanism",
	}, {
		name:   "an address of the wrong family",
		zone:   zone{"example.com. TXT": {"v=spf1 ip4:2001:db8::1 -all"}},
		result: trace.SPFPermError,
		why:    "is no IPv4 address",
	}, {
		name:   "a failed lookup is a temperror",
		zone:   zone{"example.com. TXT": {"v=spf1 include:broken.example.net -all"}, "broken.example.net. FAIL": {"SERVFAIL"}},
		result: trace.SPFTempError, lookups: 1,
		why: "SERVFAIL",
	}, {
		name:   "the policy's own lookup failing",
		zone:   zone{"example.com. FAIL": {"SERVFAIL"}},
		result: trace.SPFTempError,
	}, {
		name: "more than ten mail servers",
		zone: zone{
			"example.com. TXT": {"v=spf1 mx -all"},
			"example.com. MX":  exchangers(11),
		},
		result: trace.SPFPermError, lookups: 1,
		why: "11 mail servers, past the limit of 10",
	}, {
		name: "strings of a record are joined with nothing between",
		zone: zone{
			"example.com. TXT":      {`"v=spf1 include:_spf.exa" "mple.net -all"`},
			"_spf.example.net. TXT": {`"v=spf1 ip4:192.0.2.1 \"-all"`},
		},
		result: trace.SPFPermError, lookups: 1,
		why: `"-all is no mechanism`,
	}, {
		name:   "a decimal escape is the byte it names",
		zone:   zone{"example.com. TXT": {`"v=spf1\032-all"`}},
		result: trace.SPFOK,
	}, {
		name:   "a decimal escape past 255 is no byte, and quotes only its first digit",
		zone:   zone{"example.com. TXT": {`"v=spf1 \999-all"`}},
		result: trace.SPFPermError,
		why:    "999-all is no mechanism",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			var asked int
			got := spf.Check(t.Context(), "example.com", tt.zone.lookup(&asked), 64)
			if got.Result != tt.result {
				t.Errorf("result %q (%s), want %q", got.Result, got.Why, tt.result)
			}
			if got.Lookups != tt.lookups || got.Void != tt.void {
				t.Errorf("%d lookups and %d void, want %d and %d", got.Lookups, got.Void, tt.lookups, tt.void)
			}
			if !strings.Contains(got.Why, tt.why) {
				t.Errorf("why %q, want it to say %q", got.Why, tt.why)
			}
		})
	}
}

// TestTerms covers what each term says of itself: the running count, the
// policy an include found, and the terms no check reaches.
func TestTerms(t *testing.T) {
	z := zone{
		"example.com. TXT":        {"v=spf1 include:_spf.example.net ptr exists:%{i}.x.example.com +all mx"},
		"_spf.example.net. TXT":   {"v=spf1 include:_inner.example.net ?all"},
		"_inner.example.net. TXT": {"v=spf1 ip4:192.0.2.0/24 -all"},
	}
	var asked int
	got := spf.Check(t.Context(), "example.com.", z.lookup(&asked), 64)

	if got.Record != "v=spf1 include:_spf.example.net ptr exists:%{i}.x.example.com +all mx" {
		t.Errorf("record %q", got.Record)
	}
	if len(got.Terms) != 5 {
		t.Fatalf("%d terms, want 5", len(got.Terms))
	}
	include, ptr, exists, all, mx := got.Terms[0], got.Terms[1], got.Terms[2], got.Terms[3], got.Terms[4]

	if include.Lookup != 1 || include.Target != "_spf.example.net." || len(include.Terms) != 2 {
		t.Errorf("include: %+v", include)
	}
	if inner := include.Terms[0]; inner.Lookup != 2 || inner.Record != "v=spf1 ip4:192.0.2.0/24 -all" {
		t.Errorf("the include inside it: %+v", inner)
	}
	if neutral := include.Terms[1]; neutral.Problem != "" {
		t.Errorf("?all inside an include is only a mismatch, and was flagged: %q", neutral.Problem)
	}
	if ptr.Lookup != 3 || !ptr.Sender || !strings.Contains(ptr.Problem, "RFC 7208 5.5") || ptr.Fatal {
		t.Errorf("ptr: %+v", ptr)
	}
	if exists.Lookup != 4 || !exists.Sender || exists.Target != "%{i}.x.example.com" {
		t.Errorf("exists: %+v", exists)
	}
	if !strings.Contains(all.Problem, "anyone") || all.Fatal {
		t.Errorf("+all: %+v", all)
	}
	if !mx.Unreached || mx.Lookup != 0 {
		t.Errorf("mx after all: %+v", mx)
	}
	if got.Lookups != 4 || got.Result != trace.SPFOK {
		t.Errorf("%d lookups, %q; want 4, ok", got.Lookups, got.Result)
	}
	if asked != 3 {
		t.Errorf("%d queries, want 3: the macros and ptr are not asked", asked)
	}
}

// TestBudget covers a policy bigger than the queries it is allowed: it stops,
// and says it could not decide rather than calling what it saw the whole. An
// error it did see still stands: twelve includes in one record are past the
// limit whatever they hold.
func TestBudget(t *testing.T) {
	var asked int
	got := spf.Check(t.Context(), "example.com", chain(5).lookup(&asked), 3)
	if asked != 3 {
		t.Errorf("%d queries, want 3", asked)
	}
	if !got.Cut || got.Result != trace.SPFUndecided || !strings.Contains(got.Why, "--max-queries") {
		t.Errorf("cut %v, %q (%s); want cut and undecided", got.Cut, got.Result, got.Why)
	}

	got = spf.Check(t.Context(), "example.com", chain(12).lookup(&asked), 3)
	if got.Result != trace.SPFPermError {
		t.Errorf("%q (%s), want the permerror it could see", got.Result, got.Why)
	}
}

// TestLongPolicy covers a policy of tens of thousands of terms, which a 64 KB
// TXT answer holds and each include can fetch again: it is not read into
// terms, whether at the name or behind an include, and the check says why.
func TestLongPolicy(t *testing.T) {
	filler := strings.Repeat(" a", 32000)
	tests := map[string]struct {
		zone zone
		cut  string
	}{
		"at the name": {
			zone: zone{"example.com. TXT": {"v=spf1 -all" + filler}},
			cut:  "example.com.",
		},
		"behind an include": {
			zone: zone{
				"example.com. TXT":     {"v=spf1 include:big.example.net -all"},
				"big.example.net. TXT": {"v=spf1 -all" + filler},
			},
			cut: "big.example.net.",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var asked int
			got := spf.Check(t.Context(), "example.com", tt.zone.lookup(&asked), 64)
			if got.Result != trace.SPFUndecided || !strings.Contains(got.Why, tt.cut+" publishes a policy of 32001 terms") {
				t.Errorf("%q (%s), want undecided over %s", got.Result, got.Why, tt.cut)
			}
			var terms int
			for _, term := range got.Terms {
				terms += 1 + len(term.Terms)
			}
			if terms > 2 {
				t.Errorf("%d terms read, want the long policy left unread", terms)
			}
		})
	}
}

// TestNoResolver covers a lookup that cannot be made at all.
func TestNoResolver(t *testing.T) {
	got := spf.Check(t.Context(), "example.com", func(context.Context, string, string) *trace.Resolver { return nil }, 64)
	if got.Result != trace.SPFTempError {
		t.Errorf("%q (%s), want a temperror", got.Result, got.Why)
	}
}

// TestKinds covers what each term is, read once here so that nothing drawing
// the policy has to read its text again.
func TestKinds(t *testing.T) {
	z := zone{"example.com. TXT": {"v=spf1 IP4:192.0.2.1 -ip6:2001:db8::1 ~MX/24 a:x.example.com//64 exp=why.example.com foo=bar ?all"}}
	var asked int
	got := spf.Check(t.Context(), "example.com", z.lookup(&asked), 64)
	var kinds []string
	for _, term := range got.Terms {
		kinds = append(kinds, term.Kind)
	}
	if want := "ip4 ip6 mx a exp foo all"; strings.Join(kinds, " ") != want {
		t.Errorf("kinds %q, want %q", kinds, want)
	}
}
