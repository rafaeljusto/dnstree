package tree_test

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// draw renders a trace with colour off, which is what every assertion here is
// about: the words, not the escapes around them.
func draw(t *testing.T, tr *trace.Trace) string {
	t.Helper()

	var out bytes.Buffer
	if err := tree.Render(&out, tr, tree.Options{Color: tree.ColorNever}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out.String()
}

// oneHop is a walk that ends on a single hop into test., with whatever the test
// put on it.
func oneHop(step *trace.Step) *trace.Trace {
	step.Zone = "test."
	step.Server = trace.Server{Name: "ns.test.", IP: netip.MustParseAddr("192.0.2.5"), Port: 53}
	return &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{step}},
	}
}

func TestRenderFiltered(t *testing.T) {
	out := draw(t, oneHop(&trace.Step{
		Kind:  trace.KindFiltered,
		Rcode: "REFUSED",
		Extended: []trace.ExtendedError{
			{Code: 18, Reason: "Prohibited", Text: "not from here"},
		},
	}))

	for _, want := range []string{"filtered", "ede Prohibited (18): not from here", "REFUSED"} {
		if !strings.Contains(out, want) {
			t.Errorf("got %q, want it to carry %q", out, want)
		}
	}
	// Lame is the finding this one exists to stop being mistaken for.
	if strings.Contains(out, "lame") {
		t.Errorf("got %q, want nothing calling the server lame", out)
	}
}

// TestRenderExtendedOnAnAnswer covers a server explaining an answer it gave.
// The code belongs on the hop whether or not it changed how the hop is read.
func TestRenderExtendedOnAnAnswer(t *testing.T) {
	out := draw(t, oneHop(&trace.Step{
		Kind:     trace.KindAnswer,
		Rcode:    "NOERROR",
		Extended: []trace.ExtendedError{{Code: 3, Reason: "Stale Answer"}},
		Records:  []trace.RR{{Name: "www.test.", TTL: 300, Type: "A", Data: "192.0.2.10"}},
	}))

	if !strings.Contains(out, "ede Stale Answer (3)") {
		t.Errorf("got %q, want the extended error on the hop", out)
	}
}

func TestRenderSubnetScope(t *testing.T) {
	out := draw(t, oneHop(&trace.Step{
		Kind:   trace.KindAnswer,
		Rcode:  "NOERROR",
		Subnet: &trace.Subnet{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Scope: 24},
	}))

	if !strings.Contains(out, "ecs scope /24") {
		t.Errorf("got %q, want the scope the server used", out)
	}
}

// TestRenderSubnetIgnoredScope covers the server that took the subnet and did
// nothing with it. A zero scope is not nothing: it is the server saying this
// answer is the same wherever it was asked from.
func TestRenderSubnetIgnoredScope(t *testing.T) {
	out := draw(t, oneHop(&trace.Step{
		Kind:   trace.KindAnswer,
		Rcode:  "NOERROR",
		Subnet: &trace.Subnet{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Scope: 0},
	}))

	if !strings.Contains(out, "ecs scope /0") {
		t.Errorf("got %q, want a scope of zero said out loud", out)
	}
}

func TestRenderECH(t *testing.T) {
	out := draw(t, oneHop(&trace.Step{
		Kind:  trace.KindAnswer,
		Rcode: "NOERROR",
		Records: []trace.RR{{
			Name: "svc.test.", TTL: 300, Type: "HTTPS",
			Data:    `1 . alpn="h2,h3" ech="AEX+DQBBAAA="`,
			Service: &trace.Service{Priority: 1, ALPN: []string{"h2", "h3"}, ECH: true},
		}},
	}))

	if !strings.Contains(out, "[ech]") {
		t.Errorf("got %q, want the ECH configuration called out", out)
	}
}

func TestRenderWithoutECH(t *testing.T) {
	out := draw(t, oneHop(&trace.Step{
		Kind:  trace.KindAnswer,
		Rcode: "NOERROR",
		Records: []trace.RR{{
			Name: "bare.test.", TTL: 300, Type: "HTTPS",
			Data:    `1 . alpn="h2"`,
			Service: &trace.Service{Priority: 1, ALPN: []string{"h2"}},
		}},
	}))

	if strings.Contains(out, "[ech]") {
		t.Errorf("got %q, want nothing said: this record publishes none", out)
	}
}

// differing is a walk and a resolver that do not agree about the same name.
func differing(ours, theirs []string, rcode string) *trace.Trace {
	records := func(data []string) []trace.RR {
		var records []trace.RR
		for _, one := range data {
			records = append(records, trace.RR{Name: "www.test.", TTL: 300, Type: "A", Data: one})
		}
		return records
	}

	tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR", Records: records(ours)})
	tr.Resolvers = []*trace.Resolver{{
		Server:  trace.Server{IP: netip.MustParseAddr("192.168.1.1"), Port: 53},
		Rcode:   rcode,
		Records: records(theirs),
		Match:   trace.MatchDiffers,
	}}
	return tr
}

func TestRenderDifference(t *testing.T) {
	out := draw(t, differing([]string{"192.0.2.10"}, []string{"10.0.0.1"}, "NOERROR"))

	for _, want := range []string{"192.168.1.1 answers 10.0.0.1", "the walk found 192.0.2.10"} {
		if !strings.Contains(out, want) {
			t.Errorf("got %q, want it to carry %q", out, want)
		}
	}
}

// TestRenderDifferentRcode covers the difference worth the most: a name that is
// there for one of them and not for the other.
func TestRenderDifferentRcode(t *testing.T) {
	out := draw(t, differing([]string{"192.0.2.10"}, nil, "NXDOMAIN"))

	if !strings.Contains(out, "answers NXDOMAIN where the walk found NOERROR") {
		t.Errorf("got %q, want the two rcodes set against each other", out)
	}
}

// TestRenderAgreementIsQuiet covers the ordinary case. Agreement is what the
// reader expects, and a line saying so would be a line in the way.
func TestRenderAgreementIsQuiet(t *testing.T) {
	tr := differing([]string{"192.0.2.10"}, []string{"192.0.2.10"}, "NOERROR")
	tr.Resolvers[0].Match = trace.MatchSame

	if out := draw(t, tr); strings.Contains(out, "answers") {
		t.Errorf("got %q, want nothing said about a resolver that agrees", out)
	}
}

func TestRenderKept(t *testing.T) {
	for _, tt := range []struct {
		name string
		tr   func() *trace.Trace
		want string
	}{{
		name: "a resolver keeping the walk's answer past the zone's TTL",
		tr: func() *trace.Trace {
			tr := differing([]string{"192.0.2.10"}, []string{"192.0.2.10"}, "NOERROR")
			tr.Resolvers[0].Match, tr.Resolvers[0].Kept = trace.MatchSame, trace.KeptLonger
			tr.Resolvers[0].Records[0].TTL = 3600
			return tr
		},
		want: "ttl: 192.168.1.1 keeps this with ttl 3600, the zone gives 300",
	}, {
		name: "a resolver serving what looks like a stale answer",
		tr: func() *trace.Trace {
			tr := differing([]string{"192.0.2.10"}, []string{"10.0.0.1"}, "NOERROR")
			tr.Resolvers[0].Kept = trace.KeptStale
			tr.Resolvers[0].Records[0].TTL = 30
			return tr
		},
		want: "ttl: 192.168.1.1 looks stale: no server of the zone gave its answer, and ttl 30 is what serve-stale hands out",
	}, {
		name: "a resolver whose TTL said nothing",
		tr: func() *trace.Trace {
			return differing([]string{"192.0.2.10"}, []string{"10.0.0.1"}, "NOERROR")
		},
	}} {
		t.Run(tt.name, func(t *testing.T) {
			out := draw(t, tt.tr())
			if tt.want == "" {
				if strings.Contains(out, "ttl:") {
					t.Errorf("got %q, want nothing said about the TTL", out)
				}
				return
			}
			if !strings.Contains(out, tt.want) {
				t.Errorf("got %q, want it to carry %q", out, tt.want)
			}
		})
	}
}

func TestRenderFailures(t *testing.T) {
	// failing is the walk with the resolver's SERVFAIL read as failed, its
	// chain of trust in state where state is not empty.
	failing := func(failed trace.Failure, state trace.DNSSECState, again string, ede ...trace.ExtendedError) *trace.Trace {
		tr := differing([]string{"192.0.2.10"}, nil, "SERVFAIL")
		tr.Resolvers[0].Match, tr.Resolvers[0].Failed, tr.Resolvers[0].Extended = "", failed, ede
		tr.Resolvers[0].Unchecked = &trace.Resolver{Rcode: again}
		if state != "" {
			tr.Root.Children[0].DNSSEC = &trace.DNSSECStatus{State: state}
		}
		return tr
	}
	expired := trace.ExtendedError{Code: 7, Reason: "Signature Expired", Text: "test./dnskey"}

	for _, tt := range []struct {
		name string
		tr   *trace.Trace
		want string
	}{{
		name: "validation fails at the resolver on a chain the walk found secure",
		tr:   failing(trace.FailedValidation, trace.Secure, "NOERROR", expired),
		want: "servfail: 192.168.1.1 answers SERVFAIL where the walk found 192.0.2.10: " +
			"with checking disabled it answers, so it fails validation; " +
			"the walk found the chain secure, so look at its clock and trust anchor " +
			"(it says: Signature Expired (7): test./dnskey)",
	}, {
		name: "validation fails at a resolver that ignores checking disabled",
		tr:   failing(trace.FailedValidation, trace.Secure, "SERVFAIL", expired),
		want: "it says it fails validation, and ignores checking disabled",
	}, {
		name: "validation fails where the walk did not check the chain",
		tr:   failing(trace.FailedValidation, "", "NOERROR"),
		want: "so it fails validation; --dnssec checks the chain the walk took",
	}, {
		name: "validation fails on a chain the walk found broken too",
		tr:   failing(trace.FailedBogus, trace.Bogus, "NOERROR"),
		want: "it fails validation as the walk does, so the zone's chain of trust is what to fix",
	}, {
		name: "a failure the resolver cached",
		tr:   failing(trace.FailedCached, "", "SERVFAIL", trace.ExtendedError{Code: 13, Reason: "Cached Error"}),
		want: "it says it is serving a failure it cached",
	}, {
		name: "a resolver that cannot get an answer",
		tr:   failing(trace.FailedUnreachable, "", "SERVFAIL"),
		want: "it fails with checking disabled too, so it could not get an answer the walk got",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			if out := draw(t, tt.tr); !strings.Contains(out, tt.want) {
				t.Errorf("got %q, want it to carry %q", out, tt.want)
			}
		})
	}
}

// TestRenderFailureUnread covers a SERVFAIL nothing read, such as one in a
// walk saved before the resolver was asked again: the summary's rcode says
// all there is.
func TestRenderFailureUnread(t *testing.T) {
	tr := differing([]string{"192.0.2.10"}, nil, "SERVFAIL")
	tr.Resolvers[0].Match = ""

	if out := draw(t, tr); strings.Contains(out, "servfail:") {
		t.Errorf("got %q, want nothing said of a failure nothing read", out)
	}
}

// TestRenderDifferenceIsShortened covers a round robin big enough to push the
// tree off the screen. The first few and a count say everything the reader
// needs; the rest is in --format json.
func TestRenderDifferenceIsShortened(t *testing.T) {
	theirs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	out := draw(t, differing([]string{"192.0.2.10"}, theirs, "NOERROR"))

	if !strings.Contains(out, "(and 2 more)") {
		t.Errorf("got %q, want the tail counted rather than listed", out)
	}
	if strings.Contains(out, "10.0.0.5") {
		t.Errorf("got %q, want the tail left out", out)
	}
}

func TestSummaryFiltered(t *testing.T) {
	tr := oneHop(&trace.Step{Kind: trace.KindFiltered, Rcode: "REFUSED"})

	var out bytes.Buffer
	tree.Summary(&out, tr, tree.Options{Color: tree.ColorNever})

	// Turned away is not the same as nobody answering, and the line that a
	// reader skims has to say which it was.
	if !strings.Contains(out.String(), "filtered") {
		t.Errorf("got %q, want the walk called filtered", out.String())
	}
	if strings.Contains(out.String(), "no answer") {
		t.Errorf("got %q, want more than 'no answer'", out.String())
	}
}

func TestSummaryResolverDiffers(t *testing.T) {
	tr := differing([]string{"192.0.2.10"}, []string{"10.0.0.1"}, "NOERROR")

	var out bytes.Buffer
	tree.Summary(&out, tr, tree.Options{Color: tree.ColorNever})

	if !strings.Contains(out.String(), "(differs)") {
		t.Errorf("got %q, want the summary to say the two disagree", out.String())
	}
}

// TestASCIIStaysASCII guards the promise --format ascii makes: output that can
// be pasted anywhere. The new fields are drawn in the same charset as the rest.
func TestASCIIStaysASCII(t *testing.T) {
	tr := differing([]string{"192.0.2.10"}, []string{"10.0.0.1"}, "NOERROR")
	tr.Root.Children[0].Kind = trace.KindFiltered
	// The server's own words, as hostile as they come.
	tr.Root.Children[0].Extended = []trace.ExtendedError{{Code: 15, Reason: "Blocked",
		Text: "café\x1b[2K\r\n`-- ns.evil. [secure]"}}
	tr.Root.Children[0].Subnet = &trace.Subnet{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Scope: 24}
	tr.Root.Children[0].NSID = "fra2"
	tr.Root.Children[0].Cookie = trace.CookieMismatch
	// Names, which the codec does not escape the way it escapes text rdata.
	const forged = "x\x1b[1A\x1b[2K\r\n`-- ns.evil. [secure]\x1b[8m.example."
	tr.Root.Children[0].Server.Name = forged
	tr.Root.Children[0].Records = append(tr.Root.Children[0].Records,
		trace.RR{Name: forged, TTL: 60, Type: "CNAME", Data: forged})
	tr.Root.Children = append(tr.Root.Children, &trace.Step{Zone: forged, Kind: trace.KindReferral,
		Server: trace.Server{Name: forged}, Delegation: &trace.Delegation{Zone: forged, NS: []string{forged}}})
	tr.Warnings = append(tr.Warnings, "example. delegates to "+forged+" inside the zone, with no glue to reach them")
	tr.Resolvers = append(tr.Resolvers, &trace.Resolver{Rcode: "SERVFAIL", Failed: trace.FailedValidation,
		Unchecked: &trace.Resolver{Rcode: "NOERROR"},
		Extended:  []trace.ExtendedError{{Code: 7, Text: "café\x1b[2K\r\n`-- ns.evil. [secure]"}}})

	var out bytes.Buffer
	if err := tree.Render(&out, tr, tree.Options{Charset: tree.ASCII, Color: tree.ColorNever}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	tree.Summary(&out, tr, tree.Options{Charset: tree.ASCII, Color: tree.ColorNever})

	for i, r := range out.String() {
		if r > 127 || (r < ' ' && r != '\n') {
			t.Fatalf("got %q at %d, want printable ASCII throughout: %q", r, i, out.String())
		}
	}
	if strings.Contains(out.String(), "\n`-- ns.evil.") {
		t.Errorf("got a line the server wrote: %q", out.String())
	}
}

// TestRenderExpiring covers a chain that holds and is about to stop holding. The
// time left is read against when the walk was made, never against the clock,
// so the same trace always draws the same way.
func TestRenderExpiring(t *testing.T) {
	made := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	month := 30 * 24 * time.Hour
	tests := map[string]struct {
		life, left time.Duration
		want       string
	}{
		"two days left of a month is said": {
			life: month, left: 51 * time.Hour, want: "[secure ECDSAP256SHA256, expires in 2d3h]"},
		"a few hours left is said": {
			life: month, left: 5*time.Hour + 20*time.Minute, want: "expires in 5h"},
		"a fortnight left of a month is nothing": {
			life: month, left: 14 * 24 * time.Hour, want: "[secure ECDSAP256SHA256]"},
		"a day left of a day's signature is nothing": {
			life: 25 * time.Hour, left: 23 * time.Hour, want: "[secure ECDSAP256SHA256]"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{
				Kind:  trace.KindAnswer,
				Rcode: "NOERROR",
				DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Algorithm: "ECDSAP256SHA256",
					Signatures: []trace.Lifetime{{Inception: made.Add(test.left - test.life), Expiration: made.Add(test.left)}}},
			})
			tr.Started = made
			if out := draw(t, tr); !strings.Contains(out, test.want) {
				t.Errorf("got %q, want it to carry %q", out, test.want)
			}
		})
	}
}

// TestRenderMinimised covers a hop that asked for less of the name than the
// question: it says in its margin what it asked instead.
func TestRenderMinimised(t *testing.T) {
	out := draw(t, oneHop(&trace.Step{
		Kind:      trace.KindNoData,
		Rcode:     "NOERROR",
		Minimised: true,
		Asked:     trace.Question{Name: "test.", Type: "A"},
		Notes:     []string{"minimised to test."},
	}))
	if !strings.Contains(out, "(minimised to test.)") {
		t.Errorf("got %q, want it to say what it asked", out)
	}
}

// TestRenderReport covers where a zone asks failures to be reported, drawn on
// the hop that said so, and what came of reporting one.
func TestRenderReport(t *testing.T) {
	tests := map[string]struct {
		report *trace.Report
		want   string
	}{
		"nothing sent": {want: "report → agent.example."},
		"a report that arrived": {
			report: &trace.Report{Agent: "agent.example.", Code: 6, Name: "_er.1.www.test.6._er.agent.example.", Rcode: "NOERROR"},
			want:   "report: told agent.example. the chain of trust is bogus, as _er.1.www.test.6._er.agent.example. (NOERROR)"},
		"a report that was not sent": {
			report: &trace.Report{Agent: "agent.test.", Code: 6, Err: "the agent is at or below the name it would be told about, which RFC 9567 rules out"},
			want:   "report: not sent to agent.test.: the agent is at or below the name it would be told about, which RFC 9567 rules out"},
		"a report that did not get through": {
			report: &trace.Report{Agent: "agent.example.", Code: 6, Name: "_er.1.www.test.6._er.agent.example.", Err: "i/o timeout"},
			want:   "report: agent.example. was not reached: i/o timeout"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR", ReportTo: "agent.example."})
			tr.Report = test.report
			if out := draw(t, tr); !strings.Contains(out, test.want) {
				t.Errorf("got %q, want %q", out, test.want)
			}
		})
	}
}

// TestRenderSignal covers what a zone asks its parent to publish, beside the
// verdict of the cut its DS belongs to.
func TestRenderSignal(t *testing.T) {
	tests := map[string]struct {
		signal trace.Signal
		want   string
	}{
		"a zone that asks for nothing": {
			signal: trace.Signal{State: trace.SignalNone}, want: "no cds"},
		"a zone that asks for what the parent holds": {
			signal: trace.Signal{State: trace.SignalMatch, Requested: []uint16{7}, Held: []uint16{7}},
			want:   "cds matches the ds"},
		"a rollover waiting on the parent": {
			signal: trace.Signal{State: trace.SignalPending, Requested: []uint16{7, 9}, Held: []uint16{7}},
			want:   "cds asks for keys 7 and 9, the ds is for key 7"},
		"a zone asking to be made insecure": {
			signal: trace.Signal{State: trace.SignalDelete}, want: "cds asks for no ds"},
		"a request that could not be read": {
			signal: trace.Signal{State: trace.SignalUnchecked}, want: "cds unchecked"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out := draw(t, oneHop(&trace.Step{
				Kind:   trace.KindReferral,
				Rcode:  "NOERROR",
				DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Signal: &test.signal},
			}))
			if !strings.Contains(out, test.want) {
				t.Errorf("got %q, want it to carry %q", out, test.want)
			}
		})
	}
}

func TestRenderDangling(t *testing.T) {
	tests := map[string]struct {
		kind     trace.StepKind
		dangling *trace.Dangling
		want     string
	}{
		"a nameserver names what is missing": {
			kind: trace.KindNXDomain,
			dangling: &trace.Dangling{Kind: trace.DanglingNameserver,
				Name: "example.org.", Target: "ns1.gone.com.", Missing: "gone.com.", Zone: "com."},
			want: "dangling nameserver: gone.com. is missing",
		},
		"an alias names what is missing": {
			kind: trace.KindNXDomain,
			dangling: &trace.Dangling{Kind: trace.DanglingAlias,
				Name: "shop.test.", Target: "x.cloud.test.", Missing: "x.cloud.test.", Zone: "cloud.test."},
			want: "dangling alias: x.cloud.test. is missing",
		},
		"a zone every nameserver refused": {
			kind:     trace.KindReferral,
			dangling: &trace.Dangling{Kind: trace.DanglingLame, Name: "example.org."},
			want:     "dangling: every nameserver lame",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := draw(t, oneHop(&trace.Step{Kind: test.kind, Dangling: test.dangling}))
			if !strings.Contains(got, test.want) {
				t.Errorf("got\n%s\nwant the hop marked %q", got, test.want)
			}
		})
	}
}

func TestRenderCAA(t *testing.T) {
	letsEncrypt := &trace.Issuers{CAs: []string{"letsencrypt.org"}}
	for name, tt := range map[string]struct {
		caa  *trace.CAA
		want []string
	}{
		"a set above the name, with a report address": {
			caa: &trace.CAA{
				Asked: []trace.CAALookup{{Name: "www.test.", Found: trace.CAANone}, {Name: "test.", Found: trace.CAASet}},
				Owner: "test.",
				Records: []trace.CAARecord{
					{Tag: "issue", Value: "letsencrypt.org", Known: true},
					{Tag: "issuewild", Value: ";", Known: true},
					{Tag: "iodef", Value: "mailto:security@test", Known: true},
				},
				Issue: letsEncrypt, Wildcard: &trace.Issuers{CAs: []string{}},
				DNSSEC: &trace.DNSSECStatus{State: trace.Secure},
			},
			want: []string{
				"caa: none at www.test.; test. decides it [secure]",
				"caa: may issue: letsencrypt.org; wildcards: nobody; reports to mailto:security@test",
			},
		},
		"an alias whose target holds the set": {
			caa: &trace.CAA{
				Asked: []trace.CAALookup{{Name: "www.test.", Found: trace.CAASet, Alias: "cdn.test."}},
				Owner: "www.test.", Issue: letsEncrypt, Wildcard: letsEncrypt,
			},
			want: []string{"caa: www.test. decides it, as an alias for cdn.test.", "caa: may issue: letsencrypt.org; wildcards: letsencrypt.org"},
		},
		"a set with no issue property": {
			caa: &trace.CAA{
				Asked: []trace.CAALookup{{Name: "www.test.", Found: trace.CAASet}}, Owner: "www.test.",
			},
			want: []string{"caa: www.test. decides it", "caa: may issue: any authority; wildcards: any authority"},
		},
		"no set anywhere": {
			caa:  &trace.CAA{Asked: []trace.CAALookup{{Name: "www.test.", Found: trace.CAANone}, {Name: "test.", Found: trace.CAANone}}},
			want: []string{"caa: none from www.test. up, so any authority may issue"},
		},
		"a lookup that failed": {
			caa: &trace.CAA{
				Asked:   []trace.CAALookup{{Name: "www.test.", Found: trace.CAAFailed, Err: "SERVFAIL"}},
				Refused: "the CAA lookup at www.test. failed: SERVFAIL",
			},
			want: []string{"caa: every authority refuses: the CAA lookup at www.test. failed: SERVFAIL"},
		},
		"a lookup that failed where an authority may still issue": {
			caa: &trace.CAA{
				Asked:     []trace.CAALookup{{Name: "www.test.", Found: trace.CAAFailed, Err: "SERVFAIL"}},
				Undecided: "the CAA lookup at www.test. failed: SERVFAIL",
			},
			want: []string{"caa: an authority may refuse: the CAA lookup at www.test. failed: SERVFAIL"},
		},
		"a climb read from a file with nothing in it": {
			caa: &trace.CAA{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.CAA = tt.caa
			out := draw(t, tr)
			var got []string
			for line := range strings.Lines(out) {
				if strings.HasPrefix(line, "caa: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderSPF(t *testing.T) {
	for name, tt := range map[string]struct {
		spf  *trace.SPF
		want []string
	}{
		"a policy past the limit": {
			spf: &trace.SPF{Name: "test.", Record: "v=spf1 include:a.test -all", Lookups: 11,
				Terms:  []trace.SPFTerm{{Term: "include:a.test", Kind: "include", Lookup: 11, Problem: "lookup 11, past the limit of 10", Fatal: true}, {Term: "-all", Kind: "all"}},
				Result: trace.SPFPermError, Why: "include:a.test: lookup 11, past the limit of 10"},
			want: []string{
				"spf: test. takes 11 of 10 lookups",
				"spf: permerror: include:a.test: lookup 11, past the limit of 10",
			},
		},
		"a policy at the limit": {
			spf:  &trace.SPF{Name: "test.", Record: "v=spf1 -all", Lookups: 10, Terms: []trace.SPFTerm{{Term: "-all", Kind: "all"}}, Result: trace.SPFOK},
			want: []string{"spf: test. takes 10 of 10 lookups", "spf: ok, at the limit: one more lookup in any policy it includes is a permerror"},
		},
		"no policy": {
			spf:  &trace.SPF{Name: "test.", Result: trace.SPFNone, Why: "test. publishes no SPF policy"},
			want: []string{"spf: none: test. publishes no SPF policy"},
		},
		"a budget that ran out": {
			spf: &trace.SPF{Name: "test.", Record: "v=spf1 a mx -all", Lookups: 2, Void: 1, Cut: true,
				Terms:  []trace.SPFTerm{{Term: "a", Kind: "a", Lookup: 1, Void: true}, {Term: "mx", Kind: "mx", Lookup: 2}, {Term: "-all", Kind: "all"}},
				Result: trace.SPFUndecided, Why: "the budget of 64 queries ran out"},
			want: []string{
				"spf: test. takes at least 2 of 10 lookups, at least 1 of 2 finding nothing",
				"spf: undecided: the budget of 64 queries ran out",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.SPF = tt.spf
			out := draw(t, tr)
			var got []string
			for line := range strings.Lines(out) {
				if strings.HasPrefix(line, "spf: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderRegistration(t *testing.T) {
	started := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	registered := func(expires time.Time, status ...string) *trace.Registration {
		return &trace.Registration{Domain: "example.test.", State: trace.Registered, Expires: expires, Status: status,
			NS: []string{"ns1.example.net."}, Parent: "test."}
	}
	for name, tt := range map[string]struct {
		reg  *trace.Registration
		want []string
	}{
		"a registration with time to run": {
			reg: registered(started.Add(400*24*time.Hour), "active"),
			want: []string{
				"rdap: example.test. is registered until 2027-11-10, with 400 days left",
				"rdap: status: active",
				"rdap: nameservers match what test. hands out",
			},
		},
		"a registration about to run out": {
			reg:  registered(started.Add(12*24*time.Hour + 5*time.Hour)),
			want: []string{"rdap: example.test. runs out in 12 days, on 2026-10-18: renew it", "rdap: nameservers match what test. hands out"},
		},
		"a registration that has run out": {
			reg: registered(started.Add(-3*24*time.Hour), "redemption period"),
			want: []string{
				"rdap: example.test. expired 3 days ago, on 2026-10-03: renew it before the registry lets it go",
				"rdap: example.test. is in its redemption period: it lapsed, and only the registrar can still restore it",
				"rdap: nameservers match what test. hands out",
			},
		},
		"a registration that disagrees with the zone above": {
			reg: &trace.Registration{Domain: "example.test.", State: trace.Registered, Parent: "test.", Signed: true,
				NSOnlyParent: []string{"ns.old.net."}, DSChecked: true, DSOnlyRegistry: []uint16{7}},
			want: []string{
				"rdap: example.test. is registered; the registry does not say until when",
				"rdap: nameservers: only test. hands out ns.old.net.",
				"rdap: DS: only the registry holds key 7",
				"rdap: a change is stuck between the registry and the zone, or the registry's copy is stale",
			},
		},
		"a signed registration under an unsigned delegation": {
			reg: &trace.Registration{Domain: "example.test.", State: trace.Registered, Parent: "test.", Signed: true,
				DSChecked: true, DSDiffer: true},
			want: []string{
				"rdap: example.test. is registered; the registry does not say until when",
				"rdap: DS: the registry holds DS and test. hands out none",
				"rdap: a change is stuck between the registry and the zone, or the registry's copy is stale",
			},
		},
		"a domain nobody registered": {
			reg:  &trace.Registration{Domain: "example.test.", State: trace.Unregistered, Why: "the registry holds no registration for example.test."},
			want: []string{"rdap: the registry holds no registration for example.test."},
		},
		"a registry that did not answer": {
			reg:  &trace.Registration{Domain: "example.test.", State: trace.Unreached, Why: "the registry did not answer in time"},
			want: []string{"rdap: the registry did not answer in time"},
		},
		"a status written to move the cursor": {
			reg:  &trace.Registration{Domain: "example.test.", State: trace.Registered, Status: []string{"active\x1b[2J"}},
			want: []string{"rdap: example.test. is registered; the registry does not say until when", `rdap: status: active\027[2J`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := oneHop(&trace.Step{Kind: trace.KindAnswer, Rcode: "NOERROR"})
			tr.Started, tr.Registration = started, tt.reg
			out := draw(t, tr)
			var got []string
			for line := range strings.Lines(out) {
				if strings.HasPrefix(line, "rdap: ") {
					got = append(got, strings.TrimSuffix(line, "\n"))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
