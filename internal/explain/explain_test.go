package explain_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// noon is when the walks here that carry a clock were made.
var noon = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// lasting is a walk made at noon whose answer rests on a signature made to last
// life, with left of it to run.
func lasting(step *trace.Step, life, left time.Duration) *trace.Trace {
	expiration := noon.Add(left)
	step.DNSSEC = &trace.DNSSECStatus{State: trace.Secure, Zone: "test.",
		Signatures: []trace.Lifetime{{Inception: expiration.Add(-life), Expiration: expiration}}}
	tr := walk(step)
	tr.Started = noon
	return tr
}

// question is what every walk here set out to answer.
var question = trace.Question{Name: "www.test.", Type: "A", Class: "IN"}

// walk is a trace of that question, with the hops given hanging off the root in
// the order they were made.
func walk(steps ...*trace.Step) *trace.Trace {
	return &trace.Trace{
		Question: question,
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: steps},
	}
}

// hop is one query to a named server of test.
func hop(kind trace.StepKind, server string) *trace.Step {
	return &trace.Step{
		Zone:   "test.",
		Kind:   kind,
		Server: trace.Server{Name: server, IP: netip.MustParseAddr("192.0.2.5"), Port: 53},
	}
}

// said is every finding as one block of text, which is what a reader has in
// front of them.
func said(tr *trace.Trace) string {
	var lines []string
	for _, finding := range explain.Findings(tr) {
		lines = append(lines, finding.Text)
	}
	return strings.Join(lines, "\n")
}

func TestFindings(t *testing.T) {
	answer := func() *trace.Step {
		step := hop(trace.KindAnswer, "ns.test.")
		step.Records = []trace.RR{{Name: "www.test.", Type: "A", Data: "192.0.2.1"}}
		return step
	}

	tests := map[string]struct {
		trace *trace.Trace
		want  []string
		avoid []string
	}{
		"an answer names the records, the server and the zone it serves": {
			trace: walk(answer()),
			want:  []string{"www.test. A is 192.0.2.1", "ns.test.", "test."},
		},
		"a name that is not there names the zone that says so": {
			trace: walk(hop(trace.KindNXDomain, "ns.test.")),
			want:  []string{"www.test. does not exist", "test. is the zone that says so"},
		},
		"a type that is not there is not a name that is not there": {
			trace: walk(hop(trace.KindNoData, "ns.test.")),
			want:  []string{"exists but has no A record"},
			avoid: []string{"does not exist"},
		},
		"an alias the walk never got to the end of": {
			trace: walk(func() *trace.Step {
				step := hop(trace.KindCNAME, "ns.test.")
				step.Records = []trace.RR{{Name: "www.test.", Type: "CNAME", Data: "other.test."}}
				return step
			}()),
			want: []string{"is an alias for other.test.", "ended there without an answer"},
		},
		"an answer reached through aliases says how many": {
			trace: walk(func() *trace.Step {
				alias := hop(trace.KindCNAME, "ns.test.")
				alias.Records = []trace.RR{{Name: "www.test.", Type: "CNAME", Data: "other.test."}}
				alias.Children = []*trace.Step{answer()}
				return alias
			}()),
			want: []string{"www.test. A is 192.0.2.1", "after 1 alias"},
		},
		"an answer withheld is not a walk that found nothing": {
			trace: walk(func() *trace.Step {
				step := hop(trace.KindFiltered, "ns.test.")
				step.Rcode = "REFUSED"
				step.Extended = []trace.ExtendedError{{Code: 18, Reason: "Prohibited", Text: "not from here"}}
				return step
			}()),
			want: []string{"was withheld by ns.test.", "decided rather than served", "prohibited"},
			// The server's own words are its own, and --format ascii promises
			// the output stays under codepoint 127.
			avoid: []string{"nothing answered", "not from here"},
		},
		"a walk that ran into silence says where it stopped and who was silent": {
			trace: walk(hop(trace.KindTimeout, "ns.test.")),
			want:  []string{"nothing answered for www.test. A", "stopped at test.", "1 server did not answer in time: ns.test."},
		},
		"a server with no room left in the datagram is worth saying before it truncates": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.Size, step.Limit, step.Flags.DO = 1200, 1232, true
				return step
			}()),
			want: []string{"1 server answered with almost nothing left", "ns.test. with 1200 of 1232 bytes", "second round trip over TCP"},
			// The walk asked for signatures, so it saw what a validating
			// resolver sees and has nothing to add about it.
			avoid: []string{"asked for no signatures"},
		},
		"a walk that asked for no signatures says the room left is at most what it measured": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.Size, step.Limit = 1200, 1232
				return step
			}()),
			want: []string{"almost nothing left", "asked for no signatures: a resolver that does gets more than this"},
		},
		"an answer with room to spare is worth no sentence": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.Size, step.Limit = 700, 1232
				return step
			}()),
			avoid: []string{"bytes", "round trip"},
		},
		"a lame server is named once, not twice": {
			trace: walk(hop(trace.KindLame, "ns.test.")),
			want:  []string{"stopped at test.", "answered without authority", "ns.test."},
			avoid: []string{"authority for it"},
		},
		"more servers than anyone wants read out are counted": {
			trace: walk(
				hop(trace.KindTimeout, "a.test."), hop(trace.KindTimeout, "b.test."),
				hop(trace.KindTimeout, "c.test."), hop(trace.KindTimeout, "d.test."),
				hop(trace.KindTimeout, "e.test."),
			),
			want: []string{"5 servers did not answer in time", "a.test., b.test., c.test. and 2 more"},
		},
		"a server without cookies is named, and one with them is not": {
			trace: walk(func() *trace.Step {
				root := hop(trace.KindReferral, "a.root.")
				root.Cookie = trace.CookieSupported
				leaf := answer()
				leaf.Cookie = trace.CookieAbsent
				root.Children = []*trace.Step{leaf}
				return root
			}()),
			want:  []string{"1 server answered without a dns cookie, which is allowed", ": ns.test."},
			avoid: []string{"a.root."},
		},
		"a cookie that was not ours says the answer may not be the server's": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.Cookie = trace.CookieMismatch
				return step
			}()),
			want: []string{"client cookie other than the one sent", "may not be the server's own: ns.test."},
		},
		"a walk that sent no cookies says nothing about them": {
			trace: walk(answer()),
			avoid: []string{"cookie"},
		},
		"a budget that ran out is the reason the walk stopped": {
			trace: walk(&trace.Step{Zone: "test.", Kind: trace.KindError, Err: "the query budget of 64 ran out"}),
			want:  []string{"stopped at test.", "the query budget of 64 ran out"},
		},
		"a chain of trust that holds says how far it got": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Secure, Algorithm: "ECDSAP256SHA256"}
				return step
			}()),
			want: []string{"the chain of trust holds from the root to test.", "ECDSAP256SHA256"},
		},
		"a zone that keeps its nameservers for less than its parent says so": {
			trace: func() *trace.Trace {
				tr := walk(&trace.Step{Zone: ".", Kind: trace.KindReferral,
					Delegation: &trace.Delegation{Zone: "test.", TTL: 172800, ZoneTTL: 3600}}, answer())
				return tr
			}(),
			want: []string{"the parent hands out the nameservers of test. for 2 days and the zone gives its own for 1 hour",
				"takes up to 2 days"},
		},
		"a zone that agrees with its parent is said nothing about": {
			trace: walk(&trace.Step{Zone: ".", Kind: trace.KindReferral,
				Delegation: &trace.Delegation{Zone: "test.", TTL: 3600, ZoneTTL: 3600}}, answer()),
			avoid: []string{"the zone gives its own"},
		},
		"a signature late in its life says when it runs out": {
			trace: lasting(answer(), 30*24*time.Hour, 50*time.Hour),
			want:  []string{"a signature over test. runs out in 2 days 2 hours", "re-signed", "SERVFAIL"},
		},
		"a signature an online signer made for a day is not late in it": {
			trace: lasting(answer(), 25*time.Hour, 23*time.Hour),
			avoid: []string{"runs out"},
		},
		"a broken chain says so, and what a validating resolver will do about it": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Bogus, Reason: "the answer carries no signature"}
				return step
			}()),
			want: []string{"the chain of trust breaks at test.", "the answer carries no signature", "SERVFAIL"},
		},
		"the zone named as broken is the one the verdict is about, not the one it is drawn on": {
			trace: walk(&trace.Step{
				Zone: "org.", Kind: trace.KindReferral,
				Server:     trace.Server{Name: "a0.org.afilias-nst.info."},
				Delegation: &trace.Delegation{Zone: "dnssec-failed.org."},
				DNSSEC: &trace.DNSSECStatus{
					State: trace.Bogus, Zone: "dnssec-failed.org.",
					Reason: "no DNSKEY of the zone matches the DS its parent published",
				},
			}),
			want:  []string{"the chain of trust breaks at dnssec-failed.org."},
			avoid: []string{"breaks at org."},
		},
		"a chain nothing here could check is unchecked, never broken": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Indeterminate, Reason: "algorithm 253 is not one this build knows"}
				return step
			}()),
			want:  []string{"could not be checked", "not the same as finding it broken"},
			avoid: []string{"breaks at", "SERVFAIL"},
		},
		"a zone nobody signed says that plainly": {
			trace: walk(func() *trace.Step {
				step := answer()
				step.DNSSEC = &trace.DNSSECStatus{State: trace.Insecure, Reason: "proved that test. has no DS"}
				return step
			}()),
			want: []string{"test. is not signed", "proved that test. has no DS"},
		},
		"a walk that followed no chain says nothing about one": {
			trace: walk(answer()),
			avoid: []string{"chain of trust", "not signed"},
		},
		"a resolver that answered differently is worth a look": {
			trace: func() *trace.Trace {
				tr := walk(answer())
				tr.Resolvers = []*trace.Resolver{{Match: trace.MatchDiffers}}
				return tr
			}(),
			want: []string{"a resolver answered this question differently"},
		},
		"a resolver that agreed is worth no room": {
			trace: func() *trace.Trace {
				tr := walk(answer())
				tr.Resolvers = []*trace.Resolver{{Match: trace.MatchSame}}
				return tr
			}(),
			avoid: []string{"recursive resolver"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := said(test.trace)
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("got\n%s\nwant it to carry %q", got, want)
				}
			}
			for _, avoid := range test.avoid {
				if strings.Contains(got, avoid) {
					t.Errorf("got\n%s\nwant nothing in it saying %q", got, avoid)
				}
			}
		})
	}
}

// TestFindingsLevels covers the only thing a renderer reads besides the text.
// A chain that could not be checked must not be painted as one that broke.
func TestFindingsLevels(t *testing.T) {
	tests := map[string]struct {
		status *trace.DNSSECStatus
		want   explain.Level
	}{
		"broken is a fault":      {&trace.DNSSECStatus{State: trace.Bogus}, explain.Fault},
		"unchecked is a warning": {&trace.DNSSECStatus{State: trace.Indeterminate}, explain.Warn},
		"unsigned is a note":     {&trace.DNSSECStatus{State: trace.Insecure}, explain.Note},
		"secure is a note":       {&trace.DNSSECStatus{State: trace.Secure}, explain.Note},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			step := hop(trace.KindAnswer, "ns.test.")
			step.DNSSEC = test.status

			var found bool
			for _, finding := range explain.Findings(walk(step)) {
				if finding.Topic != explain.Trust {
					continue
				}
				found = true
				if finding.Level != test.want {
					t.Errorf("got level %d, want %d: %s", finding.Level, test.want, finding.Text)
				}
			}
			if !found {
				t.Error("got no finding about the chain of trust, want one")
			}
		})
	}
}

// TestFindingsOrder covers the reading order: what came of the walk first, and
// the workings under it.
func TestFindingsOrder(t *testing.T) {
	answer := hop(trace.KindAnswer, "ns.test.")
	answer.DNSSEC = &trace.DNSSECStatus{State: trace.Secure}

	tr := walk(&trace.Step{
		Zone: ".", Kind: trace.KindReferral,
		Server:     trace.Server{Name: "root.test.", IP: netip.MustParseAddr("192.0.2.53")},
		Delegation: &trace.Delegation{Zone: "test.", NS: []string{"ns.test."}},
		Children:   []*trace.Step{hop(trace.KindTimeout, "dead.test."), answer},
	})
	tr.Resolvers = []*trace.Resolver{{Match: trace.MatchDiffers}}

	var topics []explain.Topic
	for _, finding := range explain.Findings(tr) {
		topics = append(topics, finding.Topic)
	}

	want := []explain.Topic{explain.Outcome, explain.Trust, explain.Spread, explain.Servers, explain.Resolver}
	if len(topics) != len(want) {
		t.Fatalf("got %v, want one finding of each of %v", topics, want)
	}
	for i, topic := range topics {
		if topic != want[i] {
			t.Errorf("got %v, want %v", topics, want)
			break
		}
	}
}

// TestFindingsNothing covers the traces there is nothing to say about, which a
// renderer must be able to ask about without checking first.
func TestFindingsNothing(t *testing.T) {
	for name, tr := range map[string]*trace.Trace{
		"no trace at all":            nil,
		"a trace with no walk in it": {Question: question},
	} {
		t.Run(name, func(t *testing.T) {
			if findings := explain.Findings(tr); len(findings) != 0 {
				t.Errorf("got %v, want nothing said", findings)
			}
		})
	}
}

// ns is one nameserver address, with an origin AS where the lookups answered
// for it and none where they did not.
func ns(name, ip string, as uint32) trace.Server {
	server := trace.Server{Name: name, IP: netip.MustParseAddr(ip), Port: 53}
	if as > 0 {
		server.ASN = &trace.ASNInfo{Number: as}
	}
	return server
}

// askedAll builds a walk that was referred to test. and asked every nameserver
// it was given, which is the shape --all leaves behind: every one of them
// queried, so every one of them looked up.
func askedAll(names []string, servers ...trace.Server) *trace.Trace {
	return referred(names, true, servers...)
}

// askedFirst builds the ordinary shape: the first server answered and the rest
// were listed and never asked, so nothing looked them up. The parent's glue
// still carries all of their addresses, because glue is what it handed over
// rather than anything the walk had to go and fetch.
func askedFirst(names []string, servers ...trace.Server) *trace.Trace {
	return referred(names, false, servers...)
}

func referred(names []string, all bool, servers ...trace.Server) *trace.Trace {
	glue := make(map[string][]netip.Addr, len(names))
	children := make([]*trace.Step, 0, len(servers))
	for i, server := range servers {
		step := &trace.Step{Zone: "test.", Kind: trace.KindSkipped, Server: server}
		if all || i == 0 {
			step.Kind = trace.KindAnswer
			step.Records = []trace.RR{{Name: "www.test.", Type: "A", Data: "192.0.2.1"}}
		}
		children = append(children, step)
		glue[server.Name] = append(glue[server.Name], server.IP)
	}

	return walk(&trace.Step{
		Zone: ".", Kind: trace.KindReferral,
		Server:     trace.Server{Name: "root.test.", IP: netip.MustParseAddr("192.0.2.53")},
		Delegation: &trace.Delegation{Zone: "test.", NS: names, Glue: glue},
		Children:   children,
	})
}

func TestFindingsSpread(t *testing.T) {
	both := []string{"a.ns.test.", "b.ns.test."}

	tests := map[string]struct {
		trace *trace.Trace
		want  []string
		avoid []string
	}{
		"a zone with one nameserver has nothing to fall back on": {
			trace: askedAll([]string{"only.ns.test."}, ns("only.ns.test.", "192.0.2.1", 64496)),
			want:  []string{"test. is delegated to one nameserver, only.ns.test."},
		},
		"nameservers that all sit in one AS go down together": {
			trace: askedAll(both, ns("a.ns.test.", "192.0.2.1", 64496), ns("b.ns.test.", "198.51.100.1", 64496)),
			want:  []string{"all 2 nameservers of test. are in AS64496", "one operator's outage"},
		},
		"nameservers spread over two is what anyone would want, and gets no room": {
			trace: askedAll(both, ns("a.ns.test.", "192.0.2.1", 64496), ns("b.ns.test.", "198.51.100.1", 64497)),
			avoid: []string{"AS", "nameserver"},
		},
		"an AS lookup that did not answer is a gap, not a concentration": {
			trace: askedAll(both, ns("a.ns.test.", "192.0.2.1", 64496), ns("b.ns.test.", "198.51.100.1", 0)),
			avoid: []string{"AS64496", "one operator"},
		},
		"a nameserver the walk never asked leaves nothing to say about the set": {
			trace: askedFirst(both, ns("a.ns.test.", "192.0.2.1", 64496), ns("b.ns.test.", "198.51.100.1", 64496)),
			avoid: []string{"AS64496", "one operator"},
		},
		"a nameserver the delegation named and nothing resolved says nothing either": {
			trace: askedAll([]string{"a.ns.test.", "b.ns.test.", "far.example."},
				ns("a.ns.test.", "192.0.2.1", 64496), ns("b.ns.test.", "198.51.100.1", 64496)),
			avoid: []string{"AS64496", "one operator"},
		},
		"a zone reachable only over IPv6 is a zone most clients cannot reach": {
			trace: askedAll(both, ns("a.ns.test.", "2001:db8::1", 64496), ns("b.ns.test.", "2001:db8:1::1", 64497)),
			want:  []string{"the delegation of test. carries no IPv4 address for any of its nameservers"},
		},
		"the glue answers for the family whether or not the servers were asked": {
			trace: askedFirst(both, ns("a.ns.test.", "2001:db8::1", 64496), ns("b.ns.test.", "2001:db8:1::1", 0)),
			want:  []string{"the delegation of test. carries no IPv4 address for any of its nameservers"},
			avoid: []string{"AS64496"},
		},
		"an ordinary IPv4 zone is not told it has IPv4": {
			trace: askedAll(both, ns("a.ns.test.", "192.0.2.1", 64496), ns("b.ns.test.", "198.51.100.1", 64497)),
			avoid: []string{"IPv4"},
		},
		"the zone that answered is the one read, not the ones above it": {
			trace: walk(&trace.Step{
				Zone: ".", Kind: trace.KindReferral, Server: ns("root.test.", "192.0.2.53", 64496),
				Delegation: &trace.Delegation{Zone: "test.", NS: both},
				Children: []*trace.Step{
					{Zone: "test.", Kind: trace.KindAnswer, Server: ns("b.ns.test.", "198.51.100.1", 64497)},
					{
						Zone: "test.", Kind: trace.KindAnswer, Server: ns("a.ns.test.", "192.0.2.1", 64496),
						Delegation: &trace.Delegation{Zone: "sub.test.", NS: []string{"c.ns.test.", "d.ns.test."}},
						Children: []*trace.Step{
							{Zone: "sub.test.", Kind: trace.KindAnswer, Server: ns("c.ns.test.", "203.0.113.1", 64498),
								Records: []trace.RR{{Name: "www.test.", Type: "A", Data: "192.0.2.1"}}},
							{Zone: "sub.test.", Kind: trace.KindAnswer, Server: ns("d.ns.test.", "203.0.113.2", 64498)},
						},
					},
				},
			}),
			// sub.test. answered and its two nameservers share an AS; test. is
			// spread across two, and is not the zone being read.
			want:  []string{"all 2 nameservers of sub.test. are in AS64498"},
			avoid: []string{"of test. are in"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := said(test.trace)
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("got\n%s\nwant it to carry %q", got, want)
				}
			}
			for _, avoid := range test.avoid {
				if strings.Contains(got, avoid) {
					t.Errorf("got\n%s\nwant nothing in it saying %q", got, avoid)
				}
			}
		})
	}
}

// cut is a walk that was told where test. lives before it got there, so
// that the delegation carries a lifetime of its own.
func cut(ttl uint32, answer *trace.Step) *trace.Trace {
	return walk(&trace.Step{
		Zone:       ".",
		Kind:       trace.KindReferral,
		Server:     trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("192.0.2.1"), Port: 53},
		Delegation: &trace.Delegation{Zone: "test.", TTL: ttl, NS: []string{"ns.test."}},
		Children:   []*trace.Step{answer},
	})
}

// answered is one hop that answered, with that TTL on the records.
func answered(ttl uint32) *trace.Step {
	step := hop(trace.KindAnswer, "ns.test.")
	step.Records = []trace.RR{{Name: "www.test.", TTL: ttl, Type: "A", Data: "192.0.2.1"}}
	return step
}

// TestCache covers the question a change window turns on: how long what the
// walk found goes on being served after it has changed. Nothing here is worked
// out from a message — every number is a TTL the walk recorded.
func TestCache(t *testing.T) {
	tests := map[string]struct {
		trace *trace.Trace
		want  []string
		avoid []string
	}{
		"an answer says how long a cache may keep it": {
			trace: walk(answered(300)),
			want:  []string{"a cache may hold this answer for 5 minutes"},
		},
		"the delegation is said beside it, because it is the longer wait": {
			trace: cut(172800, answered(300)),
			want:  []string{"a cache may hold this answer for 5 minutes, and the delegation to test. for 2 days"},
		},
		"a delegation with nothing under it is still worth the wait it costs": {
			trace: cut(172800, hop(trace.KindTimeout, "ns.test.")),
			avoid: []string{"a cache may hold"}, // nothing answered, so there is nothing to hold
		},
		"a denial lives for the shorter of the two fields that can say so": {
			trace: walk(func() *trace.Step {
				step := hop(trace.KindNXDomain, "ns.test.")
				step.SOA = &trace.SOA{TTL: 3600, Minimum: 900}
				return step
			}()),
			want: []string{"a cache may hold this denial for 15 minutes"},
		},
		"a denial the zone said nothing about is not given a lifetime": {
			trace: walk(hop(trace.KindNoData, "ns.test.")),
			avoid: []string{"a cache may hold"},
		},
		"a resolver serving from its cache says how much of it is left": {
			trace: func() *trace.Trace {
				tr := walk(answered(300))
				tr.Resolvers = []*trace.Resolver{{
					Server:  trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
					Records: []trace.RR{{Name: "www.test.", TTL: 213, Type: "A", Data: "192.0.2.1"}},
				}}
				return tr
			}(),
			want: []string{"192.0.2.53 is answering this from its cache, with 3 minutes 33 seconds left"},
		},
		"a resolver that had to go and fetch it says nothing the zone has not": {
			trace: func() *trace.Trace {
				tr := walk(answered(300))
				tr.Resolvers = []*trace.Resolver{{
					Server:  trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
					Records: []trace.RR{{Name: "www.test.", TTL: 300, Type: "A", Data: "192.0.2.1"}},
				}}
				return tr
			}(),
			avoid: []string{"from its cache"},
		},
		"a walk that came to nothing has nothing to say about caches": {
			trace: walk(hop(trace.KindTimeout, "ns.test.")),
			avoid: []string{"a cache may hold"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := said(test.trace)
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("got %q, want it to say %q", got, want)
				}
			}
			for _, avoid := range test.avoid {
				if strings.Contains(got, avoid) {
					t.Errorf("got %q, want it not to say %q", got, avoid)
				}
			}
		})
	}
}

// TestCacheLifetimesAreSpelledOut covers the words themselves. A lifetime is
// read by somebody deciding whether to wait through it, so it is written the
// way they would say it rather than the way a TTL is stored.
func TestCacheLifetimesAreSpelledOut(t *testing.T) {
	for _, tt := range []struct {
		ttl  uint32
		want string
	}{
		{ttl: 45, want: "45 seconds"},
		{ttl: 60, want: "1 minute"},
		{ttl: 90, want: "1 minute 30 seconds"},
		{ttl: 300, want: "5 minutes"},
		{ttl: 3600, want: "1 hour"},
		{ttl: 5400, want: "1 hour 30 minutes"},
		{ttl: 86400, want: "1 day"},
		{ttl: 90000, want: "1 day 1 hour"},
		{ttl: 172800, want: "2 days"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			want := "a cache may hold this answer for " + tt.want
			if got := said(walk(answered(tt.ttl))); !strings.Contains(got, want) {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

// TestSeveralResolvers covers the question asked from several places at once.
// Each of them is its own view of the name, so the ones that answered
// differently are named and the ones that agreed take no room.
func TestSeveralResolvers(t *testing.T) {
	resolver := func(ip string, ttl uint32, match trace.Match) *trace.Resolver {
		return &trace.Resolver{
			Server:  trace.Server{IP: netip.MustParseAddr(ip), Port: 53},
			Rcode:   "NOERROR",
			Match:   match,
			Records: []trace.RR{{Name: "www.test.", TTL: ttl, Type: "A", Data: "192.0.2.1"}},
		}
	}

	tr := walk(answered(300))
	tr.Resolvers = []*trace.Resolver{
		resolver("192.0.2.53", 300, trace.MatchSame),
		resolver("192.0.2.54", 120, trace.MatchDiffers),
		resolver("192.0.2.55", 90, trace.MatchDiffers),
	}

	got := said(tr)
	for _, want := range []string{
		"192.0.2.54 and 192.0.2.55 answered this question differently",
		"192.0.2.54 is answering this from its cache, with 2 minutes left",
		"192.0.2.55 is answering this from its cache, with 1 minute 30 seconds left",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("got %q, want it to say %q", got, want)
		}
	}
	// It fetched the answer rather than serving one it had, so there is nothing
	// left on it to report, and it agreed, so it is not named as differing.
	if strings.Contains(got, "192.0.2.53") {
		t.Errorf("got %q, want nothing about the resolver that agreed and had nothing cached", got)
	}
}
