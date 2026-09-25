package tree_test

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/render/tree"
	"github.com/rafaeljusto/dnstree/internal/trace"
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
