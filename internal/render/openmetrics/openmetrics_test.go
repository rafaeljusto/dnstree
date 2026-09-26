package openmetrics_test

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/openmetrics"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var started = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// resolution carries one of everything a metric is read from.
func resolution() *trace.Trace {
	answer := &trace.Step{
		Zone:    "example.com.",
		Server:  trace.Server{Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53"), Port: 53},
		Asked:   trace.Question{Name: "www.example.com.", Type: "A"},
		Proto:   "udp",
		RTT:     9*time.Millisecond + 400*time.Microsecond,
		Rcode:   "NOERROR",
		Kind:    trace.KindAnswer,
		Records: []trace.RR{{Name: "www.example.com.", TTL: 3600, Type: "A", Data: "93.184.216.34"}},
		DNSSEC: &trace.DNSSECStatus{
			State: trace.Secure, Zone: "example.com.",
			Signal: &trace.Signal{State: trace.SignalPending, Requested: []uint16{2}, Held: []uint16{1}},
			Signatures: []trace.Lifetime{
				{Inception: started.Add(-24 * time.Hour), Expiration: started.Add(6 * 24 * time.Hour)},
				{Inception: started.Add(-24 * time.Hour), Expiration: started.Add(36 * time.Hour)},
			},
		},
		Children: []*trace.Step{{
			Zone:   "example.com.",
			Server: trace.Server{Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53"), Port: 53},
			Asked:  trace.Question{Name: "example.com.", Type: "DNSKEY"},
			RTT:    8 * time.Millisecond,
			Kind:   trace.KindAnswer,
			Aside:  true,
		}},
	}
	skipped := &trace.Step{
		Zone:   "example.com.",
		Server: trace.Server{Name: "b.iana-servers.net.", IP: netip.MustParseAddr("199.43.133.53"), Port: 53},
		Kind:   trace.KindSkipped,
	}
	tld := &trace.Step{
		Zone:       "com.",
		Server:     trace.Server{Name: "a.gtld-servers.net.", IP: netip.MustParseAddr("192.5.6.30"), Port: 53},
		Asked:      trace.Question{Name: "www.example.com.", Type: "A"},
		RTT:        18 * time.Millisecond,
		Rcode:      "NOERROR",
		Kind:       trace.KindReferral,
		Delegation: &trace.Delegation{Zone: "example.com.", DSPresent: true},
		DNSSEC:     &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com."},
		Children:   []*trace.Step{answer, skipped},
	}
	timeout := &trace.Step{
		Zone:   "com.",
		Server: trace.Server{Name: "b.gtld-servers.net.", IP: netip.MustParseAddr("192.33.14.30"), Port: 53},
		Asked:  trace.Question{Name: "www.example.com.", Type: "A"},
		RTT:    2 * time.Second,
		Kind:   trace.KindTimeout,
		Err:    "i/o timeout",
	}
	root := &trace.Step{
		Zone:     ".",
		Server:   trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("198.41.0.4"), Port: 53},
		Asked:    trace.Question{Name: "www.example.com.", Type: "A"},
		RTT:      12 * time.Millisecond,
		Rcode:    "NOERROR",
		Kind:     trace.KindReferral,
		DNSSEC:   &trace.DNSSECStatus{State: trace.Secure, Zone: "com."},
		Children: []*trace.Step{timeout, tld},
	}
	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{root}},
		Elapsed:  2*time.Second + 41*time.Millisecond,
		Started:  started,
		Resolvers: []*trace.Resolver{
			{Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53}, Elapsed: 23 * time.Millisecond, Match: trace.MatchSame},
			{Server: trace.Server{IP: netip.MustParseAddr("192.0.2.54"), Port: 53}, Elapsed: 31 * time.Millisecond, Match: trace.MatchDiffers},
			{Server: trace.Server{IP: netip.MustParseAddr("192.0.2.55"), Port: 53}, Err: "i/o timeout"},
		},
		Warnings: []string{"the delegation to example.com. lists a nameserver the zone does not"},
	}
}

func TestRender(t *testing.T) {
	out := render(t, resolution())
	valid(t, out)
	compare(t, "resolution", out)
}

// TestRenderTrust covers the chain of trust read the way the exit code reads
// it, and left out where nothing was checked: a zero for every state would read
// as a chain that is none of them.
func TestRenderTrust(t *testing.T) {
	tests := map[string]struct {
		trace func() *trace.Trace
		want  string
	}{
		"a broken aside outranks a secure answer": {
			trace: func() *trace.Trace {
				tr := resolution()
				tr.Root.Children[0].Children[1].Children[0].Children[0].DNSSEC = &trace.DNSSECStatus{State: trace.Bogus}
				return tr
			},
			want: `dnstree_dnssec{name="www.example.com.",type="A",state="bogus"} 1`,
		},
		"an unchecked walk says nothing of trust": {
			trace: func() *trace.Trace {
				tr := resolution()
				for step := range tr.Steps() {
					step.DNSSEC = nil
				}
				return tr
			},
			want: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out := render(t, test.trace())
			valid(t, out)
			if test.want == "" {
				for _, family := range []string{"dnstree_dnssec", "dnstree_signature_left_seconds", "dnstree_cds"} {
					if strings.Contains(out, "# TYPE "+family+" ") {
						t.Errorf("got %s in\n%s\nwant it left out", family, out)
					}
				}
				return
			}
			if !strings.Contains(out, test.want) {
				t.Errorf("got\n%s\nwant %s", out, test.want)
			}
		})
	}
}

// TestRenderMinimised covers a hop that asked about a shorter name. Its NODATA
// is only a way down, and reported as the result it would read as one.
func TestRenderMinimised(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: "test.", Kind: trace.KindNoData, Minimised: true, Rcode: "NOERROR",
			Server: trace.Server{Name: "ns.test.", IP: netip.MustParseAddr("192.0.2.5")},
			Asked:  trace.Question{Name: "test.", Type: "NS"},
		}}},
	}

	out := render(t, tr)
	valid(t, out)
	if !strings.Contains(out, `kind="none"} 1`) || strings.Contains(out, `kind="nodata"} 1`) {
		t.Errorf("got\n%s\nwant the walk read as unanswered", out)
	}
}

// TestRenderEscapes covers names the servers wrote, which must not be able to
// end a label value early or start a line of their own.
func TestRenderEscapes(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "a\"b\\c\n} 1\x1b.example.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: "\"}.", Kind: trace.KindAnswer, RTT: time.Millisecond,
			Server: trace.Server{Name: "ns\n.", IP: netip.MustParseAddr("192.0.2.1")},
		}}},
	}

	out := render(t, tr)
	valid(t, out)
	if strings.ContainsAny(out, "\x1b\r") {
		t.Errorf("got an escape through:\n%q", out)
	}
	if want := `name="a\"b\\c\\010} 1\\027.example."`; !strings.Contains(out, want) {
		t.Errorf("got\n%s\nwant %s", out, want)
	}
}

// TestRenderEmpty covers a trace with nothing in it, which still has to be a
// document a scraper accepts.
func TestRenderEmpty(t *testing.T) {
	out := render(t, &trace.Trace{})
	valid(t, out)
	if !strings.Contains(out, `dnstree_result{name="",type="",kind="none"} 1`) {
		t.Errorf("got\n%s\nwant the walk read as unanswered", out)
	}
}

func render(tb testing.TB, tr *trace.Trace) string {
	tb.Helper()
	var out bytes.Buffer
	if err := openmetrics.Render(&out, tr); err != nil {
		tb.Fatalf("Render: %v", err)
	}
	return out.String()
}

var (
	sampleLine = regexp.MustCompile(`^([a-z_]+)\{((?:[a-z_]+="(?:[^"\\\n]|\\["\\n])*",?)*)\} (-?[0-9.]+)$`)
	typeLine   = regexp.MustCompile(`^# TYPE ([a-z_]+) gauge$`)
)

// valid holds the output to what a scraper refuses: a sample of a family never
// declared, a family declared twice or split in two, the same series twice, a
// unit its name does not end in, or no end marker.
func valid(tb testing.TB, out string) {
	tb.Helper()

	body, found := strings.CutSuffix(out, "# EOF\n")
	if !found {
		tb.Fatalf("got no # EOF at the end of\n%s", out)
	}
	var (
		current string
		closed  = map[string]bool{}
		series  = map[string]bool{}
	)
	for line := range strings.Lines(body) {
		line = strings.TrimSuffix(line, "\n")
		if match := typeLine.FindStringSubmatch(line); match != nil {
			if closed[match[1]] || match[1] == current {
				tb.Errorf("got %s declared twice", match[1])
			}
			closed[current] = true
			current = match[1]
			continue
		}
		if unit, ok := strings.CutPrefix(line, "# UNIT "+current+" "); ok {
			if !strings.HasSuffix(current, "_"+unit) {
				tb.Errorf("got %s in %s, want the name to end in it", unit, current)
			}
			continue
		}
		if strings.HasPrefix(line, "# HELP "+current+" ") {
			continue
		}
		match := sampleLine.FindStringSubmatch(line)
		switch {
		case match == nil:
			tb.Errorf("got a line no scraper reads: %q", line)
		case match[1] != current:
			tb.Errorf("got a sample of %s under %q", match[1], current)
		case series[match[1]+"{"+match[2]+"}"]:
			tb.Errorf("got %s twice", line)
		default:
			series[match[1]+"{"+match[2]+"}"] = true
		}
	}
}

func compare(tb testing.TB, name, got string) {
	tb.Helper()

	golden := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			tb.Fatalf("writing %s: %v", golden, err)
		}
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		tb.Fatalf("%v (run go test -update to create it)", err)
	}
	if got != string(want) {
		tb.Errorf("output does not match %s, run go test -update to see the change\n--- got ---\n%s", golden, got)
	}
}
