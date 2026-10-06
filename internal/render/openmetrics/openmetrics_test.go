package openmetrics_test

import (
	"bytes"
	"flag"
	"fmt"
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
			{
				Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53}, Elapsed: 23 * time.Millisecond, Match: trace.MatchSame,
				Records: []trace.RR{{Name: "www.example.com.", TTL: 3412, Type: "A", Data: "93.184.216.34"}},
			},
			{
				Server: trace.Server{IP: netip.MustParseAddr("192.0.2.54"), Port: 53}, Elapsed: 31 * time.Millisecond, Match: trace.MatchDiffers,
				Records: []trace.RR{{Name: "www.example.com.", TTL: 30, Type: "A", Data: "192.0.2.80"}}, Kept: trace.KeptStale,
			},
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

// TestRenderProbes covers what --check-axfr and --check-recursion found. A
// server that could not be asked has no sample, since a zero would read as a
// server that refused; and a refusal that came as a reset is not a failed
// query, since the server did its job.
func TestRenderProbes(t *testing.T) {
	probe := func(ip string, kind trace.ProbeKind, state trace.ProbeState, how trace.StepKind) *trace.Step {
		return &trace.Step{
			Zone: "test.", Kind: how, Aside: true,
			Server: trace.Server{Name: "ns.test.", IP: netip.MustParseAddr(ip)},
			Asked:  trace.Question{Name: "test.", Type: "AXFR"},
			Probe:  &trace.Probe{Kind: kind, State: state},
		}
	}
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
			probe("192.0.2.5", trace.ProbeTransfer, trace.ProbeOpen, trace.KindAnswer),
			probe("192.0.2.5", trace.ProbeRecursion, trace.ProbeClosed, trace.KindAnswer),
			probe("192.0.2.6", trace.ProbeTransfer, trace.ProbeUnchecked, trace.KindTimeout),
			probe("192.0.2.7", trace.ProbeTransfer, trace.ProbeClosed, trace.KindError),
		}},
	}

	out := render(t, tr)
	valid(t, out)
	for _, want := range []string{
		`dnstree_open{name="www.test.",type="A",check="transfer",zone="test.",server="ns.test.",address="192.0.2.5"} 1`,
		`dnstree_open{name="www.test.",type="A",check="recursion",zone="test.",server="ns.test.",address="192.0.2.5"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got\n%s\nwant %s", out, want)
		}
	}
	if !strings.Contains(out, `dnstree_failed_queries{name="www.test.",type="A"} 1`) {
		t.Errorf("got\n%s\nwant only the silent server counted as failed", out)
	}
	if strings.Contains(out, "192.0.2.6") {
		t.Errorf("got\n%s\nwant no sample for the server that could not be asked", out)
	}
}

// TestRenderEDNS covers --check-edns: a sample for every test that was read,
// none for a server that answered nothing, and a dropped test counted once.
func TestRenderEDNS(t *testing.T) {
	test := func(ip string, kind trace.EDNSKind, state trace.EDNSState, how trace.StepKind) *trace.Step {
		return &trace.Step{
			Zone: "test.", Kind: how, Aside: true,
			Server: trace.Server{Name: "ns.test.", IP: netip.MustParseAddr(ip)},
			Asked:  trace.Question{Name: "test.", Type: "SOA"},
			EDNS:   &trace.EDNSTest{Kind: kind, State: state},
		}
	}
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
			test("192.0.2.5", trace.EDNSPlain, trace.EDNSOK, trace.KindAnswer),
			test("192.0.2.5", trace.EDNSFlag, trace.EDNSBroken, trace.KindTimeout),
			test("192.0.2.6", trace.EDNSPlain, trace.EDNSUnchecked, trace.KindTimeout),
		}},
	}

	out := render(t, tr)
	valid(t, out)
	for _, want := range []string{
		`dnstree_edns_ok{name="www.test.",type="A",test="edns",zone="test.",server="ns.test.",address="192.0.2.5"} 1`,
		`dnstree_edns_ok{name="www.test.",type="A",test="flag",zone="test.",server="ns.test.",address="192.0.2.5"} 0`,
		`dnstree_failed_queries{name="www.test.",type="A"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("got\n%s\nwant %s", out, want)
		}
	}
	if strings.Contains(out, "192.0.2.6") {
		t.Errorf("got\n%s\nwant no sample for the server that answered nothing", out)
	}
}

func TestRenderCAA(t *testing.T) {
	for name, tt := range map[string]struct {
		caa   *trace.CAA
		state string
	}{
		"a set naming who may issue": {caa: &trace.CAA{Owner: "test.", Issue: &trace.Issuers{CAs: []string{"letsencrypt.org"}}}, state: "restricted"},
		"no set anywhere":            {caa: &trace.CAA{}, state: "open"},
		"a lookup that failed":       {caa: &trace.CAA{Refused: "the CAA lookup at www.test. failed: SERVFAIL"}, state: "refused"},
		"a lookup left undecided":    {caa: &trace.CAA{Undecided: "the CAA lookup at www.test. failed: SERVFAIL"}, state: "undecided"},
		"a walk that did not look":   {},
	} {
		t.Run(name, func(t *testing.T) {
			tr := &trace.Trace{
				Question: trace.Question{Name: "www.test.", Type: "A"},
				Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
				CAA:      tt.caa,
			}
			out := render(t, tr)
			valid(t, out)
			if tt.state == "" {
				if strings.Contains(out, "dnstree_caa") {
					t.Errorf("got\n%s\nwant no CAA family", out)
				}
				return
			}
			for _, state := range []string{"restricted", "open", "refused", "undecided"} {
				want := fmt.Sprintf(`dnstree_caa{name="www.test.",type="A",state=%q} %s`, state, map[bool]string{true: "1", false: "0"}[state == tt.state])
				if !strings.Contains(out, want) {
					t.Errorf("got\n%s\nwant %s", out, want)
				}
			}
		})
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
			Asked:  trace.Question{Name: "a\"b\\c\n} 1\x1b.example.", Type: "A"},
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

func TestRenderSPF(t *testing.T) {
	for name, tt := range map[string]struct {
		spf *trace.SPF
	}{
		"a policy within the limits": {spf: &trace.SPF{Lookups: 7, Result: trace.SPFOK}},
		"a policy past them":         {spf: &trace.SPF{Lookups: 12, Result: trace.SPFPermError}},
		"a walk that did not look":   {},
	} {
		t.Run(name, func(t *testing.T) {
			tr := &trace.Trace{
				Question: trace.Question{Name: "www.test.", Type: "A"},
				Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
				SPF:      tt.spf,
			}
			out := render(t, tr)
			valid(t, out)
			if tt.spf == nil {
				if strings.Contains(out, "dnstree_spf") {
					t.Errorf("got\n%s\nwant no SPF family", out)
				}
				return
			}
			if want := fmt.Sprintf(`dnstree_spf_lookups{name="www.test.",type="A"} %d`, tt.spf.Lookups); !strings.Contains(out, want) {
				t.Errorf("got\n%s\nwant %s", out, want)
			}
			for _, result := range []string{"ok", "none", "permerror", "temperror", "undecided"} {
				want := fmt.Sprintf(`dnstree_spf{name="www.test.",type="A",result=%q} %s`, result, map[bool]string{true: "1", false: "0"}[result == string(tt.spf.Result)])
				if !strings.Contains(out, want) {
					t.Errorf("got\n%s\nwant %s", out, want)
				}
			}
		})
	}
}

func TestRenderRegistration(t *testing.T) {
	started := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	for name, tt := range map[string]struct {
		reg     *trace.Registration
		want    []string
		without []string
	}{
		"a registration with a month left": {
			reg: &trace.Registration{Domain: "test.", State: trace.Registered, Expires: started.Add(30 * 24 * time.Hour),
				Parent: ".", Status: []string{"active"}},
			want: []string{
				`dnstree_registration{name="www.test.",type="A",domain="test.",state="registered"} 1`,
				`dnstree_registration{name="www.test.",type="A",domain="test.",state="unreached"} 0`,
				`dnstree_registration_left_seconds{name="www.test.",type="A",domain="test."} 2592000`,
				`dnstree_registration_held{name="www.test.",type="A",domain="test."} 0`,
				`dnstree_registration_agrees{name="www.test.",type="A",domain="test."} 1`,
			},
		},
		"a registration that has run out and is held": {
			reg: &trace.Registration{Domain: "test.", State: trace.Registered, Expires: started.Add(-time.Hour),
				Status: []string{"redemption period"}},
			want: []string{
				`dnstree_registration_left_seconds{name="www.test.",type="A",domain="test."} -3600`,
				`dnstree_registration_held{name="www.test.",type="A",domain="test."} 1`,
			},
			without: []string{"dnstree_registration_agrees"},
		},
		"a registry that did not answer": {
			reg:     &trace.Registration{Domain: "test.", State: trace.Unreached},
			want:    []string{`dnstree_registration{name="www.test.",type="A",domain="test.",state="unreached"} 1`},
			without: []string{"dnstree_registration_left_seconds", "dnstree_registration_held"},
		},
		"a walk that did not ask": {
			without: []string{"dnstree_registration"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := &trace.Trace{
				Question:     trace.Question{Name: "www.test.", Type: "A"},
				Root:         &trace.Step{Zone: ".", Kind: trace.KindZone},
				Started:      started,
				Registration: tt.reg,
			}
			out := render(t, tr)
			valid(t, out)
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("got\n%s\nwant %s", out, want)
				}
			}
			for _, family := range tt.without {
				if strings.Contains(out, family+"{") {
					t.Errorf("got\n%s\nwant no %s", out, family)
				}
			}
		})
	}
}
