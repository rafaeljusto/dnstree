package mermaid_test

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/mermaid"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// resolution carries one of everything the schema has to be able to say.
func resolution() *trace.Trace {
	answer := &trace.Step{
		Zone: "example.com.",
		Server: trace.Server{
			Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53"), Port: 53,
			ASN: &trace.ASNInfo{
				Number: 10745, Prefix: "199.43.132.0/22", CountryCode: "US",
				Registry: "arin", Allocated: "2010-03-30",
			},
		},
		Proto:   "udp",
		RTT:     9*time.Millisecond + 400*time.Microsecond,
		Rcode:   "NOERROR",
		Flags:   trace.Flags{AA: true, DO: true, EDNS: true},
		Kind:    trace.KindAnswer,
		DNSSEC:  &trace.DNSSECStatus{State: trace.Secure, KeyTags: []uint16{31589}, Algorithm: "ECDSAP256SHA256"},
		Records: []trace.RR{{Name: "www.example.com.", TTL: 3600, Type: "A", Data: "93.184.216.34"}},
		Children: []*trace.Step{{
			Zone:   "example.com.",
			Server: trace.Server{Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53"), Port: 53},
			Proto:  "udp",
			RTT:    8 * time.Millisecond,
			Rcode:  "NOERROR",
			Flags:  trace.Flags{AA: true},
			Kind:   trace.KindAnswer,
			Aside:  true,
			Notes:  []string{"DNSKEY of example.com."},
		}},
	}
	skipped := &trace.Step{
		Zone:   "example.com.",
		Server: trace.Server{Name: "b.iana-servers.net.", IP: netip.MustParseAddr("199.43.133.53"), Port: 53},
		Kind:   trace.KindSkipped,
	}
	tld := &trace.Step{
		Zone:   "com.",
		Server: trace.Server{Name: "a.gtld-servers.net.", IP: netip.MustParseAddr("192.5.6.30"), Port: 53},
		Proto:  "tcp",
		RTT:    18 * time.Millisecond,
		Rcode:  "NOERROR",
		Kind:   trace.KindReferral,
		Notes:  []string{"truncated over udp"},
		Delegation: &trace.Delegation{
			Zone: "example.com.",
			NS:   []string{"a.iana-servers.net.", "ns.outside.example."},
			Glue: map[string][]netip.Addr{
				"a.iana-servers.net.": {netip.MustParseAddr("199.43.135.53")},
			},
			OutOfBailiwick: []string{"ns.outside.example."},
			DSPresent:      true,
		},
		DNSSEC:   &trace.DNSSECStatus{State: trace.Secure, Algorithm: "ECDSAP256SHA256", Digest: "SHA256"},
		Children: []*trace.Step{answer, skipped},
	}
	timeout := &trace.Step{
		Zone:   "com.",
		Server: trace.Server{Name: "b.gtld-servers.net.", IP: netip.MustParseAddr("192.33.14.30"), Port: 53},
		Proto:  "udp",
		RTT:    2 * time.Second,
		Kind:   trace.KindTimeout,
		Err:    "udp 192.33.14.30:53: i/o timeout",
	}
	root := &trace.Step{
		Zone:       ".",
		Server:     trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("198.41.0.4"), Port: 53},
		Proto:      "udp",
		RTT:        12 * time.Millisecond,
		Rcode:      "NOERROR",
		Kind:       trace.KindReferral,
		NSID:       "fra2",
		Cookie:     trace.CookieSupported,
		Delegation: &trace.Delegation{Zone: "com.", NS: []string{"a.gtld-servers.net."}, DSPresent: true},
		DNSSEC:     &trace.DNSSECStatus{State: trace.Insecure, Reason: "the parent published no DS"},
		Children:   []*trace.Step{timeout, tld},
	}

	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{root}},
		Elapsed:  41*time.Millisecond + 500*time.Microsecond,
		Resolvers: []*trace.Resolver{{
			Server:  trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
			Elapsed: 23 * time.Millisecond,
			Rcode:   "NOERROR",
		}},
		Warnings: []string{"the delegation to example.com. lists a nameserver the zone does not"},
	}
}

func TestRender(t *testing.T) {
	var got bytes.Buffer
	if err := mermaid.Render(&got, resolution()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	compare(t, "resolution", got.String())
}

// TestRenderEscapes covers text the servers wrote, which reaches a page that
// reads Mermaid entities and HTML: neither may be able to end a label early,
// open a tag or become an entity it did not spell.
func TestRenderEscapes(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: `a"b.example.`, Type: "TXT"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindAnswer, Server: trace.Server{IP: netip.MustParseAddr("192.0.2.1")},
			Records: []trace.RR{{Name: "a.example.", Type: "TXT", Data: `"<script>x</script> #quot; & ` + "`" + `"`}},
		}}},
		Warnings: []string{"title: end"},
	}

	var got bytes.Buffer
	if err := mermaid.Render(&got, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := got.String()
	for _, raw := range []string{"<script>", "</script>", "#quot; &", "`"} {
		if strings.Contains(out, raw) {
			t.Errorf("got %q in the chart, want it escaped:\n%s", raw, out)
		}
	}
	if !strings.Contains(out, `title: "dnstree a\"b.example. TXT"`) {
		t.Errorf("got\n%s\nwant the title quoted for YAML", out)
	}
}

// TestRenderIsMermaid hands the output to the Mermaid CLI, which is the only
// real judge of whether this is a chart.
func TestRenderIsMermaid(t *testing.T) {
	mmdc, err := exec.LookPath("mmdc")
	if err != nil {
		t.Skip("the mermaid cli is not installed here")
	}

	for name, tr := range map[string]*trace.Trace{
		"a resolution": resolution(),
		"a bare trace": {Question: trace.Question{Name: `a "quoted\name".`, Type: "A"}},
	} {
		t.Run(name, func(t *testing.T) {
			var chart bytes.Buffer
			if err := mermaid.Render(&chart, tr); err != nil {
				t.Fatalf("Render: %v", err)
			}
			dir := t.TempDir()
			input := filepath.Join(dir, "chart.mmd")
			if err := os.WriteFile(input, chart.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(mmdc, "-i", input, "-o", filepath.Join(dir, "chart.svg")).CombinedOutput()
			if err != nil {
				t.Fatalf("mmdc: %v\n--- chart ---\n%s\n--- output ---\n%s", err, chart.String(), output)
			}
		})
	}
}

// TestRenderIsStable guards against the subgraphs coming out in whatever order
// a map felt like.
func TestRenderIsStable(t *testing.T) {
	var first, second bytes.Buffer
	if err := mermaid.Render(&first, resolution()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := mermaid.Render(&second, resolution()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if first.String() != second.String() {
		t.Error("two renderings of the same trace differ")
	}
}

func compare(tb testing.TB, name, got string) {
	tb.Helper()

	golden := filepath.Join("testdata", name+".golden")
	if *update {
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

// TestRenderMinimised covers a hop that asked about a shorter name than the
// question. What it came back with is only a way down, and drawn as the answer
// it would be read as one.
func TestRenderMinimised(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: "test.", Kind: trace.KindNoData, Minimised: true, Rcode: "NOERROR",
			Server: trace.Server{Name: "ns.test.", IP: netip.MustParseAddr("192.0.2.5")},
			Notes:  []string{"minimised to test."},
		}}},
	}

	var out bytes.Buffer
	if err := mermaid.Render(&out, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out.String(), "class n1 denial") {
		t.Errorf("got %q, want the minimised hop left uncoloured", out.String())
	}
	if !strings.Contains(out.String(), "minimised to test.") {
		t.Errorf("got %q, want it to say what it asked", out.String())
	}
}
