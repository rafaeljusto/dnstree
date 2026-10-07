package mermaid_test

import (
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/render/mermaid"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fixture"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/golden"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRender(t *testing.T) {
	var got bytes.Buffer
	if err := mermaid.Render(&got, fixture.Graph()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	golden.Compare(t, "resolution", got.String())
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
		"a resolution": fixture.Graph(),
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
	if err := mermaid.Render(&first, fixture.Graph()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := mermaid.Render(&second, fixture.Graph()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if first.String() != second.String() {
		t.Error("two renderings of the same trace differ")
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

// TestRenderRequests covers what a zone asks its parent to change: its CSYNC,
// and whether a parent would bootstrap its first DS.
func TestRenderRequests(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: ".", Kind: trace.KindReferral, Rcode: "NOERROR",
			Server:     trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("192.0.2.1")},
			Delegation: &trace.Delegation{Zone: "test.", CSYNC: &trace.CSYNC{State: trace.CSYNCWaiting}},
			DNSSEC: &trace.DNSSECStatus{State: trace.Insecure, Signal: &trace.Signal{State: trace.SignalPending,
				Bootstrap: &trace.Bootstrap{State: trace.BootstrapRefused}}},
		}}},
	}

	var out bytes.Buffer
	if err := mermaid.Render(&out, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"cds pending", "bootstrap refused", "csync waiting"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("got %q, want it to carry %q", out.String(), want)
		}
	}
}
