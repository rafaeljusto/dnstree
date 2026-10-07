package dot_test

import (
	"bytes"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/render/dot"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fixture"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/golden"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRender(t *testing.T) {
	var got bytes.Buffer
	if err := dot.Render(&got, fixture.Graph()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	golden.Compare(t, "resolution", got.String())
}

// TestRenderIsGraphviz hands the output to Graphviz, which is the only real
// judge of whether this is a graph.
func TestRenderIsGraphviz(t *testing.T) {
	graphviz, err := exec.LookPath("dot")
	if err != nil {
		t.Skip("graphviz is not installed here")
	}

	for name, tr := range map[string]*trace.Trace{
		"a resolution": fixture.Graph(),
		"nothing":      nil,
		"a bare trace": {Question: trace.Question{Name: `a "quoted\name".`, Type: "A"}},
	} {
		t.Run(name, func(t *testing.T) {
			var graph bytes.Buffer
			if err := dot.Render(&graph, tr); err != nil {
				t.Fatalf("Render: %v", err)
			}

			command := exec.Command(graphviz, "-Tsvg")
			command.Stdin = &graph
			svg, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("dot -Tsvg: %v\n--- graph ---\n%s\n--- output ---\n%s", err, graph.String(), svg)
			}
			if !strings.Contains(string(svg), "<svg") {
				t.Errorf("got %q, want an SVG", svg)
			}
		})
	}
}

// TestRenderIsStable guards against the clusters coming out in whatever order a
// map felt like.
func TestRenderIsStable(t *testing.T) {
	var first, second bytes.Buffer
	if err := dot.Render(&first, fixture.Graph()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := dot.Render(&second, fixture.Graph()); err != nil {
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
	if err := dot.Render(&out, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out.String(), "color=darkgoldenrod") {
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
	if err := dot.Render(&out, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"cds pending", "bootstrap refused", "csync waiting"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("got %q, want it to carry %q", out.String(), want)
		}
	}
}
