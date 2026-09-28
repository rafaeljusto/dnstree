package mermaid_test

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/mermaid"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// timeline is a timed walk: a silence at the root, a detour for the address of
// a nameserver, the keys of the zone, and a walk that gave up.
func timeline() *trace.Trace {
	ms := time.Millisecond
	at := func(name, addr string) trace.Server {
		return trace.Server{Name: name, IP: netip.MustParseAddr(addr), Port: 53}
	}
	asked := func(name, qtype string) trace.Question { return trace.Question{Name: name, Type: qtype} }

	keys := &trace.Step{Zone: "example.com.", Server: at("hera.ns.example.com.", "192.0.2.10"),
		Kind: trace.KindAnswer, Aside: true, Asked: asked("example.com.", "DNSKEY"), Start: 335 * ms, RTT: 38 * ms}
	answer := &trace.Step{Zone: "example.com.", Server: at("hera.ns.example.com.", "192.0.2.10"),
		Kind: trace.KindAnswer, Asked: asked("www.example.com.", "A"), Start: 261 * ms, RTT: 74 * ms,
		Children: []*trace.Step{keys}}
	address := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true, Children: []*trace.Step{{
		Zone: ".", Server: at("b.root-servers.net.", "170.247.170.2"), Kind: trace.KindReferral,
		Asked: asked("ns1.dnshost.net.", "A"), Start: 110 * ms, RTT: 51 * ms, Delegation: &trace.Delegation{Zone: "net."},
	}}}
	tld := &trace.Step{Zone: "com.", Server: at("l.gtld-servers.net.", "192.41.162.30"),
		Kind: trace.KindReferral, Asked: asked("www.example.com.", "A"), Start: 48 * ms, RTT: 61 * ms,
		Delegation: &trace.Delegation{Zone: "example.com."}, Children: []*trace.Step{address, answer}}
	silent := &trace.Step{Zone: ".", Server: trace.Server{IP: netip.MustParseAddr("2001:500:2::c"), Port: 53},
		Kind: trace.KindTimeout, Asked: asked("www.example.com.", "A"), RTT: 400 * ms}
	root := &trace.Step{Zone: ".", Server: at("a.root-servers.net.", "198.41.0.4"),
		Kind: trace.KindReferral, Asked: asked("www.example.com.", "A"), Start: 300 * time.Microsecond, RTT: 47 * ms,
		Delegation: &trace.Delegation{Zone: "com."},
		Children:   []*trace.Step{tld, {Zone: "com.", Kind: trace.KindError, Err: "gave up after 64 queries"}}}

	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Timed:    true,
		Elapsed:  450 * ms,
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{silent, root}},
	}
}

func TestGantt(t *testing.T) {
	var got bytes.Buffer
	if err := mermaid.Gantt(&got, timeline()); err != nil {
		t.Fatalf("Gantt: %v", err)
	}
	compare(t, "gantt", got.String())
}

// TestGanttText covers what a gantt chart cannot quote: a colon ends a task's
// name, which every IPv6 address has, and a hash or a percent sign starts a
// comment that would swallow the rest of the line.
func TestGanttText(t *testing.T) {
	tr := timeline()
	tr.Root.Children[1].Server.Name = "odd%name#here;."

	var got bytes.Buffer
	if err := mermaid.Gantt(&got, tr); err != nil {
		t.Fatalf("Gantt: %v", err)
	}
	for line := range strings.Lines(got.String()) {
		name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.HasPrefix(line, "    dateFormat") || strings.HasPrefix(line, "    axisFormat") {
			continue
		}
		if strings.ContainsAny(name, ":#%;") {
			t.Errorf("got %q, want no colon, hash, percent or semicolon in a task name", name)
		}
	}
}

func TestGanttUntimed(t *testing.T) {
	tr := timeline()
	tr.Timed = false
	if err := mermaid.Gantt(&bytes.Buffer{}, tr); !errors.Is(err, trace.ErrUntimed) {
		t.Errorf("got %v, want %v", err, trace.ErrUntimed)
	}
}

func TestGanttAxis(t *testing.T) {
	tests := map[string]struct {
		elapsed time.Duration
		want    string
	}{
		"a walk under a second is read in milliseconds": {elapsed: 450 * time.Millisecond, want: "axisFormat %L ms"},
		"a walk of seconds is read in seconds":          {elapsed: 8 * time.Second, want: "axisFormat %S.%L s"},
		"a walk of minutes is read in minutes":          {elapsed: 2 * time.Minute, want: "axisFormat %M:%S"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := timeline()
			tr.Elapsed = test.elapsed
			var got bytes.Buffer
			if err := mermaid.Gantt(&got, tr); err != nil {
				t.Fatalf("Gantt: %v", err)
			}
			if !strings.Contains(got.String(), test.want) {
				t.Errorf("got\n%s\nwant %q", got.String(), test.want)
			}
		})
	}
}
