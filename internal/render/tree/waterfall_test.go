package tree_test

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func question(name, qtype string) trace.Question { return trace.Question{Name: name, Type: qtype} }

// timeline is a walk with something of each thing a waterfall has to show: two
// servers of a zone asked at once, a silence asked again, a detour for the
// address of a nameserver, the keys of the zone fetched in under a
// millisecond, and a walk that gave up.
func timeline() *trace.Trace {
	ms := time.Millisecond
	keys := &trace.Step{Zone: "example.com.", Server: server("hera.ns.example.com.", "192.0.2.10", 0),
		Kind: trace.KindAnswer, Aside: true, Asked: question("example.com.", "DNSKEY"),
		Start: 335 * ms, RTT: 380 * time.Microsecond, Notes: []string{"DNSKEY of example.com."}}
	answer := &trace.Step{Zone: "example.com.", Server: server("hera.ns.example.com.", "192.0.2.10", 0),
		Kind: trace.KindAnswer, Asked: question("www.example.com.", "A"),
		Start: 261 * ms, RTT: 74 * ms, Children: []*trace.Step{keys}}
	address := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true,
		Notes: []string{"resolving ns1.dnshost.net."}, Children: []*trace.Step{{
			Zone: ".", Server: server("b.root-servers.net.", "170.247.170.2", 0), Kind: trace.KindReferral,
			Asked: question("ns1.dnshost.net.", "A"), Start: 110 * ms, RTT: 51 * ms,
			Delegation: &trace.Delegation{Zone: "net."},
			Children: []*trace.Step{{
				Zone: "net.", Server: server("a.gtld-servers.net.", "192.5.6.30", 0), Kind: trace.KindAnswer,
				Asked: question("ns1.dnshost.net.", "A"), Start: 162 * ms, RTT: 98 * ms,
			}},
		}}}
	tld := &trace.Step{Zone: "com.", Server: server("l.gtld-servers.net.", "192.41.162.30", 0),
		Kind: trace.KindReferral, Asked: question("www.example.com.", "A"), Start: 48 * ms, RTT: 61 * ms,
		Delegation: &trace.Delegation{Zone: "example.com."},
		Children:   []*trace.Step{address, answer}}
	silent := &trace.Step{Zone: "com.", Server: server("m.gtld-servers.net.", "192.55.83.30", 0),
		Kind: trace.KindTimeout, Asked: question("www.example.com.", "A"), Start: 48 * ms, RTT: 400 * ms,
		Notes: []string{"asked again after a silence"}}
	root := &trace.Step{Zone: ".", Server: server("a.root-servers.net.", "198.41.0.4", 0),
		Kind: trace.KindReferral, Asked: question("www.example.com.", "A"), Start: 0, RTT: 47 * ms,
		Delegation: &trace.Delegation{Zone: "com."},
		Children:   []*trace.Step{silent, tld, {Zone: "com.", Kind: trace.KindError, Err: "gave up after 64 queries"}}}

	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Timed:    true,
		Elapsed:  450 * ms,
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{root}},
		Warnings: []string{"the delegation to example.com. came with no glue"},
	}
}

func TestWaterfall(t *testing.T) {
	tests := map[string]tree.Options{
		"waterfall":       {Width: 100},
		"waterfall_ascii": {Width: 100, Charset: tree.ASCII},
		"waterfall_color": {Width: 100, Color: tree.ColorAlways},
		"waterfall_80":    {},
	}
	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			var got bytes.Buffer
			if err := tree.Waterfall(&got, timeline(), options); err != nil {
				t.Fatalf("Waterfall: %v", err)
			}
			compare(t, name, got.String())
		})
	}
}

// TestWaterfallASCII holds waterfall-ascii to the promise --format ascii makes.
func TestWaterfallASCII(t *testing.T) {
	var got bytes.Buffer
	if err := tree.Waterfall(&got, timeline(), tree.Options{Charset: tree.ASCII, Width: 60}); err != nil {
		t.Fatalf("Waterfall: %v", err)
	}
	for i, r := range got.String() {
		if r > 127 {
			t.Fatalf("got %q at byte %d, want ASCII only", r, i)
		}
	}
}

// TestWaterfallScale checks the bars are laid out on the width asked for, and
// that a query too quick for a cell of its own still gets one.
func TestWaterfallScale(t *testing.T) {
	tr := timeline()
	tr.Warnings = nil
	for _, width := range []int{60, 100, 160} {
		var got bytes.Buffer
		if err := tree.Waterfall(&got, tr, tree.Options{Width: width}); err != nil {
			t.Fatalf("Waterfall: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(got.String(), "\n"), "\n")
		for _, line := range lines[1:] {
			if strings.Contains(line, "gave up") {
				if strings.ContainsAny(line, "█░") {
					t.Errorf("width %d: got a bar for a step that asked nothing: %q", width, line)
				}
				continue
			}
			if !strings.ContainsAny(line, "█░") {
				t.Errorf("width %d: got no bar for a query: %q", width, line)
			}
			// Everything up to the end of the bars fits, whatever follows it.
			end := strings.LastIndexAny(line, "█░")
			if cells := utf8.RuneCountInString(line[:end]) + 1; cells > width {
				t.Errorf("width %d: the bars run to column %d: %q", width, cells, line)
			}
		}
	}
}

// TestWaterfallUntimed is a walk saved before start times were kept: a zero
// start is no position, so nothing is drawn rather than every bar at zero.
func TestWaterfallUntimed(t *testing.T) {
	tr := timeline()
	tr.Timed = false

	var got bytes.Buffer
	if err := tree.Waterfall(&got, tr, tree.Options{}); !errors.Is(err, trace.ErrUntimed) {
		t.Fatalf("got %v, want %v", err, trace.ErrUntimed)
	}
	if got.Len() > 0 {
		t.Errorf("got %q, want nothing drawn", got.String())
	}
}

// TestWaterfallHostileTimes draws times a hand-written file can carry, which
// no walk makes: every one of them has to come back drawn, and soon.
func TestWaterfallHostileTimes(t *testing.T) {
	tests := map[string]struct{ start, rtt, elapsed time.Duration }{
		"a start at the end of time":    {start: math.MaxInt64 - 1, rtt: math.MaxInt64, elapsed: math.MaxInt64},
		"a round trip that runs back":   {start: time.Second, rtt: -time.Hour},
		"a start before the walk began": {start: -time.Hour, rtt: time.Millisecond},
		"a start far past a walk that took no time": {
			start: 9_000_000_000_000_000_000, rtt: time.Nanosecond - 9_000_000_000_000_000_000},
		"no time at all, anywhere": {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := &trace.Trace{Timed: true, Elapsed: test.elapsed, Root: &trace.Step{Zone: ".", Kind: trace.KindZone,
				Children: []*trace.Step{{Zone: ".", Kind: trace.KindAnswer, Asked: question("x.", "A"),
					Start: test.start, RTT: test.rtt}}}}
			var got bytes.Buffer
			if err := tree.Waterfall(&got, tr, tree.Options{Width: 80}); err != nil {
				t.Fatalf("Waterfall: %v", err)
			}
			if !strings.Contains(got.String(), "answer") {
				t.Errorf("got %q, want the query drawn", got.String())
			}
		})
	}
}

func TestWaterfallNothingAsked(t *testing.T) {
	tr := &trace.Trace{Timed: true, Root: &trace.Step{Zone: ".", Kind: trace.KindZone}}

	var got bytes.Buffer
	if err := tree.Waterfall(&got, tr, tree.Options{}); err != nil {
		t.Fatalf("Waterfall: %v", err)
	}
	if want := "no server was asked\n"; got.String() != want {
		t.Errorf("got %q, want %q", got.String(), want)
	}
}
