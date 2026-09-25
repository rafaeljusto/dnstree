package tree_test

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// resolution is the shape a real walk leaves behind: a timeout before the
// server that answered, an unqueried sibling, and the records at the end.
func resolution() *trace.Trace {
	answer := &trace.Step{
		Zone:   "example.com.",
		Server: server("a.iana-servers.net.", "199.43.135.53", 10745),
		Proto:  "udp",
		RTT:    9 * time.Millisecond,
		Rcode:  "NOERROR",
		Flags:  trace.Flags{AA: true, DO: true},
		Kind:   trace.KindAnswer,
		DNSSEC: &trace.DNSSECStatus{State: trace.Secure},
		Records: []trace.RR{
			{Name: "www.example.com.", TTL: 3600, Type: "A", Data: "93.184.216.34"},
		},
	}
	skipped := &trace.Step{
		Zone:   "example.com.",
		Server: trace.Server{Name: "b.iana-servers.net.", IP: netip.MustParseAddr("199.43.133.53"), Port: 53},
		Kind:   trace.KindSkipped,
	}
	tld := &trace.Step{
		Zone:       "com.",
		Server:     server("a.gtld-servers.net.", "192.5.6.30", 26415),
		Proto:      "udp",
		RTT:        18 * time.Millisecond,
		Rcode:      "NOERROR",
		Kind:       trace.KindReferral,
		Delegation: &trace.Delegation{Zone: "example.com.", DSPresent: true},
		Cookie:     trace.CookieAbsent,
		DNSSEC:     &trace.DNSSECStatus{State: trace.Secure},
		Children:   []*trace.Step{answer, skipped},
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
		Server:     server("a.root-servers.net.", "198.41.0.4", 397197),
		Proto:      "udp",
		RTT:        12 * time.Millisecond,
		Rcode:      "NOERROR",
		Kind:       trace.KindReferral,
		NSID:       "fra2",
		Cookie:     trace.CookieSupported,
		Delegation: &trace.Delegation{Zone: "com.", DSPresent: true},
		DNSSEC:     &trace.DNSSECStatus{State: trace.Secure},
		Children:   []*trace.Step{timeout, tld},
	}

	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{root}},
		Elapsed:  41 * time.Millisecond,
	}
}

// kinds is not a resolution anyone would get: it is one of every step kind, so
// that the golden file covers every label the renderer can draw.
func kinds() *trace.Trace {
	children := []*trace.Step{
		{Zone: "com.", Server: server("ns1.com.", "192.0.2.2", 0), Rcode: "SERVFAIL", Kind: trace.KindError, RTT: 4 * time.Millisecond,
			Notes: []string{"retried without EDNS0", "truncated over udp"}},
		// An answer with room behind it says nothing about its size, and one
		// with almost none left says so where the reader is looking.
		{Zone: "com.", Server: server("ns2.com.", "192.0.2.3", 0), Rcode: "NXDOMAIN", Flags: trace.Flags{AA: true}, Kind: trace.KindNXDomain, RTT: 4 * time.Millisecond,
			Size: 214, Limit: 1232},
		{Zone: "com.", Server: server("ns3.com.", "192.0.2.4", 0), Rcode: "NOERROR", Flags: trace.Flags{AA: true}, Kind: trace.KindNoData, RTT: 1250 * time.Microsecond,
			Size: 1200, Limit: 1232},
		{
			Zone: "com.", Server: server("ns4.com.", "192.0.2.5", 0), Rcode: "NOERROR",
			Flags: trace.Flags{AA: true, TC: true, AD: true, DO: true}, Kind: trace.KindCNAME, RTT: 340 * time.Microsecond,
			DNSSEC:  &trace.DNSSECStatus{State: trace.Bogus, Reason: "signature does not verify", Algorithm: "ED25519"},
			Records: []trace.RR{{Name: "alias.example.com.", TTL: 300, Type: "CNAME", Data: "target.example.net."}},
			// A walk of its own, drawn where it was needed.
			Children: []*trace.Step{{
				Zone: ".", Kind: trace.KindZone, Aside: true, Notes: []string{"resolving ns.outside.net."},
				Children: []*trace.Step{
					{Zone: ".", Server: server("c.root-servers.net.", "192.33.4.12", 0), Rcode: "NOERROR", RTT: 7 * time.Millisecond,
						Kind: trace.KindTimeout},
				},
			}},
		},
		{Zone: "com.", Kind: trace.KindError, Err: "gave up after 4 queries"},
	}
	referral := &trace.Step{
		Zone:       ".",
		Server:     trace.Server{Name: "b.root-servers.net.", IP: netip.MustParseAddr("170.247.170.2"), Port: 53},
		Rcode:      "NOERROR",
		RTT:        6 * time.Millisecond,
		Kind:       trace.KindReferral,
		Delegation: &trace.Delegation{Zone: "com."},
		DNSSEC:     &trace.DNSSECStatus{State: trace.Insecure, Algorithm: "ECDSAP256SHA256", Digest: "SHA256"},
		Children:   children,
	}
	lame := &trace.Step{
		Zone:   ".",
		Server: trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("198.41.0.4"), Port: 53},
		Rcode:  "REFUSED",
		RTT:    5 * time.Millisecond,
		Kind:   trace.KindLame,
		DNSSEC: &trace.DNSSECStatus{State: trace.Indeterminate, Reason: "digest type 5 is not supported here", Digest: "digest 5"},
	}

	return &trace.Trace{
		Question: trace.Question{Name: "alias.example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{lame, referral}},
		Warnings: []string{"no server answered for com."},
	}
}

func TestRender(t *testing.T) {
	tests := map[string]struct {
		trace   *trace.Trace
		options tree.Options
	}{
		"resolution":       {trace: resolution()},
		"resolution_ascii": {trace: resolution(), options: tree.Options{Charset: tree.ASCII}},
		"resolution_color": {trace: resolution(), options: tree.Options{Color: tree.ColorAlways}},
		"resolution_emoji": {trace: resolution(), options: tree.Options{Charset: tree.Emoji}},
		"kinds":            {trace: kinds()},
		"kinds_ascii":      {trace: kinds(), options: tree.Options{Charset: tree.ASCII}},
		"kinds_emoji":      {trace: kinds(), options: tree.Options{Charset: tree.Emoji}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var got bytes.Buffer
			if err := tree.Render(&got, test.trace, test.options); err != nil {
				t.Fatalf("Render: %v", err)
			}
			compare(t, name, got.String())
		})
	}
}

// TestRenderASCII guards the promise the ascii charset makes to documentation
// and markdown: nothing outside ASCII comes out.
func TestRenderASCII(t *testing.T) {
	for _, tr := range []*trace.Trace{resolution(), kinds()} {
		var got bytes.Buffer
		opts := tree.Options{Charset: tree.ASCII, Highlight: tr.Root.Children[0]}
		if err := tree.Render(&got, tr, opts); err != nil {
			t.Fatalf("Render: %v", err)
		}
		for i, r := range got.String() {
			if r > 127 {
				t.Fatalf("got %q at byte %d, want ASCII only", r, i)
			}
		}
	}
}

// TestRenderHighlight is what a live frame points at, and the alignment it may
// not cost: a marked branch is the same four cells wide as an unmarked one.
func TestRenderHighlight(t *testing.T) {
	tr := resolution()
	marked := tr.Root.Children[0]

	var plain, pointed bytes.Buffer
	if err := tree.Render(&plain, tr, tree.Options{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := tree.Render(&pointed, tr, tree.Options{Highlight: marked}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	if got := pointed.String(); !strings.Contains(got, "▸") {
		t.Errorf("got %q, want the hop that just landed pointed at", got)
	}
	if got, want := strings.Count(pointed.String(), "▸"), 1; got != want {
		t.Errorf("got %d hops pointed at, want %d", got, want)
	}

	// Every line keeps its width, and only the one branch differs.
	lines, marks := strings.Split(plain.String(), "\n"), strings.Split(pointed.String(), "\n")
	if len(lines) != len(marks) {
		t.Fatalf("got %d lines, want the %d of a tree drawn without a mark", len(marks), len(lines))
	}
	var differ int
	for i := range lines {
		if len([]rune(lines[i])) != len([]rune(marks[i])) {
			t.Errorf("got %q, want it the width of %q", marks[i], lines[i])
		}
		if lines[i] != marks[i] {
			differ++
		}
	}
	if differ != 1 {
		t.Errorf("got %d lines changed, want only the hop pointed at", differ)
	}
}

func TestRenderColor(t *testing.T) {
	tests := map[string]struct {
		mode    tree.ColorMode
		noColor string
		want    bool
	}{
		"always":                  {mode: tree.ColorAlways, want: true},
		"always despite NO_COLOR": {mode: tree.ColorAlways, noColor: "1", want: true},
		"never":                   {mode: tree.ColorNever},
		"auto is not a terminal":  {mode: tree.ColorAuto},
		"default is auto":         {},
		"auto with NO_COLOR":      {mode: tree.ColorAuto, noColor: "1"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// An empty NO_COLOR is the same as an absent one, per no-color.org.
			t.Setenv("TERM", "xterm-256color")
			t.Setenv("NO_COLOR", test.noColor)

			var got bytes.Buffer
			if err := tree.Render(&got, resolution(), tree.Options{Color: test.mode}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if coloured := strings.Contains(got.String(), "\x1b["); coloured != test.want {
				t.Errorf("got coloured %v, want %v", coloured, test.want)
			}
		})
	}
}

func TestRenderDuration(t *testing.T) {
	tests := map[string]struct {
		rtt     time.Duration
		charset tree.Charset
		want    string
	}{
		"seconds":        {rtt: 1234 * time.Millisecond, want: "1.23s"},
		"milliseconds":   {rtt: 12345 * time.Microsecond, want: "12ms"},
		"sub ten":        {rtt: 9440 * time.Microsecond, want: "9.4ms"},
		"microseconds":   {rtt: 342 * time.Microsecond, want: "340µs"},
		"ascii is ascii": {rtt: 342 * time.Microsecond, charset: tree.ASCII, want: "340us"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := &trace.Trace{Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
				{Zone: ".", Server: trace.Server{Name: "ns."}, RTT: test.rtt, Rcode: "NOERROR", Kind: trace.KindAnswer},
			}}}

			var got bytes.Buffer
			if err := tree.Render(&got, tr, tree.Options{Charset: test.charset}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if !strings.Contains(got.String(), test.want) {
				t.Errorf("got %q, want it to carry %q", got.String(), test.want)
			}
		})
	}
}

func TestRenderNothing(t *testing.T) {
	tests := map[string]*trace.Trace{
		"nil trace":      nil,
		"no root":        {},
		"only a warning": {Warnings: []string{"nothing to see"}},
	}

	for name, tr := range tests {
		t.Run(name, func(t *testing.T) {
			var got bytes.Buffer
			if err := tree.Render(&got, tr, tree.Options{}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if tr != nil && len(tr.Warnings) > 0 {
				if !strings.Contains(got.String(), "warning: nothing to see") {
					t.Errorf("got %q, want the warning", got.String())
				}
				return
			}
			if got.Len() != 0 {
				t.Errorf("got %q, want nothing", got.String())
			}
		})
	}
}

func TestRenderUnknownCharset(t *testing.T) {
	if err := tree.Render(&bytes.Buffer{}, resolution(), tree.Options{Charset: "runes"}); err == nil {
		t.Error("got no error for an unknown charset, want one")
	}
}

func server(name, addr string, asn uint32) trace.Server {
	server := trace.Server{Name: name, IP: netip.MustParseAddr(addr), Port: 53}
	if asn > 0 {
		server.ASN = &trace.ASNInfo{Number: asn}
	}
	return server
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
		tb.Errorf("output does not match %s, run go test -update to see the change\n--- got ---\n%s\n--- want ---\n%s",
			golden, got, want)
	}
}
