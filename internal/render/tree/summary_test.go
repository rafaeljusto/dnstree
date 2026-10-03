package tree

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestSummary is the line a finished tree gets without anybody having watched
// the walk: what it cost is read back off the trace.
func TestSummary(t *testing.T) {
	tr := walk(2)
	tr.Root.Children[0].Children[0].Kind = trace.KindAnswer
	tr.Elapsed = 1500 * time.Millisecond

	// The second hop went to a server of its own, a third was only listed, and
	// a budget that ran out left a note that was never sent anywhere.
	tr.Root.Children[0].Children[0].Server.IP = netip.MustParseAddr("192.0.2.2")
	tr.Root.Children = append(tr.Root.Children, &trace.Step{
		Zone:   ".",
		Kind:   trace.KindSkipped,
		Server: trace.Server{IP: netip.MustParseAddr("192.0.2.3")},
	}, &trace.Step{
		Zone: ".",
		Kind: trace.KindError,
		Err:  "gave up after 2 queries",
	})

	var buf bytes.Buffer
	Summary(&buf, tr, Options{Color: ColorNever})

	for _, want := range []string{"answered in 1.5s", "2 queries", "2 servers"} {
		if got := buf.String(); !strings.Contains(got, want) {
			t.Errorf("got %q, want it to carry %q", got, want)
		}
	}
}

// TestSummaryTrial covers a walk of a zone moved by --try-ns, which has to read
// as a simulation on the line that says how the walk went.
func TestSummaryTrial(t *testing.T) {
	tr := walk(1)
	tr.Root.Children[0].Kind = trace.KindAnswer
	tr.Trial = &trace.Trial{Zone: "example.com.", NS: []string{"ns1.new.net.", "ns2.new.net."}}

	var buf bytes.Buffer
	Summary(&buf, tr, Options{Color: ColorNever})
	if want := "as though delegated to ns1.new.net., ns2.new.net."; !strings.Contains(buf.String(), want) {
		t.Errorf("got %q, want it to carry %q", buf.String(), want)
	}
}

// TestSummaryResolver is the comparison the line is there for: what the same
// question cost through a recursive server.
func TestSummaryResolver(t *testing.T) {
	tests := map[string]struct {
		resolver *trace.Resolver
		want     string
	}{
		"none was asked": {},
		"answered": {
			resolver: &trace.Resolver{Elapsed: 23 * time.Millisecond, Rcode: "NOERROR"},
			want:     "resolver in 23ms",
		},
		"a name that is not there is still an answer": {
			resolver: &trace.Resolver{Elapsed: 23 * time.Millisecond, Rcode: "NXDOMAIN"},
			want:     "resolver in 23ms",
		},
		"the resolver could not answer either": {
			resolver: &trace.Resolver{Elapsed: 30 * time.Millisecond, Rcode: "SERVFAIL"},
			want:     "resolver in 30ms (SERVFAIL)",
		},
		"the resolver said nothing at all": {
			resolver: &trace.Resolver{Err: "i/o timeout"},
			want:     "resolver did not answer",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := walk(1)
			tr.Root.Children[0].Kind = trace.KindAnswer
			tr.Elapsed = 1500 * time.Millisecond
			if test.resolver != nil {
				tr.Resolvers = []*trace.Resolver{test.resolver}
			}

			var buf bytes.Buffer
			Summary(&buf, tr, Options{Color: ColorNever})

			got := buf.String()
			switch {
			case test.want == "" && strings.Contains(got, "resolver"):
				t.Errorf("got %q, want nothing about a resolver nobody asked", got)
			case test.want != "" && !strings.Contains(got, test.want):
				t.Errorf("got %q, want it to carry %q", got, test.want)
			}
		})
	}
}

// TestSummaryASCII keeps the line to what the charset can draw: no mark, and
// fields set apart by something a terminal of any age has.
func TestSummaryASCII(t *testing.T) {
	tr := walk(1)
	tr.Root.Children[0].Kind = trace.KindAnswer
	tr.Elapsed = time.Second
	tr.Resolvers = []*trace.Resolver{{Elapsed: 5 * time.Millisecond, Rcode: "NOERROR"}}

	var buf bytes.Buffer
	Summary(&buf, tr, Options{Charset: ASCII, Color: ColorNever})

	got := buf.String()
	if want := "answered in 1s | resolver in 5ms | 1 query | 1 server\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, r := range got {
		if r > 127 {
			t.Errorf("got %q, want nothing but ASCII in it", got)
			break
		}
	}
}

// TestSummaryResolvers covers the line when the question was put to several
// places at once. What is worth the room then is not what each of them took but
// how far apart they were and how many of them disagreed.
func TestSummaryResolvers(t *testing.T) {
	answered := func(elapsed time.Duration, match trace.Match) *trace.Resolver {
		return &trace.Resolver{Elapsed: elapsed, Rcode: "NOERROR", Match: match}
	}

	tests := map[string]struct {
		resolvers []*trace.Resolver
		want      string
		avoid     string
	}{
		"all of them agreed, and the range is the whole of it": {
			resolvers: []*trace.Resolver{
				answered(12*time.Millisecond, trace.MatchSame),
				answered(41*time.Millisecond, trace.MatchSame),
			},
			want:  "resolvers in 12ms-41ms",
			avoid: "differ",
		},
		"the ones that disagreed are counted against the ones that were asked": {
			resolvers: []*trace.Resolver{
				answered(12*time.Millisecond, trace.MatchSame),
				answered(30*time.Millisecond, trace.MatchDiffers),
				answered(41*time.Millisecond, trace.MatchDiffers),
			},
			want: "resolvers in 12ms-41ms (2 of 3 differ)",
		},
		"one that said nothing is counted rather than left out": {
			resolvers: []*trace.Resolver{
				answered(12*time.Millisecond, trace.MatchSame),
				{Err: "i/o timeout"},
			},
			want: "resolvers in 12ms (1 did not answer)",
		},
		"none of them answering is still worth the room": {
			resolvers: []*trace.Resolver{{Err: "i/o timeout"}, {Err: "i/o timeout"}},
			want:      "2 resolvers did not answer",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := walk(1)
			tr.Root.Children[0].Kind = trace.KindAnswer
			tr.Elapsed = 1500 * time.Millisecond
			tr.Resolvers = test.resolvers

			var buf bytes.Buffer
			Summary(&buf, tr, Options{Color: ColorNever})

			got := buf.String()
			if !strings.Contains(got, test.want) {
				t.Errorf("got %q, want it to carry %q", got, test.want)
			}
			if test.avoid != "" && strings.Contains(got, test.avoid) {
				t.Errorf("got %q, want it not to say %q", got, test.avoid)
			}
		})
	}
}

// TestSummaryWithout covers --without: the verdict is about the DNS with those
// servers left out, and the line has to say so.
func TestSummaryWithout(t *testing.T) {
	tests := map[string]struct {
		answered bool
		without  []string
		want     string
	}{
		"nothing left out says nothing": {
			answered: true,
			want:     "answered in 1.5s · 1 query",
		},
		"an answer found without a nameserver": {
			answered: true,
			without:  []string{"ns1.example.com."},
			want:     "answered in 1.5s · without ns1.example.com. · 1 query",
		},
		"no answer without a network and a server": {
			without: []string{"192.0.2.0/24", "ns2.example.net."},
			want:    "no answer in 1.5s · without 192.0.2.0/24, ns2.example.net. · 1 query",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := walk(1)
			if test.answered {
				tr.Root.Children[0].Kind = trace.KindAnswer
			}
			tr.Elapsed = 1500 * time.Millisecond
			tr.Without = test.without

			var buf bytes.Buffer
			Summary(&buf, tr, Options{Color: ColorNever})
			if got := buf.String(); !strings.Contains(got, test.want) {
				t.Errorf("got %q, want it to carry %q", got, test.want)
			}
		})
	}
}
