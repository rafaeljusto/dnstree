package teach_test

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/render/teach"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/golden"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// resolution is the walk --format json writes as its golden.
func resolution(tb testing.TB) *trace.Trace {
	tb.Helper()

	file, err := os.Open(filepath.Join("..", "jsonout", "testdata", "resolution.golden"))
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()
	tr, err := jsonout.Read(file)
	if err != nil {
		tb.Fatal(err)
	}
	return tr
}

func TestRender(t *testing.T) {
	var got bytes.Buffer
	if err := teach.Render(&got, resolution(t)); err != nil {
		t.Fatalf("Render: %v", err)
	}
	golden.Compare(t, "resolution", got.String())
}

var asked = trace.Question{Name: "www.example.com.", Type: "A"}

func hop(zone, name, ip string, kind trace.StepKind, children ...*trace.Step) *trace.Step {
	return &trace.Step{Zone: zone, Server: trace.Server{Name: name, IP: netip.MustParseAddr(ip), Port: 53},
		Proto: "udp", Asked: asked, Kind: kind, Children: children}
}

func referral(zone, name, ip, to string, ns []string, children ...*trace.Step) *trace.Step {
	step := hop(zone, name, ip, trace.KindReferral, children...)
	glue := map[string][]netip.Addr{}
	for _, n := range ns {
		glue[n] = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	}
	step.Delegation = &trace.Delegation{Zone: to, NS: ns, Glue: glue, TTL: 172800}
	return step
}

func answer(name, ip string, children ...*trace.Step) *trace.Step {
	step := hop("example.com.", name, ip, trace.KindAnswer, children...)
	step.Flags.AA = true
	step.Records = []trace.RR{{Name: "www.example.com.", TTL: 300, Type: "A", Data: "192.0.2.80"}}
	return step
}

func walk(children ...*trace.Step) *trace.Trace {
	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: children},
	}
}

func TestRenderSays(t *testing.T) {
	com := []string{"a.gtld-servers.net."}
	example := []string{"ns1.example.com."}
	tests := map[string]struct {
		trace   *trace.Trace
		want    []string
		without []string
	}{
		"a server that timed out before the one that answered is told as tried first": {
			trace: walk(referral(".", "a.root-servers.net.", "198.41.0.4", "com.", com,
				hop("com.", "b.gtld-servers.net.", "192.33.14.30", trace.KindTimeout),
				referral("com.", "a.gtld-servers.net.", "192.5.6.30", "example.com.", example,
					answer("ns1.example.com.", "192.0.2.1"))),
			),
			want: []string{
				"first it asked b.gtld-servers.net. (192.33.14.30), which did not answer, so it moved on. then it asked a.gtld-servers.net. (192.5.6.30)",
				"that is the end of the walk: www.example.com. A is 192.0.2.80.",
			},
		},
		"a nameserver named outside the zone is found with a walk of its own": {
			trace: func() *trace.Trace {
				detour := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true, Notes: []string{"resolving ns.other.net."},
					Children: []*trace.Step{func() *trace.Step {
						step := hop("other.net.", "ns.other.net.", "192.0.2.9", trace.KindAnswer)
						step.Asked = trace.Question{Name: "ns.other.net.", Type: "A"}
						step.Records = []trace.RR{{Name: "ns.other.net.", TTL: 60, Type: "A", Data: "192.0.2.53"}}
						return step
					}()}}
				com := referral("com.", "a.gtld-servers.net.", "192.5.6.30", "example.com.", nil, detour)
				com.Delegation.NS = []string{"ns.other.net."}
				com.Delegation.OutOfBailiwick = []string{"ns.other.net."}
				com.Children = append(com.Children, answer("ns.other.net.", "192.0.2.53"))
				return walk(com)
			}(),
			want: []string{
				"it gave no address for ns.other.net., named outside example.com.: with no address for it, finding one takes a lookup of its own.",
				"it had to find the address of ns.other.net.: a walk of its own from the root, 1 query, which found 192.0.2.53.",
				"it asked ns.other.net. (192.0.2.53), the one server the referral named for example.com.",
			},
		},
		"a nameserver inside the zone with no glue is called a broken delegation": {
			trace: func() *trace.Trace {
				com := referral("com.", "a.gtld-servers.net.", "192.5.6.30", "example.com.", nil)
				com.Delegation.NS = []string{"ns1.example.com."}
				com.Delegation.GlueLess = []string{"ns1.example.com."}
				return walk(com)
			}(),
			want: []string{
				"ns1.example.com. is named inside example.com. yet came with no address",
				"that part of the delegation is broken.",
				"the walk ends without an answer for www.example.com. A.",
			},
		},
		"an alias starts the walk again at the root for its target": {
			trace: func() *trace.Trace {
				again := &trace.Step{Zone: ".", Kind: trace.KindZone, Notes: []string{"resolving web.example.net."},
					Children: []*trace.Step{func() *trace.Step {
						step := hop("example.net.", "ns.example.net.", "192.0.2.7", trace.KindAnswer)
						step.Asked = trace.Question{Name: "web.example.net.", Type: "A"}
						step.Records = []trace.RR{{Name: "web.example.net.", TTL: 60, Type: "A", Data: "192.0.2.81"}}
						return step
					}()}}
				alias := hop("example.com.", "ns1.example.com.", "192.0.2.1", trace.KindCNAME, again)
				alias.Records = []trace.RR{{Name: "www.example.com.", TTL: 300, Type: "CNAME", Data: "web.example.net."}}
				return walk(alias)
			}(),
			want: []string{
				"www.example.com. is an alias: example.com. answered with a CNAME record that points at web.example.net.",
				"so the walk starts again at the root for it.",
				"2. back at the root, it asked ns.example.net. (192.0.2.7) for web.example.net. A.",
				"www.example.com. A is 192.0.2.81, reached through 1 alias.",
			},
		},
		"a minimised hop says what came back is not the answer yet": {
			trace: func() *trace.Trace {
				root := referral(".", "a.root-servers.net.", "198.41.0.4", "com.", com)
				root.Minimised = true
				root.Asked = trace.Question{Name: "com.", Type: "A"}
				root.Notes = []string{"minimised to com."}
				return walk(root)
			}(),
			want:    []string{"it asked about com. alone, not the whole name", "not yet the answer."},
			without: []string{"it notes: minimised"},
		},
		"a broken chain of trust says a validating resolver refuses the answer": {
			trace: func() *trace.Trace {
				com := referral("com.", "a.gtld-servers.net.", "192.5.6.30", "example.com.", example, answer("ns1.example.com.", "192.0.2.1"))
				com.DNSSEC = &trace.DNSSECStatus{State: trace.Bogus, Zone: "example.com.", Reason: "no DNSKEY matches the DS"}
				return walk(com)
			}(),
			want: []string{
				"the chain of trust breaks at example.com.: no DNSKEY matches the DS. a validating resolver refuses these answers",
				"the chain of trust is broken, though",
			},
		},
		"a walk with no answer tells every server it asked": {
			trace: walk(
				hop(".", "a.root-servers.net.", "198.41.0.4", trace.KindTimeout),
				func() *trace.Step {
					step := hop(".", "b.root-servers.net.", "170.247.170.2", trace.KindLame)
					step.RTT = 20 * time.Millisecond
					return step
				}(),
			),
			want: []string{
				"1. dnstree starts at the root",
				"it did not answer.",
				"2. then it asked b.root-servers.net. (170.247.170.2)",
				"it answered, but not for the root: it does not serve the zone it was named for (a lame server).",
				"the walk ends without an answer",
			},
		},
		"the servers asked beside the one followed are counted by how they answered": {
			trace: walk(referral("com.", "a.gtld-servers.net.", "192.5.6.30", "example.com.", []string{"ns1.example.com.", "ns2.example.com.", "ns3.example.com."},
				answer("ns1.example.com.", "192.0.2.1"),
				answer("ns2.example.com.", "192.0.2.2"),
				hop("example.com.", "ns3.example.com.", "192.0.2.3", trace.KindTimeout),
			)),
			want: []string{"it put the same question to 2 more servers of example.com. as well, to hold them against each other: 1 answered and 1 did not answer."},
		},
		"a check's own lookups are left out of the story": {
			trace: func() *trace.Trace {
				apart := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true, Apart: true, Notes: []string{"resolving _dmarc.example.com."},
					Children: []*trace.Step{hop("example.com.", "ns9.example.com.", "192.0.2.99", trace.KindAnswer)}}
				return walk(answer("ns1.example.com.", "192.0.2.1", apart))
			}(),
			without: []string{"ns9.example.com.", "_dmarc"},
		},
		"the keys asked on the side are said in the hop that needed them": {
			trace: func() *trace.Trace {
				keys := hop(".", "a.root-servers.net.", "198.41.0.4", trace.KindAnswer)
				keys.Aside = true
				keys.Asked = trace.Question{Name: ".", Type: "DNSKEY"}
				keys.Notes = []string{"truncated over udp", "DNSKEY of ."}
				return walk(referral(".", "a.root-servers.net.", "198.41.0.4", "com.", com, keys))
			}(),
			want:    []string{"it also asked the same server for the keys of the root (DNSKEY)."},
			without: []string{"on the side: truncated"},
		},
		"a name off the wire cannot move the cursor": {
			trace: func() *trace.Trace {
				step := answer("ns1.example.com.", "192.0.2.1")
				step.Records[0].Data = "\x1b[2Kx"
				return walk(step)
			}(),
			want:    []string{`\027[2Kx`},
			without: []string{"\x1b"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var got bytes.Buffer
			if err := teach.Render(&got, tt.trace); err != nil {
				t.Fatalf("Render: %v", err)
			}
			// Sentences are wrapped, so they are looked for on one line.
			flat := strings.Join(strings.Fields(got.String()), " ")
			for _, want := range tt.want {
				if !strings.Contains(flat, want) {
					t.Errorf("got\n%s\nwant it to say\n%s", got.String(), want)
				}
			}
			for _, without := range tt.without {
				if strings.Contains(got.String(), without) {
					t.Errorf("got\n%s\nwant nothing of\n%s", got.String(), without)
				}
			}
		})
	}
}

func TestRenderWraps(t *testing.T) {
	var got bytes.Buffer
	if err := teach.Render(&got, resolution(t)); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for line := range strings.Lines(got.String()) {
		line = strings.TrimSuffix(line, "\n")
		if len(line) > 76 && strings.Contains(strings.TrimSpace(line), " ") {
			t.Errorf("a line runs past 76 columns: %q", line)
		}
	}
}

func TestRenderNothing(t *testing.T) {
	var got bytes.Buffer
	if err := teach.Render(&got, nil); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got.Len() != 0 {
		t.Errorf("a nil walk drew %q", got.String())
	}
}
