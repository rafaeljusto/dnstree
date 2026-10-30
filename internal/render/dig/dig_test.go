package dig_test

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/render/dig"
	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
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
	if err := dig.Render(&got, resolution(t)); err != nil {
		t.Fatalf("Render: %v", err)
	}
	golden.Compare(t, "resolution", got.String())
}

// TestRenderSaved covers a walk read back with --from, whose names the file
// holds escaped: the command has to ask for the octets the walk asked for, not
// for the escape.
func TestRenderSaved(t *testing.T) {
	document := `{"schema_version": 5, "question": {"name": "a\\000b.example.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
		"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "answer",
			"server": {"name": "a.root-servers.net.", "ip": "198.41.0.4"}, "proto": "udp",
			"asked": {"name": "a\\000b.example.", "type": "A"}}]}}`
	tr, err := jsonout.Read(strings.NewReader(document))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	var got bytes.Buffer
	if err := dig.Render(&got, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := "dig @198.41.0.4 'a\\000b.example.' A\n"; !strings.Contains(got.String(), want) {
		t.Errorf("got\n%s\nwant it to hold\n%s", got.String(), want)
	}
}

func TestRenderSays(t *testing.T) {
	server := trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 853}
	asked := trace.Question{Name: "example.com.", Type: "A"}
	tests := map[string]struct {
		step *trace.Step
		want string
	}{
		"a walk saved before the options were recorded says its commands carry none": {
			step: &trace.Step{Zone: ".", Server: server, Proto: "udp", Asked: asked, Kind: trace.KindAnswer},
			want: "# a query without options was saved before dnstree recorded what it sent\n",
		},
		"a cookie says which dig can send one": {
			step: &trace.Step{Zone: ".", Server: server, Proto: "udp", Asked: asked, Kind: trace.KindAnswer,
				Sent: &trace.Sent{EDNS: true, UDPSize: 1232, Cookie: true}},
			want: "# +cookie needs dig 9.11 or later\n",
		},
		"an encrypted transport says which dig can ask over it": {
			step: &trace.Step{Zone: ".", Server: server, Proto: "dot", Asked: asked, Kind: trace.KindAnswer,
				Sent: &trace.Sent{EDNS: true, UDPSize: 1232}},
			want: "# +tls and +https need dig 9.18 or later\n",
		},
		"a type a saved walk made up is not put on a command line": {
			step: &trace.Step{Zone: ".", Server: server, Proto: "udp", Kind: trace.KindAnswer,
				Asked: trace.Question{Name: "example.com.", Type: "-f/etc/passwd"}, Sent: &trace.Sent{EDNS: true, UDPSize: 1232}},
			want: "# no command: the type or class saved for it is not one dig reads as such\n",
		},
		"a class a saved walk made up is not put on a command line": {
			step: &trace.Step{Zone: ".", Server: server, Proto: "udp", Asked: asked, Kind: trace.KindAnswer,
				Sent: &trace.Sent{Class: "IN +tries=1", EDNS: true, UDPSize: 1232}},
			want: "# no command: the type or class saved for it is not one dig reads as such\n",
		},
		"a name saved with its octets escaped is asked as those octets": {
			step: &trace.Step{Zone: ".", Server: server, Proto: "udp", Kind: trace.KindAnswer,
				Asked: trace.Question{Name: "a\x00b.example.", Type: "A"}, Sent: &trace.Sent{EDNS: true, UDPSize: 1232}},
			want: "dig @192.0.2.53 -p 853 'a\\000b.example.' A",
		},
		"a query under a check's own lookup says whose it is": {
			step: &trace.Step{Zone: ".", Kind: trace.KindZone, Apart: true, Children: []*trace.Step{{
				Zone: "example.com.", Server: server, Proto: "dot", Asked: trace.Question{Name: "_dmarc.example.com.", Type: "TXT"},
				Kind: trace.KindAnswer, Sent: &trace.Sent{EDNS: true, UDPSize: 1232},
			}}},
			want: "# example.com. at 192.0.2.53: a check's own lookup, answer\n" +
				"dig @192.0.2.53 _dmarc.example.com. TXT +tls +norecurse +bufsize=1232\n",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := &trace.Trace{
				Question: asked,
				Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{test.step}},
			}
			var got bytes.Buffer
			if err := dig.Render(&got, tr); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if !strings.Contains(got.String(), test.want) {
				t.Errorf("got\n%s\nwant it to hold\n%s", got.String(), test.want)
			}
		})
	}
}
