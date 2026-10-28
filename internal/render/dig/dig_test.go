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
