package tree_test

import (
	"bytes"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/served"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func matched(name, qtype string, change func(*served.Match)) served.Match {
	answer := served.Answer{Kind: "answer"}
	match := served.Match{
		Question: trace.Question{Name: name, Type: qtype, Class: "IN"},
		Zone:     "example.com.", Servers: []string{"ns1.new.net.", "ns2.new.net."},
		Current: answer, Tried: answer,
	}
	if change != nil {
		change(&match)
	}
	return match
}

func TestCompared(t *testing.T) {
	tests := map[string]struct {
		matches []served.Match
		charset tree.Charset
		want    string
	}{
		"every way a copy can differ": {
			charset: tree.Unicode,
			matches: []served.Match{
				matched("www.example.com.", "A", nil),
				matched("example.com.", "MX", func(m *served.Match) {
					m.TTLs = []served.TTL{{Set: "example.com. MX", Current: 300, Tried: 86400}}
				}),
				matched("example.com.", "CAA", func(m *served.Match) {
					m.Tried.Kind = "nodata"
					m.Missing = []string{`example.com. CAA 0 issue "letsencrypt.org"`}
				}),
				matched("shop.example.com.", "A", func(m *served.Match) {
					m.Missing = []string{"shop.example.com. CNAME shops.example.net."}
					m.Extra = []string{"shop.example.com. A 192.0.2.7"}
				}),
				matched("old.example.com.", "A", func(m *served.Match) { m.Tried.Kind = "" }),
			},
			want: "example.com. at the servers it is delegated to, against ns1.new.net., ns2.new.net.: 5 questions\n" +
				"  www.example.com. A   same\n" +
				"  example.com. MX      ttl 300 → 86400\n" +
				`  example.com. CAA     nodata at the new servers, answer at the old; missing at the new servers: CAA 0 issue "letsencrypt.org"` + "\n" +
				"  shop.example.com. A  missing at the new servers: CNAME shops.example.net.; only at the new servers: A 192.0.2.7\n" +
				"  old.example.com. A   no answer at the new servers\n" +
				"1 the same, 4 differ · only the questions asked were compared\n",
		},
		"in ascii": {
			charset: tree.ASCII,
			matches: []served.Match{matched("example.com.", "MX", func(m *served.Match) {
				m.TTLs = []served.TTL{{Set: "example.com. MX", Current: 300, Tried: 86400}}
			})},
			want: "example.com. at the servers it is delegated to, against ns1.new.net., ns2.new.net.: 1 question\n" +
				"  example.com. MX  ttl 300 -> 86400\n" +
				"0 the same, 1 differs | only the questions asked were compared\n",
		},
		"servers that answer for none of it yet": {
			charset: tree.Unicode,
			matches: []served.Match{
				matched("www.example.com.", "A", func(m *served.Match) { m.Tried.Kind = "" }),
				matched("example.com.", "MX", func(m *served.Match) { m.Tried.Kind = "" }),
			},
			want: "example.com. at the servers it is delegated to, against ns1.new.net., ns2.new.net.: 2 questions\n" +
				"  the new servers answered none of them: they may not serve example.com. yet\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			tree.Compared(&out, test.matches, tree.Options{Charset: test.charset, Color: tree.ColorNever})
			if out.String() != test.want {
				t.Errorf("got\n%s\nwant\n%s", out.String(), test.want)
			}
			if test.charset == tree.ASCII {
				for _, r := range out.String() {
					if r > 127 {
						t.Fatalf("got %q in ascii output, want none", r)
					}
				}
			}
		})
	}
}

// TestComparedOwners covers records owned by another name than the one asked
// about, which keep their owner, a space inside a label included.
func TestComparedOwners(t *testing.T) {
	match := matched("www.example.com.", "A", func(m *served.Match) {
		m.Missing = []string{"www.example.com. CNAME a\\ b.example.com.", "a b.example.com. A 192.0.2.1"}
		m.TTLs = []served.TTL{{Set: "a b.example.com. A", Current: 300, Tried: 600}}
	})
	var out bytes.Buffer
	tree.Compared(&out, []served.Match{match}, tree.Options{Charset: tree.ASCII, Color: tree.ColorNever})
	want := `  www.example.com. A  missing at the new servers: CNAME a\ b.example.com., a b.example.com. A 192.0.2.1; a b.example.com. A ttl 300 -> 600` + "\n"
	if !bytes.Contains(out.Bytes(), []byte(want)) {
		t.Errorf("got\n%s\nwant a line\n%s", out.String(), want)
	}
}
