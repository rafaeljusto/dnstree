package tree_test

import (
	"bytes"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/served"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func filed(match served.Match, dangling ...*trace.Dangling) tree.FiledQuestion {
	walk := &trace.Trace{Question: match.Question, Root: &trace.Step{Kind: trace.KindZone}}
	for _, d := range dangling {
		walk.Root.Children = append(walk.Root.Children, &trace.Step{Kind: trace.KindNXDomain, Dangling: d})
	}
	return tree.FiledQuestion{Match: match, Walk: walk}
}

func TestFiled(t *testing.T) {
	alias := &trace.Dangling{Kind: trace.DanglingAlias, Name: "promo.example.com.",
		Target: "promo.s3.example.net.", Missing: "promo.s3.example.net.", Zone: "s3.example.net."}
	tests := map[string]struct {
		filing    tree.Filing
		questions []tree.FiledQuestion
		charset   tree.Charset
		want      string
	}{
		"every way a file and its servers can differ": {
			filing:  tree.Filing{Path: "db.example", Zone: "example.com.", Names: 5, Wildcards: 2, Escaped: 1, Unaskable: 1},
			charset: tree.Unicode,
			questions: []tree.FiledQuestion{
				filed(matched("www.example.com.", "A", nil)),
				filed(matched("mail.example.com.", "A", func(m *served.Match) {
					m.Missing = []string{"mail.example.com. A 192.0.2.25"}
					m.Extra = []string{"mail.example.com. A 192.0.2.26"}
				})),
				filed(matched("example.com.", "MX", func(m *served.Match) {
					m.TTLs = []served.TTL{{Set: "example.com. MX", Current: 3600, Tried: 300}}
				})),
				filed(matched("old.example.com.", "TXT", func(m *served.Match) {
					m.Tried = served.Answer{Kind: "nxdomain"}
					m.Missing = []string{`old.example.com. TXT "v=1"`}
				})),
				filed(matched("promo.example.com.", "A", nil), alias, alias),
				filed(matched("gone.example.com.", "A", func(m *served.Match) { m.Tried = served.Answer{} })),
			},
			want: "example.com. from db.example, against its servers: 5 names, 6 questions; not asked: 2 wildcards, 1 name with an escape, 1 set of a type this build cannot ask\n" +
				"  www.example.com. A    same\n" +
				"  mail.example.com. A   only in the file: A 192.0.2.25; only at the servers: A 192.0.2.26\n" +
				"  example.com. MX       ttl 3600 in the file, 300 at the servers\n" +
				"  old.example.com. TXT  nxdomain at the servers\n" +
				"  promo.example.com. A  same; dangling alias: promo.s3.example.net. is missing\n" +
				"  gone.example.com. A   no answer from the servers\n" +
				"2 the same, 4 differ, 1 dangling · serials are not compared\n",
		},
		"in ascii, with nothing left out": {
			filing:    tree.Filing{Path: "db.example", Zone: "example.com.", Names: 1},
			charset:   tree.ASCII,
			questions: []tree.FiledQuestion{filed(matched("www.example.com.", "A", nil))},
			want: "example.com. from db.example, against its servers: 1 name, 1 question\n" +
				"  www.example.com. A  same\n" +
				"1 the same, 0 differ | serials are not compared\n",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			tree.Filed(&out, test.filing, test.questions, tree.Options{Charset: test.charset, Color: tree.ColorNever})
			if out.String() != test.want {
				t.Errorf("got\n%s\nwant\n%s", out.String(), test.want)
			}
		})
	}
}
