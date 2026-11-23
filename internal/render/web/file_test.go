package web_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

var opts = web.Options{Version: "v0.1.0", Now: time.Date(2026, 11, 23, 14, 2, 11, 0, time.UTC)}

func TestFile(t *testing.T) {
	var out bytes.Buffer
	if err := web.File(&out, resolution(), nil, opts); err != nil {
		t.Fatalf("File: %v", err)
	}
	document := out.String()

	tests := map[string]func(t *testing.T){
		"nothing is fetched from outside the file": func(t *testing.T) {
			if strings.Contains(document, " src=") {
				t.Error("got a src attribute, want every script inline")
			}
			for _, href := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(document, -1) {
				switch link := href[1]; {
				case strings.HasPrefix(link, "#"), strings.HasPrefix(link, "data:"):
				case link == "/", link == "trace.json": // the page takes these over when it reads a carried walk
				default:
					t.Errorf("got href %q, want nothing outside the file", link)
				}
			}
		},
		"the walk it carries is the one the served page reads": func(t *testing.T) {
			page, _, err := web.Payload(resolution(), nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			if !sameJSON(t, carried(t, document), page) {
				t.Errorf("got\n%s\nwant\n%s", carried(t, document), page)
			}
		},
		"walk.js is reached through the import map": func(t *testing.T) {
			if !strings.Contains(document, `{"imports":{"./walk.js":"data:text/javascript;base64,`) {
				t.Error("got no import map for walk.js")
			}
		},
	}
	for name, test := range tests {
		t.Run(name, test)
	}
}

// The page goes inline as it is, so it must hold nothing that would end the
// block it is put in.
func TestFileAssetsInline(t *testing.T) {
	for name, closer := range map[string]string{"app.js": "</script", "app.css": "</style"} {
		raw, err := os.ReadFile("assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		for _, bad := range []string{closer, "<!--"} {
			if strings.Contains(strings.ToLower(body), bad) {
				t.Errorf("%s holds %q, which ends the block it is inlined in", name, bad)
			}
		}
	}
}

// FuzzFile holds that what a DNS server wrote never leaves the block the walk
// is carried in, and comes back out of it as it went in.
func FuzzFile(f *testing.F) {
	f.Add("www.example.com.", "192.0.2.1")
	f.Add("</script><script>alert(1)</script>.", `"</SCRIPT ><!--`)
	f.Add(" .", "<!-- <script>")
	f.Fuzz(func(t *testing.T, name, data string) {
		tr := resolution()
		tr.Question.Name = name
		tr.Root.Records = []trace.RR{{Name: name, Type: "TXT", Data: data}}

		var out bytes.Buffer
		if err := web.File(&out, tr, nil, opts); err != nil {
			t.Fatalf("File: %v", err)
		}
		document := strings.ToLower(out.String())
		if got := strings.Count(document, "<script"); got != 3 {
			t.Fatalf("got %d <script tags, want 3", got)
		}
		if got := strings.Count(document, "</script"); got != 3 {
			t.Fatalf("got %d </script tags, want 3", got)
		}

		page, _, err := web.Payload(tr, nil, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !sameJSON(t, carried(t, out.String()), page) {
			t.Fatalf("got\n%s\nwant\n%s", carried(t, out.String()), page)
		}
	})
}

func carried(t *testing.T, document string) []byte {
	t.Helper()
	const open = `<script type="application/json" id="walk">`
	_, rest, ok := strings.Cut(document, open)
	if !ok {
		t.Fatal("got no walk carried in the file")
	}
	block, _, ok := strings.Cut(rest, "</script>")
	if !ok {
		t.Fatal("got a walk block that is never closed")
	}
	return []byte(block)
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("the carried walk is not JSON: %v", err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}
