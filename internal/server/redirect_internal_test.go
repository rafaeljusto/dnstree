package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	pathpkg "path"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
)

// FuzzRedirect sends the form, and an address typed by hand, with whatever a
// stranger puts in them. A redirect that comes back stays on this server, and
// lands on the address of one walk, which a browser following it is never
// sent on from again.
func FuzzRedirect(f *testing.F) {
	f.Add("www.example.com", "a", "3d")
	f.Add("  WWW.Example.COM. ", "aaaa", "tree")
	f.Add("bücher.example", "TXT", "")
	f.Add(`\evil.example`, "A", "x")
	f.Add("a/../../b", "MX", "3d")
	f.Add("%2e%2e.example", "A", "tree")
	f.Fuzz(func(t *testing.T, name, qtype, view string) {
		s := &Server{pages: map[bool]http.Handler{false: web.Files(false), true: web.Files(true)}}
		s.routes()

		form := "/walk?" + url.Values{"name": {name}, "type": {qtype}, "view": {view}}.Encode()
		typed := "/" + url.PathEscape(view) + "/" + url.PathEscape(name) + "/" + url.PathEscape(qtype)
		for _, target := range []string{form, typed} {
			r, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				continue
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code < 300 || w.Code > 399 {
				continue
			}
			// The mux sends a path with a . or .. in it to its clean form
			// before any handler sees it, which has only to stay on this server.
			landed(t, target, w.Header().Get("Location"), pathpkg.Clean(r.URL.Path) == r.URL.Path)
		}
	})
}

// landed checks where a redirect sends a browser: a path on this server, which
// drawn takes as the address of a walk as it stands.
func landed(t *testing.T, from, location string, walk bool) {
	t.Helper()
	to, err := url.Parse(location)
	if err != nil || to.Scheme != "" || to.Host != "" || to.Opaque != "" ||
		!strings.HasPrefix(location, "/") || strings.HasPrefix(location, "//") || strings.ContainsAny(location, `\`) {
		t.Fatalf("%q sends a browser to %q, off this server", from, location)
	}
	if !walk {
		return
	}

	var view, name, qtype, file string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{view}/{name}/{type}/{file...}", func(_ http.ResponseWriter, r *http.Request) {
		view, name, qtype, file = r.PathValue("view"), r.PathValue("name"), r.PathValue("type"), r.PathValue("file")
	})
	r, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		t.Fatalf("%q sends a browser to %q, which is no request: %v", from, location, err)
	}
	mux.ServeHTTP(httptest.NewRecorder(), r)

	if _, ok := views[view]; !ok || file != "" || !slices.Contains(Types, qtype) {
		t.Fatalf("%q sends a browser to %q, which is no walk's address", from, location)
	}
	if again, ok := canonical(name); !ok || again != name {
		t.Fatalf("%q sends a browser to %q, which sends it on to %q", from, location, again)
	}
}
