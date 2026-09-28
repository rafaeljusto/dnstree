package server_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/server"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

const (
	rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
`

	comZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns.example
ns.example IN A 192.0.2.3
`

	exampleZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.3
www   IN A    192.0.2.10
`
)

// internet is a root, com and example.com, and the server serving it. allow is
// which of the declared addresses a walk may send to.
func internet(t *testing.T, allow func(netip.Addr) bool, cfg server.Config) (*server.Server, *fakens.Server) {
	t.Helper()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	example := hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3"})

	carrier := transport.Config{Timeout: 200 * time.Millisecond}
	cfg.Roots = []trace.Server{root.Nameserver()}
	cfg.Transport = hierarchy.Transport(transport.NewUDP(carrier))
	cfg.TCP = hierarchy.Transport(transport.NewTCP(carrier))
	cfg.Allow = allow

	served, err := server.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return served, example
}

func anywhere(netip.Addr) bool { return true }

func get(t *testing.T, h http.Handler, path string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.RemoteAddr = "198.51.100.7:40000"
	for name, values := range header {
		request.Header[name] = values
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	return recorder
}

func TestRoutes(t *testing.T) {
	served, _ := internet(t, anywhere, server.Config{})

	tests := map[string]struct {
		path        string
		wantStatus  int
		wantType    string
		wantContent string
		wantAt      string
	}{
		"the form": {
			path: "/", wantStatus: http.StatusOK, wantType: "text/html; charset=utf-8", wantContent: `<form action="walk"`,
		},
		"the form sent on to where its walk is drawn": {
			path: "/walk?name=WWW.Example.COM.&type=a&view=3d", wantStatus: http.StatusSeeOther,
			wantAt: "/3d/www.example.com/A/",
		},
		"a view nobody asked for drawn in 3d": {
			path: "/walk?name=www.example.com&type=A", wantStatus: http.StatusSeeOther, wantAt: "/3d/www.example.com/A/",
		},
		"the tree asked for": {
			path: "/walk?name=www.example.com&type=A&view=tree", wantStatus: http.StatusSeeOther,
			wantAt: "/tree/www.example.com/A/",
		},
		"a name typed in another script, sent on in punycode": {
			path: "/walk?name=B%C3%BCcher.example&type=A", wantStatus: http.StatusSeeOther,
			wantAt: "/3d/xn--bcher-kva.example/A/",
		},
		"a name with underscores left as it is": {
			path: "/walk?name=_25._tcp.mail.example.com&type=TLSA", wantStatus: http.StatusSeeOther,
			wantAt: "/3d/_25._tcp.mail.example.com/TLSA/",
		},
		"a name no script can spell": {
			path: "/walk?name=%E2%80%AEexample.com&type=A", wantStatus: http.StatusBadRequest,
		},
		"a type the form does not offer": {
			path: "/walk?name=www.example.com&type=AXFR", wantStatus: http.StatusBadRequest,
			wantContent: "not one of the types",
		},
		"no name at all": {path: "/walk?name=&type=A", wantStatus: http.StatusBadRequest},
		"the root, which a path cannot carry": {
			path: "/walk?name=.&type=NS", wantStatus: http.StatusBadRequest,
		},
		"the scene": {
			path: "/3d/www.example.com/A/", wantStatus: http.StatusOK, wantType: "text/html; charset=utf-8",
			wantContent: `<canvas id="scene"`,
		},
		"the tree": {
			path: "/tree/www.example.com/A/", wantStatus: http.StatusOK, wantContent: "<dns-tree",
		},
		"an address spelled another way, sent on to the walk's own": {
			path: "/3d/WWW.Example.COM./a/", wantStatus: http.StatusMovedPermanently, wantAt: "/3d/www.example.com/A/",
		},
		"an address in another script, sent on in punycode": {
			path: "/tree/b%c3%bccher.example/A/", wantStatus: http.StatusMovedPermanently,
			wantAt: "/tree/xn--bcher-kva.example/A/",
		},
		"an address without the slash": {
			path: "/3d/www.example.com/A", wantStatus: http.StatusMovedPermanently, wantAt: "/3d/www.example.com/A/",
		},
		"a name typed in another script, walked in punycode": {
			path: "/3d/b%C3%BCcher.example/A/page.json", wantStatus: http.StatusOK, wantContent: `"xn--bcher-kva.example."`,
		},
		"what draws the scene": {
			path: "/3d/www.example.com/A/scene.js", wantStatus: http.StatusOK,
			wantType: "text/javascript; charset=utf-8", wantContent: `getContext("webgl2"`,
		},
		"what draws the tree": {
			path: "/tree/www.example.com/A/app.js", wantStatus: http.StatusOK, wantType: "text/javascript; charset=utf-8",
		},
		"the walk the scene reads": {
			path: "/3d/www.example.com/A/page.json", wantStatus: http.StatusOK,
			wantType: "application/json; charset=utf-8", wantContent: `"www.example.com."`,
		},
		"the walk on its own": {
			path: "/3d/www.example.com/A/trace.json", wantStatus: http.StatusOK, wantContent: `"schema_version"`,
		},
		"the icon":               {path: "/mark.svg", wantStatus: http.StatusOK, wantType: "image/svg+xml"},
		"a view that is not one": {path: "/2d/www.example.com/A/", wantStatus: http.StatusNotFound},
		"a file that is not one": {path: "/3d/www.example.com/A/etc/passwd", wantStatus: http.StatusNotFound},
		"a type in the path the form does not offer": {
			path: "/3d/www.example.com/ANY/", wantStatus: http.StatusBadRequest,
		},
		"a name the resolver will not walk": {
			path: "/3d/" + strings.Repeat("a", 70) + ".com/A/", wantStatus: http.StatusBadRequest,
		},
		"the health check": {path: "/healthz", wantStatus: http.StatusOK, wantContent: "ok"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := get(t, served, test.path, nil)
			if got.Code != test.wantStatus {
				t.Fatalf("got %d, want %d: %.300s", got.Code, test.wantStatus, got.Body.String())
			}
			if test.wantType != "" {
				if contentType := got.Header().Get("Content-Type"); contentType != test.wantType {
					t.Errorf("got %q, want %q", contentType, test.wantType)
				}
			}
			if !strings.Contains(got.Body.String(), test.wantContent) {
				t.Errorf("got %.300q, want %q in it", got.Body.String(), test.wantContent)
			}
			if test.wantAt != "" {
				if at := got.Header().Get("Location"); at != test.wantAt {
					t.Errorf("got sent to %q, want %q", at, test.wantAt)
				}
			}
		})
	}
}

// TestGlueNotFollowedOffTheInternet covers a zone that hands out glue on the
// network the server runs on: the walk says so, and nothing is sent there.
func TestGlueNotFollowedOffTheInternet(t *testing.T) {
	private := netip.MustParseAddr("192.0.2.3")
	served, example := internet(t, func(addr netip.Addr) bool { return addr != private }, server.Config{})

	got := get(t, served, "/3d/www.example.com/A/page.json", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("got %d, want the walk drawn anyway: %s", got.Code, got.Body.String())
	}
	if !strings.Contains(got.Body.String(), "192.0.2.3 is not a public address") {
		t.Errorf("got %.500s, want the refused hop recorded", got.Body.String())
	}
	if queries := example.Queries(); len(queries) != 0 {
		t.Errorf("got %d queries at the private address, want none", len(queries))
	}
}

// TestWalkKept covers the page asking for the walk it was just served beside.
func TestWalkKept(t *testing.T) {
	served, example := internet(t, anywhere, server.Config{})

	get(t, served, "/3d/www.example.com/A/", nil)
	asked := len(example.Queries())
	if asked == 0 {
		t.Fatal("got no queries at example.com, want the first walk to reach it")
	}
	for _, path := range []string{"/3d/www.example.com/A/page.json", "/tree/WWW.example.com./A/trace.json"} {
		if got := get(t, served, path, nil); got.Code != http.StatusOK {
			t.Fatalf("%s: got %d", path, got.Code)
		}
	}
	if again := len(example.Queries()); again != asked {
		t.Errorf("got %d queries, want the %d of the first walk and no more", again, asked)
	}
}

func TestPerClient(t *testing.T) {
	served, _ := internet(t, anywhere, server.Config{PerClient: 1, ClientHeader: "Fly-Client-IP"})

	first := http.Header{"Fly-Client-Ip": {"2001:db8:1:2::1"}}
	same := http.Header{"Fly-Client-Ip": {"2001:db8:1:2::99"}} // the same /64
	other := http.Header{"Fly-Client-Ip": {"203.0.113.9"}}

	if got := get(t, served, "/3d/www.example.com/A/", first); got.Code != http.StatusOK {
		t.Fatalf("got %d for the first walk, want it made", got.Code)
	}
	if got := get(t, served, "/3d/www.example.com/A/page.json", same); got.Code != http.StatusOK {
		t.Errorf("got %d for a walk already made, want it served without counting", got.Code)
	}
	if got := get(t, served, "/3d/example.com/NS/", same); got.Code != http.StatusTooManyRequests {
		t.Errorf("got %d for another walk from the same network, want %d", got.Code, http.StatusTooManyRequests)
	}
	if got := get(t, served, "/3d/example.com/SOA/", other); got.Code != http.StatusOK {
		t.Errorf("got %d for somebody else, want the walk made", got.Code)
	}
}

func TestFormOffersEveryType(t *testing.T) {
	served, _ := internet(t, anywhere, server.Config{})
	body := get(t, served, "/", nil).Body.String()
	for _, qtype := range server.Types {
		if !strings.Contains(body, "<option>"+qtype+"</option>") {
			t.Errorf("got no %s in the form, want every type the server walks offered", qtype)
		}
	}
}

func TestFailureEscapesTheMessage(t *testing.T) {
	served, _ := internet(t, anywhere, server.Config{})
	got := get(t, served, "/walk?name=<b>&type=<script>", nil)
	if strings.Contains(got.Body.String(), "<script>") {
		t.Errorf("got %s, want nothing from the request in the page", got.Body.String())
	}
}
