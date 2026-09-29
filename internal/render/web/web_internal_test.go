package web

import (
	"bytes"
	"encoding/json"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// walked is a resolution with the things the page draws differently: a referral
// that was signed, an answer under it, and an aside beside it.
func walked() *trace.Trace {
	answer := &trace.Step{
		Zone:    "example.com.",
		Server:  trace.Server{Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53"), Port: 53},
		Proto:   "udp",
		RTT:     9 * time.Millisecond,
		Rcode:   "NOERROR",
		Flags:   trace.Flags{AA: true},
		Kind:    trace.KindAnswer,
		DNSSEC:  &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.", Algorithm: "ECDSAP256SHA256"},
		Records: []trace.RR{{Name: "www.example.com.", TTL: 3600, Type: "A", Data: "93.184.216.34"}},
		Children: []*trace.Step{{
			Zone:   "example.com.",
			Server: trace.Server{Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53")},
			Kind:   trace.KindAnswer,
			Aside:  true,
			Notes:  []string{"DNSKEY of example.com."},
		}},
	}
	referral := &trace.Step{
		Zone:       "com.",
		Server:     trace.Server{Name: "a.gtld-servers.net.", IP: netip.MustParseAddr("192.5.6.30"), Port: 53},
		Proto:      "udp",
		RTT:        18 * time.Millisecond,
		Rcode:      "NOERROR",
		Kind:       trace.KindReferral,
		Delegation: &trace.Delegation{Zone: "example.com.", NS: []string{"a.iana-servers.net."}, DSPresent: true},
		Children:   []*trace.Step{answer},
	}
	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Elapsed:  40 * time.Millisecond,
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{referral}},
	}
}

// TestBuildDatesTheWalk covers a walk drawn again from a file: the page says
// when the walk was made, not when it was served.
func TestBuildDatesTheWalk(t *testing.T) {
	tr := walked()
	tr.Started = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

	page, _, err := build(tr, nil, Options{Now: time.Date(2026, 9, 21, 10, 30, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var document struct {
		Page struct {
			Generated string `json:"generated"`
		} `json:"page"`
	}
	if err := json.Unmarshal(page, &document); err != nil {
		t.Fatalf("the page is not JSON: %v", err)
	}
	if want := tr.Started.Format(time.RFC3339); document.Page.Generated != want {
		t.Errorf("got %q, want the walk dated %s", document.Page.Generated, want)
	}
}

func TestBuild(t *testing.T) {
	findings := []explain.Finding{
		{Topic: explain.Outcome, Level: explain.Note, Text: "www.example.com A is 93.184.216.34"},
		{Topic: explain.Trust, Level: explain.Fault, Text: "the chain of trust is broken"},
	}
	when := time.Date(2026, 9, 21, 10, 30, 0, 0, time.UTC)

	page, traceDoc, err := build(walked(), findings, Options{Version: "v1.2.3", Now: when})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var document struct {
		Page struct {
			Version   string `json:"version"`
			Generated string `json:"generated"`
		} `json:"page"`
		Trace struct {
			SchemaVersion int `json:"schema_version"`
			Question      struct {
				Name string `json:"name"`
			} `json:"question"`
		} `json:"trace"`
		Findings []finding `json:"findings"`
	}
	if err := json.Unmarshal(page, &document); err != nil {
		t.Fatalf("the page is not JSON: %v\n%s", err, page)
	}

	if document.Page.Version != "v1.2.3" {
		t.Errorf("got version %q, want the one it was built with", document.Page.Version)
	}
	if document.Page.Generated != when.Format(time.RFC3339) {
		t.Errorf("got %q, want the walk dated %s", document.Page.Generated, when.Format(time.RFC3339))
	}
	if document.Trace.SchemaVersion == 0 || document.Trace.Question.Name != "www.example.com." {
		t.Errorf("got %+v, want the walk inside the page", document.Trace)
	}

	want := []finding{
		{Topic: "outcome", Level: "note", Text: "www.example.com A is 93.184.216.34"},
		{Topic: "trust", Level: "fault", Text: "the chain of trust is broken"},
	}
	if len(document.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d", len(document.Findings), len(want))
	}
	for i, found := range document.Findings {
		if found != want[i] {
			t.Errorf("got %+v, want %+v", found, want[i])
		}
	}

	// The walk on its own is a document of its own, not a fragment of this one.
	var alone map[string]any
	if err := json.Unmarshal(traceDoc, &alone); err != nil {
		t.Fatalf("the trace is not JSON on its own: %v", err)
	}
}

// TestBuildNothing covers the run that found nothing at all: there is always a
// page, because a failure is something to look at too.
func TestBuildNothing(t *testing.T) {
	page, _, err := build(nil, nil, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !json.Valid(page) {
		t.Errorf("got %s, want a page", page)
	}
}

// TestHandler covers what each page serves: its own files, the same walk
// behind both, and none of the other page's files.
func TestHandler(t *testing.T) {
	page, traceDoc, err := build(walked(), nil, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	tests := map[string]struct {
		pages       site
		path        string
		wantStatus  int
		wantType    string
		wantContent string
	}{
		"the page itself": {
			pages: flat, path: "/", wantStatus: http.StatusOK,
			wantType: "text/html; charset=utf-8", wantContent: "<title>dnstree</title>",
		},
		"what it is drawn with": {
			pages: flat, path: "/app.css", wantStatus: http.StatusOK, wantType: "text/css; charset=utf-8", wantContent: "@layer",
		},
		"what draws it": {
			pages: flat, path: "/app.js", wantStatus: http.StatusOK, wantType: "text/javascript; charset=utf-8", wantContent: "customElements",
		},
		"the walk the page reads": {
			pages: flat, path: "/page.json", wantStatus: http.StatusOK,
			wantType: "application/json; charset=utf-8", wantContent: `"schema_version"`,
		},
		"the walk on its own": {
			pages: flat, path: "/trace.json", wantStatus: http.StatusOK,
			wantType: "application/json; charset=utf-8", wantContent: `"www.example.com."`,
		},
		"nothing else is served": {pages: flat, path: "/etc/passwd", wantStatus: http.StatusNotFound},
		"not even the directory": {pages: flat, path: "/assets/app.js", wantStatus: http.StatusNotFound},
		"not the scene's files":  {pages: flat, path: "/scene.js", wantStatus: http.StatusNotFound},

		"the scene itself": {
			pages: scene, path: "/", wantStatus: http.StatusOK,
			wantType: "text/html; charset=utf-8", wantContent: `<canvas id="scene"`,
		},
		"what the scene is laid over": {
			pages: scene, path: "/scene.css", wantStatus: http.StatusOK, wantType: "text/css; charset=utf-8", wantContent: "@layer",
		},
		"what draws the scene": {
			pages: scene, path: "/scene.js", wantStatus: http.StatusOK,
			wantType: "text/javascript; charset=utf-8", wantContent: `getContext("webgl2"`,
		},
		"the walk the scene reads": {
			pages: scene, path: "/page.json", wantStatus: http.StatusOK,
			wantType: "application/json; charset=utf-8", wantContent: `"schema_version"`,
		},
		"the walk on its own, beside the scene": {
			pages: scene, path: "/trace.json", wantStatus: http.StatusOK,
			wantType: "application/json; charset=utf-8", wantContent: `"www.example.com."`,
		},
		"the icon the landing page wears": {
			pages: flat, path: "/mark.svg", wantStatus: http.StatusOK, wantType: "image/svg+xml", wantContent: "<svg",
		},
		"the same icon beside the scene": {
			pages: scene, path: "/mark.svg", wantStatus: http.StatusOK, wantType: "image/svg+xml", wantContent: "<svg",
		},
		"the icon an old browser asks for": {
			pages: scene, path: "/favicon.ico", wantStatus: http.StatusOK, wantType: "image/x-icon",
		},
		"the icon a phone asks for": {
			pages: flat, path: "/apple-touch-icon.png", wantStatus: http.StatusOK, wantType: "image/png", wantContent: "PNG",
		},
		"not the flat page's files":      {pages: scene, path: "/app.js", wantStatus: http.StatusNotFound},
		"not even the scene's directory": {pages: scene, path: "/assets/scene/scene.js", wantStatus: http.StatusNotFound},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+test.path, nil)
			recorder := httptest.NewRecorder()
			handler(test.pages, page, traceDoc).ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("got %d, want %d", recorder.Code, test.wantStatus)
			}
			if test.wantStatus != http.StatusOK {
				return
			}
			if got := recorder.Header().Get("Content-Type"); got != test.wantType {
				t.Errorf("got %q, want %q", got, test.wantType)
			}
			if got := recorder.Body.String(); !strings.Contains(got, test.wantContent) {
				t.Errorf("got %.200q, want %q in it", got, test.wantContent)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("got %q, want the page kept nowhere", got)
			}
		})
	}
}

// TestSiteFor covers which page Options ask for.
func TestSiteFor(t *testing.T) {
	if got := siteFor(Options{}); got.dir != flat.dir {
		t.Errorf("got %s, want the flat page by default", got.dir)
	}
	if got := siteFor(Options{Scene: true}); got.dir != scene.dir {
		t.Errorf("got %s, want the scene when it is asked for", got.dir)
	}
}

// TestHandlerOnlyByAddress covers the one thing a page on loopback still has to
// defend: a browser sent here by a name somebody else owns.
func TestHandlerOnlyByAddress(t *testing.T) {
	page, traceDoc, err := build(walked(), nil, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	served := handler(flat, page, traceDoc)

	tests := map[string]int{
		"127.0.0.1:8080":             http.StatusOK,
		"[::1]:8080":                 http.StatusOK,
		"localhost:8080":             http.StatusOK,
		"192.0.2.10:8080":            http.StatusOK, // --web-addr was asked for; it is an address
		"dns.example:8080":           http.StatusForbidden,
		"localhost.attacker.example": http.StatusForbidden,
	}

	for host, want := range tests {
		t.Run(host, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Host = host
			recorder := httptest.NewRecorder()
			served.ServeHTTP(recorder, request)

			if recorder.Code != want {
				t.Errorf("got %d for %q, want %d", recorder.Code, host, want)
			}
		})
	}
}

func TestListening(t *testing.T) {
	tests := map[string]struct {
		addr netip.AddrPort
		want string
	}{
		"where it was bound":    {netip.MustParseAddrPort("127.0.0.1:8080"), "127.0.0.1:8080"},
		"an address of its own": {netip.MustParseAddrPort("192.0.2.10:9000"), "192.0.2.10:9000"},
		"everything, over v4":   {netip.MustParseAddrPort("0.0.0.0:8080"), "127.0.0.1:8080"},
		"everything, over v6":   {netip.MustParseAddrPort("[::]:8080"), "[::1]:8080"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tcp := &net.TCPAddr{IP: test.addr.Addr().AsSlice(), Port: int(test.addr.Port())}
			if got := listening(tcp).String(); got != test.want {
				t.Errorf("got %s, want %s", got, test.want)
			}
		})
	}
}

// TestIconsMatchDocs keeps the icons in the binary the ones the landing page
// wears: the copies are there only because go:embed cannot reach docs.
func TestIconsMatchDocs(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(icons)) {
		want, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", name))
		if err != nil {
			t.Fatalf("docs/%s: %v", name, err)
		}
		got, err := assets.ReadFile("assets/" + name)
		if err != nil {
			t.Fatalf("assets/%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("assets/%s differs from docs/%s, want the landing page's icon: cp docs/%s internal/render/web/assets/", name, name, name)
		}
	}
}

// TestPagesFetchNothing holds both pages to what the guide says of them: the
// page is in the binary, and nothing it is made of is fetched from anywhere.
// The only address either may name is the one SVG is written in.
func TestPagesFetchNothing(t *testing.T) {
	address := regexp.MustCompile(`(?i)(https?:)?//[a-z0-9.-]+\.[a-z]{2,}`)
	for _, pages := range []site{flat, scene} {
		for _, name := range append(slices.Sorted(maps.Keys(pages.files)), "index.html") {
			body, err := assets.ReadFile(pages.dir + "/" + name)
			if err != nil {
				t.Fatalf("%s/%s: %v", pages.dir, name, err)
			}
			for _, found := range address.FindAllString(string(body), -1) {
				if !strings.HasSuffix(found, "//www.w3.org") {
					t.Errorf("%s/%s names %s, want nothing fetched", pages.dir, name, found)
				}
			}
		}
	}
}
