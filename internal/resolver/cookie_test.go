package resolver_test

import (
	"slices"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// cookieService is the hierarchy of service, with a hold on the leaf server so
// that a test can read what it was sent.
func cookieService(tb testing.TB, cookies fakens.Cookies) (harness, resolver.Config, *fakens.Server) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: serviceRootZone, Declared: "192.0.2.1",
	})
	leaf := hierarchy.Add(fakens.Config{
		Name: "ns.test.", Origin: "test.", Zone: serviceZone, Declared: "192.0.2.5",
		Behaviour: fakens.Behaviour{Cookies: cookies},
	})
	return harness{hierarchy, root}, resolver.Config{Cookie: true}, leaf
}

// askedLeaf is the hop that put the question to the leaf server.
func askedLeaf(tb testing.TB, tr *trace.Trace) *trace.Step {
	tb.Helper()
	for _, step := range steps(tr) {
		if step.Server.IP.String() == "192.0.2.5" && step.Asked.Name == "www.test." {
			return step
		}
	}
	tb.Fatalf("got no hop to the leaf server: %s", format(steps(tr)))
	return nil
}

// TestCookieIsRecorded covers each way a server can answer a cookie. Only the
// one that answers without is allowed to be quiet about it; the rest are
// servers getting it wrong, and none of them may cost the walk its answer
// except the one that turns every cookie down.
func TestCookieIsRecorded(t *testing.T) {
	tests := map[string]struct {
		cookies  fakens.Cookies
		want     trace.CookieState
		kind     trace.StepKind
		warned   bool
		retried  bool
		sentMost int
	}{
		"a server that supports cookies": {
			cookies: fakens.CookieSupport, want: trace.CookieSupported, kind: trace.KindAnswer, sentMost: 1,
		},
		"a server that ignores them": {
			cookies: fakens.CookieIgnore, want: trace.CookieAbsent, kind: trace.KindAnswer, sentMost: 1,
		},
		"a server that wants its own cookie back first is asked again with it": {
			cookies: fakens.CookieRequire, want: trace.CookieSupported, kind: trace.KindAnswer,
			retried: true, sentMost: 2,
		},
		"a server that turns down its own cookie is asked again once and no more": {
			cookies: fakens.CookieRefuse, want: trace.CookieRejected, kind: trace.KindError,
			retried: true, sentMost: 2,
		},
		"a server that echoes somebody else's client cookie is warned about": {
			cookies: fakens.CookieWrongClient, want: trace.CookieMismatch, kind: trace.KindAnswer,
			warned: true, sentMost: 1,
		},
		"a server that hands out no cookie of its own": {
			cookies: fakens.CookieMalformed, want: trace.CookieMalformed, kind: trace.KindAnswer, sentMost: 1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h, cfg, leaf := cookieService(t, tt.cookies)

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			step := askedLeaf(t, tr)
			if step.Cookie != tt.want || step.Kind != tt.kind {
				t.Errorf("got %s %s, want %s %s: %s", step.Cookie, step.Kind, tt.want, tt.kind, format(steps(tr)))
			}
			if got := slices.Contains(step.Notes, "asked again with the server's cookie"); got != tt.retried {
				t.Errorf("got notes %q, want a retry noted: %v", step.Notes, tt.retried)
			}
			if got := warned(tr, "client cookie other than the one sent"); got != tt.warned {
				t.Errorf("got warnings %q, want a warning: %v", tr.Warnings, tt.warned)
			}
			if sent := len(leaf.Queries()); sent > tt.sentMost {
				t.Errorf("got %d queries to the leaf, want at most %d", sent, tt.sentMost)
			}
		})
	}
}

// TestCookieNotAsked covers the default: no cookie goes out, and no hop says
// anything about one.
func TestCookieNotAsked(t *testing.T) {
	h, cfg, leaf := cookieService(t, fakens.CookieSupport)
	cfg.Cookie = false

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, step := range steps(tr) {
		if step.Cookie != "" {
			t.Errorf("got %s at %s, want nothing: no cookie was sent", step.Cookie, step.Server.IP)
		}
	}
	for _, query := range leaf.Queries() {
		if query.Cookie != "" {
			t.Errorf("got %q sent, want no cookie", query.Cookie)
		}
	}
}

// TestCookieIsSentBack covers what makes a cookie worth having: the server
// cookie handed out on one query goes back with the next, and each server is
// sent a client cookie of its own rather than one that follows the walk.
func TestCookieIsSentBack(t *testing.T) {
	h, cfg, leaf := cookieService(t, fakens.CookieSupport)
	cfg.CheckNS = true // a second question for the leaf

	if _, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	queries := leaf.Queries()
	if len(queries) < 2 {
		t.Fatalf("got %d queries to the leaf, want at least two", len(queries))
	}
	first, second := queries[0].Cookie, queries[1].Cookie
	if len(first) != 16 {
		t.Errorf("got %q first, want a client cookie alone", first)
	}
	if len(second) != 32 || second[:16] != first {
		t.Errorf("got %q second, want %q and the server cookie after it", second, first)
	}
	for _, query := range h.root.Queries() {
		if query.Cookie[:16] == first[:16] {
			t.Errorf("got the leaf's client cookie sent to the root too")
		}
	}
}

// TestCookieOverTCP covers the other transport a cookie means anything over.
func TestCookieOverTCP(t *testing.T) {
	h, cfg, _ := cookieService(t, fakens.CookieSupport)
	cfg.Transport = h.carry(transport.NewTCP(fast))

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if step := askedLeaf(t, tr); step.Cookie != trace.CookieSupported {
		t.Errorf("got %q, want the cookie answered over tcp", step.Cookie)
	}
}

// TestCookieSurvivesTheEDNSFallback covers a server that cannot parse EDNS0.
// The question asked again without it has nowhere to carry a cookie, so the
// hop says nothing about one rather than calling the server one without.
func TestCookieSurvivesTheEDNSFallback(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{FormErrEDNS: true})
	cfg.Cookie = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	step := askedLeaf(t, tr)
	if step.Kind != trace.KindAnswer || step.Cookie != "" {
		t.Errorf("got %s with cookie %q, want the answer and no cookie", step.Kind, step.Cookie)
	}
}
