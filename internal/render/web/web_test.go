package web_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/output"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestServe walks the whole way round: a trace goes in, an address comes out,
// and what is at that address is the page and the walk behind it.
func TestServe(t *testing.T) {
	out := new(output.Buffer)
	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	done := make(chan error, 1)
	go func() {
		done <- web.Serve(ctx, out, resolution(), nil, web.Options{Addr: "127.0.0.1:0", Version: "v0.1.0"})
	}()

	base := out.Await(t, output.Address)
	for _, path := range []string{"", "app.css", "app.js", "page.json", "trace.json"} {
		answer, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET /%s: %v", path, err)
		}
		body, _ := io.ReadAll(answer.Body)
		answer.Body.Close()

		if answer.StatusCode != http.StatusOK {
			t.Errorf("got %d for /%s, want it served", answer.StatusCode, path)
		}
		if len(body) == 0 {
			t.Errorf("got nothing for /%s, want the file", path)
		}
	}

	// The run ending is what takes the page down, and it goes down quietly.
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server is still up after the run was interrupted")
	}
}

// TestServeNowhere covers an address nothing can listen on: it is the command
// line being wrong, and it is said rather than served.
func TestServeNowhere(t *testing.T) {
	err := web.Serve(t.Context(), io.Discard, resolution(), nil, web.Options{Addr: "203.0.113.1:80"})
	if err == nil {
		t.Fatal("got no error, want the address it could not listen on")
	}
	if !strings.Contains(err.Error(), "web:") {
		t.Errorf("got %v, want it said where it came from", err)
	}
}

// TestServeSaysWhereItIs covers what somebody running this actually reads: an
// address they can open, and a warning where the page is not only theirs.
func TestServeSaysWhereItIs(t *testing.T) {
	tests := map[string]struct {
		addr  string
		warns bool
	}{
		"kept to this machine": {addr: "127.0.0.1:0"},
		"open to the network":  {addr: ":0", warns: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out := new(output.Buffer)
			ctx, stop := context.WithCancel(t.Context())

			done := make(chan error, 1)
			go func() { done <- web.Serve(ctx, out, resolution(), nil, web.Options{Addr: test.addr}) }()
			out.Await(t, output.Address)
			stop()
			<-done

			said := out.String()
			if warned := strings.Contains(said, "anyone who can reach this machine"); warned != test.warns {
				t.Errorf("got %q, want a warning: %v", said, test.warns)
			}
		})
	}
}

// TestServeAnnounces covers the address said to a terminal that wants colour:
// the mark beside it, the address as a link, and the name that was asked for
// drawn escaped, since it is somebody's input going to a terminal.
func TestServeAnnounces(t *testing.T) {
	tests := map[string]struct {
		scene bool
		says  string
	}{
		"the flat page": {says: "drawn as a page to read"},
		"the scene":     {scene: true, says: "drawn as a scene to turn around"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr := resolution()
			tr.Question.Name = "evil\x1b[2J.example."

			out := new(output.Buffer)
			ctx, stop := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- web.Serve(ctx, out, tr, nil, web.Options{
					Addr: "127.0.0.1:0", Scene: test.scene, Color: tree.ColorAlways,
				})
			}()
			out.Await(t, "served until ctrl-c")
			stop()
			<-done

			said := out.String()
			for _, want := range []string{"\x1b]8;;http://127.0.0.1:", test.says, "⣿⣿"} {
				if !strings.Contains(said, want) {
					t.Errorf("got %q, want %q in it", said, want)
				}
			}
			if strings.Contains(said, "\x1b[2J") {
				t.Errorf("got %q, want the name's escape escaped rather than obeyed", said)
			}
		})
	}
}

// TestServeInterrupted covers the run that was stopped while it was still
// walking: there is nothing to serve, and nothing is opened at it.
func TestServeInterrupted(t *testing.T) {
	ctx, stop := context.WithCancel(t.Context())
	stop()

	out := new(output.Buffer)
	if err := web.Serve(ctx, out, resolution(), nil, web.Options{Browser: true}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if said := out.String(); !strings.Contains(said, "interrupted") {
		t.Errorf("got %q, want it said why there is no page", said)
	}
	if strings.Contains(out.String(), "http://") {
		t.Errorf("got %q, want no address for a page that is not there", out.String())
	}
}

func resolution() *trace.Trace {
	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Elapsed:  30 * time.Millisecond,
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
	}
}
