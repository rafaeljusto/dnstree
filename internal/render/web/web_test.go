package web_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/render/web"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// TestServe walks the whole way round: a trace goes in, an address comes out,
// and what is at that address is the page and the walk behind it.
func TestServe(t *testing.T) {
	out := new(watched)
	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	done := make(chan error, 1)
	go func() {
		done <- web.Serve(ctx, out, resolution(), nil, web.Options{Addr: "127.0.0.1:0", Version: "v0.1.0"})
	}()

	base := out.address(t)
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
			out := new(watched)
			ctx, stop := context.WithCancel(t.Context())

			done := make(chan error, 1)
			go func() { done <- web.Serve(ctx, out, resolution(), nil, web.Options{Addr: test.addr}) }()
			out.address(t)
			stop()
			<-done

			said := out.String()
			if warned := strings.Contains(said, "anyone who can reach this machine"); warned != test.warns {
				t.Errorf("got %q, want a warning: %v", said, test.warns)
			}
		})
	}
}

// TestServeInterrupted covers the run that was stopped while it was still
// walking: there is nothing to serve, and nothing is opened at it.
func TestServeInterrupted(t *testing.T) {
	ctx, stop := context.WithCancel(t.Context())
	stop()

	out := new(watched)
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

// watched is what the command writes, read from another goroutine as it is
// written: the address is only known once the server is up.
type watched struct {
	mutex sync.Mutex
	buf   bytes.Buffer
}

func (w *watched) Write(p []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.buf.Write(p)
}

func (w *watched) String() string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.buf.String()
}

var addressRE = regexp.MustCompile(`http://[^\s]+/`)

// address waits for the line that says where the page is.
func (w *watched) address(tb testing.TB) string {
	tb.Helper()

	for range 200 {
		if found := addressRE.FindString(w.String()); found != "" {
			return found
		}
		time.Sleep(10 * time.Millisecond)
	}
	tb.Fatalf("got %q, want an address in it", w.String())
	return ""
}
