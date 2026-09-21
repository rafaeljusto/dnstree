// Package web serves a finished trace as a page, and points a browser at it.
// Nothing here works anything out about the DNS: the walk is handed over as the
// document --format json writes, and the drawing happens in the browser.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/explain"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// DefaultAddr is where the page is served when nothing says otherwise: this
// machine, on whatever port is free. A walk names the servers it asked and the
// addresses they answered from, which is nobody else's business by default.
const DefaultAddr = "127.0.0.1:0"

// How long the server is given to finish what it is serving once the run is
// interrupted, and how long a client has to send its headers. Neither is
// tuning: they are there so that a stuck connection cannot hold the command
// open, nor a half-open one hold a port.
const (
	shutdownGrace  = 2 * time.Second
	headerDeadline = 10 * time.Second
)

//go:embed assets
var assets embed.FS

// Options configure a served page.
type Options struct {
	// Addr is where to listen, [DefaultAddr] when empty.
	Addr string

	// Browser asks for a browser to be opened at the page. It is best effort: a
	// machine that cannot open one still gets the address printed.
	Browser bool

	// Version is the build the page says it came from.
	Version string

	// Now is when the walk was made, taken from the clock when it is zero.
	Now time.Time
}

// Serve draws nothing itself: it hands the trace to a browser and waits. It
// returns when ctx is done, which is what a signal leaves behind, or when the
// server cannot carry on.
func Serve(ctx context.Context, out io.Writer, tr *trace.Trace, findings []explain.Finding, opts Options) error {
	// A run interrupted while it was still walking has nothing to hand over: the
	// page would be served and taken down in the same breath, and a browser
	// would open on an address nothing answers at.
	if ctx.Err() != nil {
		fmt.Fprintln(out, "the run was interrupted, so there is no page")
		return nil
	}

	page, traceDoc, err := build(tr, findings, opts)
	if err != nil {
		return err
	}

	addr := opts.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web: %w", err)
	}

	url := "http://" + listening(listener.Addr()).String() + "/"
	fmt.Fprintln(out, "the walk is at "+url)
	fmt.Fprintln(out, "it is served until this command is interrupted")

	// The address the page is offered at is not the one it is bound to: a server
	// bound to everything is offered on loopback, and is still on the network.
	if !onlyHere(listener.Addr()) {
		fmt.Fprintln(out, "anyone who can reach this machine can read it; --web-addr "+DefaultAddr+" keeps it here")
	}
	if opts.Browser {
		if err := launch(url); err != nil {
			fmt.Fprintln(out, "no browser was opened ("+err.Error()+"); the address above is the page")
		}
	}

	server := &http.Server{
		Handler:           handler(page, traceDoc),
		ReadHeaderTimeout: headerDeadline,
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	select {
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("web: %w", err)
	case <-ctx.Done():
	}

	// The context that ended the run cannot be the one that bounds the
	// shutdown: it is already cancelled, and a cancelled one closes every
	// connection at once rather than letting the last response out.
	grace, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	return server.Shutdown(grace)
}

// onlyHere reports whether the page is bound where nothing else can reach it.
func onlyHere(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.AddrPort().Addr().IsLoopback()
}

// listening is the address to hand a browser. A server bound to everything
// answers on no address in particular, so the page is offered where it is
// certain to be: this machine.
func listening(addr net.Addr) netip.AddrPort {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}
	}

	where := tcp.AddrPort()
	if !where.Addr().IsUnspecified() {
		return netip.AddrPortFrom(where.Addr().Unmap(), where.Port())
	}
	if where.Addr().Is4() || where.Addr().Is4In6() {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), where.Port())
	}
	return netip.AddrPortFrom(netip.IPv6Loopback(), where.Port())
}

// The files the page is made of, and what they are served as. The list is
// written out rather than walked, so that a file added to the directory is a
// file somebody meant to publish.
var files = map[string]string{
	"app.css": "text/css; charset=utf-8",
	"app.js":  "text/javascript; charset=utf-8",
}

// handler is the whole of what is served: the page, the files it is made of,
// and the walk behind it. Everything is written once, at the start, so nothing
// here reads the trace and nothing needs a lock.
func handler(page, traceDoc []byte) http.Handler {
	mux := http.NewServeMux()
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		// The files are embedded at build time, so this cannot happen in a
		// binary that was built; it can in one being changed.
		panic("web: the page is missing from the binary: " + err.Error())
	}

	mux.Handle("GET /{$}", serve("text/html; charset=utf-8", index))
	for name, contentType := range files {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			panic("web: " + name + " is missing from the binary: " + err.Error())
		}
		mux.Handle("GET /"+name, serve(contentType, body))
	}

	// The walk as the page reads it, and the walk on its own, which is byte for
	// byte what --format json writes for whatever is pointed at it.
	mux.Handle("GET /page.json", serve("application/json; charset=utf-8", page))
	mux.Handle("GET /trace.json", serve("application/json; charset=utf-8", traceDoc))

	return local(mux)
}

func serve(contentType string, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		// One run, one walk: a page kept in a cache would outlive the answer it
		// draws, and the server it came from.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
	})
}

// local turns away a request that reached the server under a name. A page on
// loopback is still reachable from a browser that was told a name pointing at
// it, which is how a site somebody else wrote reads what is on this machine;
// only a request that names an address, or localhost, is one this page was
// opened for.
func local(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !addressed(r.Host) {
			http.Error(w, "this page is only served to a browser that asked for it by address", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// addressed reports whether a Host header names a machine rather than a name in
// the DNS. Stripping the port is done by hand because a Host may carry none.
func addressed(host string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}
