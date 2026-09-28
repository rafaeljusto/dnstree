// Package web serves a finished trace as a page, and points a browser at it.
// Nothing here works anything out about the DNS: the walk is handed over as the
// document --format json writes, and the drawing happens in the browser. There
// are two pages, the flat one and the scene, and they read the same walk.
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

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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

	// Scene serves the walk drawn in three dimensions rather than as a tree.
	Scene bool

	// Color is whether the address is announced with the mark beside it, or
	// in the two plain lines a script reads it from.
	Color tree.ColorMode

	// Version is the build the page says it came from.
	Version string

	// Now is when the walk was made, for a trace that does not say. The clock
	// is read when both are zero.
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
	announce(out, url, tr, opts)

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
		Handler:           handler(siteFor(opts), page, traceDoc),
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

// announce says where the page is. A terminal that wants colour gets the mark
// with the address beside it, as something to click; anything else gets the
// two lines it has always got, because a script waiting on the page reads the
// address out of them.
func announce(out io.Writer, url string, tr *trace.Trace, opts Options) {
	if !tree.ColorEnabled(out, opts.Color) {
		fmt.Fprintln(out, "the walk is at "+url)
		fmt.Fprintln(out, "it is served until this command is interrupted")
		return
	}

	// The name is somebody's input, and it is going to a terminal.
	asked := "the walk"
	if tr != nil {
		question := tr.Question.Shown()
		asked = question.Name + " " + question.Type
	}
	drawn := "drawn as a page to read"
	if opts.Scene {
		drawn = "drawn as a scene to turn around"
	}

	// OSC 8 makes the address a link in the terminals that know it, and is
	// passed over by the ones that do not.
	link := "\x1b]8;;" + url + "\x1b\\" + tree.MarkBlue + "\x1b[4m" + url + tree.MarkReset + "\x1b]8;;\x1b\\"

	tree.WriteMark(out, tree.Unicode, []string{
		tree.MarkBold + asked + tree.MarkReset + tree.MarkGrey + " · " + drawn + tree.MarkReset,
		"the walk is at " + link,
		tree.MarkGrey + "served until ctrl-c" + tree.MarkReset,
	})
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

// site is one page and the files it is made of, and what they are served as.
// The list is written out rather than walked, so that a file added to the
// directory is a file somebody meant to publish.
type site struct {
	dir   string
	files map[string]string
}

var (
	flat = site{dir: "assets", files: map[string]string{
		"app.css": "text/css; charset=utf-8",
		"app.js":  "text/javascript; charset=utf-8",
	}}
	scene = site{dir: "assets/scene", files: map[string]string{
		"scene.css": "text/css; charset=utf-8",
		"scene.js":  "text/javascript; charset=utf-8",
	}}
)

// icons are served beside either page, at the names docs/index.html gives them.
var icons = map[string]string{
	"favicon.ico":          "image/x-icon",
	"mark.svg":             "image/svg+xml",
	"apple-touch-icon.png": "image/png",
}

func siteFor(opts Options) site {
	if opts.Scene {
		return scene
	}
	return flat
}

// handler is the whole of what is served: the page, the files it is made of,
// and the walk behind it. Everything is written once, at the start, so nothing
// here reads the trace and nothing needs a lock.
func handler(pages site, page, traceDoc []byte) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", files(pages))

	// The walk as the page reads it, and the walk on its own, which is byte for
	// byte what --format json writes for whatever is pointed at it.
	mux.Handle("GET /page.json", serve("application/json; charset=utf-8", page))
	mux.Handle("GET /trace.json", serve("application/json; charset=utf-8", traceDoc))

	return local(mux)
}

// Files serves one of the pages and the files it is made of, but not the walk:
// whatever mounts it answers page.json and trace.json beside it.
func Files(scene bool) http.Handler {
	return files(siteFor(Options{Scene: scene}))
}

func files(pages site) http.Handler {
	mux := http.NewServeMux()
	index, err := assets.ReadFile(pages.dir + "/index.html")
	if err != nil {
		// The files are embedded at build time, so this cannot happen in a
		// binary that was built; it can in one being changed.
		panic("web: the page is missing from the binary: " + err.Error())
	}

	mux.Handle("GET /{$}", serve("text/html; charset=utf-8", index))
	for name, contentType := range pages.files {
		body, err := assets.ReadFile(pages.dir + "/" + name)
		if err != nil {
			panic("web: " + name + " is missing from the binary: " + err.Error())
		}
		mux.Handle("GET /"+name, serve(contentType, body))
	}

	// Both pages wear the landing page's icons. They are copies of the ones in
	// docs, which the binary cannot reach, and a test keeps them the same.
	for name, contentType := range icons {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			panic("web: " + name + " is missing from the binary: " + err.Error())
		}
		mux.Handle("GET /"+name, serve(contentType, body))
	}
	return mux
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
