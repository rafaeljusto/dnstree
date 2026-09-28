// Package server is dnstree as a public web page: a form that asks for a name
// and a type, and the walk to it drawn by the same pages --format web and
// web-3d serve. The walk is the resolver's, run with a fixed configuration:
// nothing a visitor sends reaches the resolver but the question itself.
package server

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/idn"
	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// Defaults for a [Config] left at zero.
const (
	DefaultTimeout   = 15 * time.Second
	DefaultWalks     = 4
	DefaultPerClient = 12
	DefaultKeep      = time.Minute
)

// Types are the query types the form offers, and the only ones walked.
var Types = []string{
	"A", "AAAA", "CAA", "CNAME", "DNSKEY", "DS", "HTTPS", "MX",
	"NAPTR", "NS", "PTR", "SOA", "SRV", "SVCB", "TLSA", "TXT",
}

// views are the two ways a walk is drawn, by the name they take in a path.
var views = map[string]bool{"3d": true, "tree": false}

// How long the server waits for a place among the walks running, and how long
// a client has to send its headers.
const (
	queueWait      = 5 * time.Second
	headerDeadline = 10 * time.Second
	shutdownGrace  = 5 * time.Second
)

//go:embed assets
var assets embed.FS

var (
	landing = form()
	failure = template.Must(template.ParseFS(assets, "assets/failed.html"))
)

// form is the landing page, which offers the types this server walks.
func form() []byte {
	var page bytes.Buffer
	if err := template.Must(template.ParseFS(assets, "assets/index.html")).Execute(&page, Types); err != nil {
		panic("server: " + err.Error())
	}
	return page.Bytes()
}

// Config is what a server walks with. Roots and Transport are required.
type Config struct {
	Roots []trace.Server

	// Transport carries every query, and TCP fetches what came back truncated.
	// Both are guarded by Allow before they are used.
	Transport transport.Transport
	TCP       transport.Transport

	// Allow is which addresses a walk may send to, [transport.Public] when nil.
	// A zone that hands out glue on somebody's private network is recorded as
	// having done so, and not followed there.
	Allow func(netip.Addr) bool

	// Timeout bounds one walk, Walks how many run at once, PerClient how many
	// one client may start in a minute, and Keep how long a finished walk is
	// served again rather than made again.
	Timeout   time.Duration
	Walks     int
	PerClient int
	Keep      time.Duration

	// ClientHeader names the header a proxy in front puts the client's address
	// in. Empty reads the address the connection came from.
	ClientHeader string

	Version string
	Log     *slog.Logger
}

// Server answers the form and the walks behind it.
type Server struct {
	cfg     Config
	engine  *resolver.Resolver
	mux     *http.ServeMux
	walks   *walks
	clients *limiter
	pages   map[bool]http.Handler // by whether it is the scene
}

// New checks cfg and builds the server for it.
func New(cfg Config) (*Server, error) {
	if cfg.Transport == nil {
		return nil, errors.New("server: no transport to query with")
	}
	if cfg.Allow == nil {
		cfg.Allow = transport.Public
	}
	cfg.Timeout = cmpOr(cfg.Timeout, DefaultTimeout)
	cfg.Walks = cmpOr(cfg.Walks, DefaultWalks)
	cfg.PerClient = cmpOr(cfg.PerClient, DefaultPerClient)
	cfg.Keep = cmpOr(cfg.Keep, DefaultKeep)
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}

	engineCfg := resolver.Config{
		Transport: transport.Guard(cfg.Transport, cfg.Allow),
		Roots:     cfg.Roots,
		DNSSEC:    true,
	}
	if cfg.TCP != nil {
		engineCfg.TCP = transport.Guard(cfg.TCP, cfg.Allow)
	}
	engine, err := resolver.New(engineCfg)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:     cfg,
		engine:  engine,
		walks:   newWalks(cfg.Walks, cfg.Keep, queueWait),
		clients: newLimiter(cfg.PerClient, time.Minute),
		pages:   map[bool]http.Handler{false: web.Files(false), true: web.Files(true)},
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		headers(w, "text/html; charset=utf-8")
		_, _ = w.Write(landing)
	})
	s.mux.HandleFunc("GET /walk", s.asked)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		headers(w, "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	for _, name := range []string{"favicon.ico", "mark.svg", "apple-touch-icon.png"} {
		s.mux.Handle("GET /"+name, s.pages[false])
	}

	s.mux.HandleFunc("GET /{view}/{name}/{type}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("GET /{view}/{name}/{type}/{file...}", s.drawn)
}

// ServeHTTP implements [http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// asked is the form arriving, sent on to the address its walk is drawn at, so
// that the address can be kept and handed to somebody else.
func (s *Server) asked(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	name, ok := canonical(query.Get("name"))
	if !ok {
		s.failed(w, http.StatusBadRequest, "that is not a name that can be walked to")
		return
	}
	qtype, ok := known(query.Get("type"))
	if !ok {
		s.failed(w, http.StatusBadRequest, "that is not one of the types this page walks")
		return
	}
	view := query.Get("view")
	if _, ok := views[view]; !ok {
		view = "3d"
	}
	http.Redirect(w, r, path(view, name, qtype), http.StatusSeeOther)
}

// path is where a walk is drawn.
func path(view, name, qtype string) string {
	return "/" + view + "/" + url.PathEscape(name) + "/" + qtype + "/"
}

// drawn is one of the pages, the files it is made of, or the walk it reads.
// The page itself waits for the walk, so that a name that cannot be walked, or
// a server with no room for it, is said in a page rather than in one that
// never draws; the page's own request for the walk is then served from what
// was just made.
func (s *Server) drawn(w http.ResponseWriter, r *http.Request) {
	scene, ok := views[r.PathValue("view")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	file := r.PathValue("file")
	switch file {
	case "", "page.json", "trace.json":
	default:
		s.page(w, r, scene, file)
		return
	}

	name, ok := canonical(r.PathValue("name"))
	if !ok {
		s.failed(w, http.StatusBadRequest, "that is not a name that can be walked to")
		return
	}
	qtype, ok := known(r.PathValue("type"))
	if !ok {
		s.failed(w, http.StatusBadRequest, "that is not one of the types this page walks")
		return
	}

	// A walk has one address, which is what keeps the files the page asks for
	// relative to where it was served from, and one question per walk kept.
	if file == "" && (r.PathValue("name") != name || r.PathValue("type") != qtype) {
		http.Redirect(w, r, path(r.PathValue("view"), name, qtype), http.StatusMovedPermanently)
		return
	}

	made, err := s.walks.get(r.Context(), name+" "+qtype, func() bool {
		return s.clients.allow(s.client(r), time.Now())
	}, func(ctx context.Context) (*walked, error) {
		return s.walk(ctx, name, qtype)
	})
	switch {
	case errors.Is(err, errLimited):
		s.failed(w, http.StatusTooManyRequests, "that is a lot of walks in one minute; try again in a moment")
		return
	case errors.Is(err, errBusy):
		s.failed(w, http.StatusServiceUnavailable, "every walk this server has room for is running; try again in a moment")
		return
	case errors.Is(err, errUnwalkable):
		s.failed(w, http.StatusBadRequest, "that is not a name that can be walked to")
		return
	case err != nil:
		s.failed(w, http.StatusInternalServerError, "the walk could not be drawn")
		return
	}

	switch file {
	case "page.json":
		headers(w, "application/json; charset=utf-8")
		_, _ = w.Write(made.page)
	case "trace.json":
		headers(w, "application/json; charset=utf-8")
		_, _ = w.Write(made.traceDoc)
	default:
		s.page(w, r, scene, file)
	}
}

// page is one of the files a page is made of, served as if the page were at
// the root: everything it asks for is relative, so it asks for it here.
func (s *Server) page(w http.ResponseWriter, r *http.Request, scene bool, file string) {
	at := strings.TrimSuffix(r.URL.Path, file)
	http.StripPrefix(strings.TrimSuffix(at, "/"), s.pages[scene]).ServeHTTP(w, r)
}

// errUnwalkable is a question the resolver would not start on.
var errUnwalkable = errors.New("server: not a question that can be walked")

// walk is one resolution and the payload the pages read, bounded by the
// server's timeout rather than by the request that started it: a visitor who
// gives up leaves a walk that others asking the same question are waiting on.
func (s *Server) walk(ctx context.Context, name, qtype string) (*walked, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.Timeout)
	defer cancel()

	started := time.Now()
	tr, err := s.engine.Resolve(ctx, name, qtype)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnwalkable, err)
	}
	page, traceDoc, err := web.Payload(tr, explain.Findings(tr), web.Options{Version: s.cfg.Version})
	if err != nil {
		return nil, err
	}
	s.cfg.Log.Info("walked", "name", name, "type", qtype,
		"took", time.Since(started).Round(time.Millisecond), "answered", tr.Result() != nil)
	return &walked{page: page, traceDoc: traceDoc}, nil
}

// client is who a request counts against. An IPv6 client is counted by its
// /64, since that is the least a network hands out and all of it is theirs.
func (s *Server) client(r *http.Request) string {
	from := r.RemoteAddr
	if s.cfg.ClientHeader != "" {
		if header := r.Header.Get(s.cfg.ClientHeader); header != "" {
			from = strings.TrimSpace(strings.Split(header, ",")[0])
		}
	}
	if host, _, err := net.SplitHostPort(from); err == nil {
		from = host
	}
	addr, err := netip.ParseAddr(from)
	if err != nil {
		return from
	}
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}

func (s *Server) failed(w http.ResponseWriter, status int, message string) {
	headers(w, "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = failure.Execute(w, message)
}

// canonical is the name as the walk and its address spell it: in lower case,
// in punycode, without the dot at the end. The root is left out, since a path
// cannot carry it without being cleaned away.
func canonical(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	name, err := idn.ASCII(name)
	if err != nil {
		return "", false
	}
	if name == "" || len(name) > 253 || strings.ContainsAny(name, "/\\ \t") {
		return "", false
	}
	return name, true
}

func known(qtype string) (string, bool) {
	qtype = strings.ToUpper(strings.TrimSpace(qtype))
	return qtype, slices.Contains(Types, qtype)
}

func headers(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// ListenAndServe serves h at addr until ctx is done.
func ListenAndServe(ctx context.Context, addr string, h http.Handler) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: headerDeadline,
		IdleTimeout:       time.Minute,
	}
	served := make(chan error, 1)
	go func() { served <- server.ListenAndServe() }()

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	grace, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	return server.Shutdown(grace)
}

func cmpOr[T time.Duration | int](value, fallback T) T {
	if value <= 0 {
		return fallback
	}
	return value
}
