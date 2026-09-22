// Command dnstree resolves a name iteratively from the root servers and draws
// the delegation path it followed.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rafaeljusto/dnstree/internal/asn"
	"github.com/rafaeljusto/dnstree/internal/cli"
	"github.com/rafaeljusto/dnstree/internal/expect"
	"github.com/rafaeljusto/dnstree/internal/explain"
	"github.com/rafaeljusto/dnstree/internal/history"
	"github.com/rafaeljusto/dnstree/internal/recursive"
	"github.com/rafaeljusto/dnstree/internal/render/dot"
	"github.com/rafaeljusto/dnstree/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/internal/render/tree"
	"github.com/rafaeljusto/dnstree/internal/render/web"
	"github.com/rafaeljusto/dnstree/internal/resolver"
	"github.com/rafaeljusto/dnstree/internal/roothints"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// What the exit code says about the run.
const (
	exitAnswer   = 0 // something answered
	exitUsage    = 1 // the command line, or the question, could not be read
	exitNoAnswer = 2 // the walk ended without an answer
	exitBogus    = 3 // the chain of trust is broken
	exitExpect   = 4 // an expectation was not met
)

// asnGrace is how long the origin AS lookups may carry on once the walk is
// over. They start as the walk discovers each server, so by here they have had
// the whole resolution as a head start and this is only for the stragglers.
const asnGrace = 2 * time.Second

// version is stamped into a release build; see the dist target of the Makefile.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop() // os.Exit runs no deferred function

	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := cli.Parse(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, err)
		}
		return exitUsage
	}
	if cfg.Version {
		fmt.Fprintln(stdout, "dnstree "+version)
		return exitAnswer
	}
	if cfg.Schema {
		if err := jsonout.WriteSchema(stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		return exitAnswer
	}

	// The lookups run behind the walk: each server is asked about the moment
	// the walk reaches it, so the tree is not held up by metadata at the end.
	var log *slog.Logger
	if cfg.Debug {
		log = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	if log != nil && cfg.ConfigFile != "" {
		log.Debug("defaults read from a file", "file", cfg.ConfigFile)
	}

	var lookups *asn.Resolver
	if cfg.ASN {
		lookups = asn.New(asnLookup(cfg), log)
	}

	// The comparison runs beside the walk rather than after it: a recursive
	// server answers in the time one hop of the walk takes, so waiting for it
	// separately would be time spent on metadata.
	timed := compare(ctx, cfg, log)

	// The live drawing owns the screen until it is cleared, and the finished
	// tree is then written exactly where it stood.
	var live *tree.Live
	if cfg.Live {
		live = tree.NewLive(stdout, treeOptions(cfg))
		defer live.Clear()
	}

	tr, err := resolve(ctx, cfg, log, lookups, live)
	if err != nil {
		live.Clear()
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	if lookups != nil {
		grace, cancel := context.WithTimeout(ctx, asnGrace)
		defer cancel()
		lookups.Annotate(grace, tr)
	}
	if timed != nil {
		tr.Resolver = <-timed
		recursive.Compare(tr)
	}

	// The last frame stays up until there is something to put in its place.
	live.Clear()

	// A served walk is drawn in a browser rather than here, and the sentences
	// the run asked for go to the page with it.
	if cfg.Format == "web" {
		options := web.Options{
			Addr:    cfg.WebAddr,
			Browser: cfg.Browser,
			Version: version,
			Now:     time.Now(),
		}
		if err := web.Serve(ctx, stdout, tr, readings(cfg, tr, stderr), options); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		return outcome(cfg, tr, stderr)
	}

	if err := render(stdout, cfg, tr); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if live != nil {
		live.Summary(stdout, tr)
	} else if cfg.Format != "json" && cfg.Format != "dot" {
		tree.Summary(stdout, tr, treeOptions(cfg))
	}
	if findings := readings(cfg, tr, stderr); len(findings) > 0 {
		tree.Explain(stdout, findings, treeOptions(cfg))
	}
	return outcome(cfg, tr, stderr)
}

// outcome is what the run says to whoever started it: what the walk came to,
// and then whether that was what was asked for.
//
// The walk's own verdict wins wherever there is one. A chain of trust that is
// broken, or an answer that never came, is a bigger fact than an address that
// is not the one somebody wanted, and a script reading 4 for either of those
// would go looking in the wrong place. What went unmet goes to stderr, where
// the reason for an exit code belongs: it is a verdict rather than a reading,
// so it is said whether or not --explain asked for prose.
func outcome(cfg *cli.Config, tr *trace.Trace, stderr io.Writer) int {
	code := verdict(tr)
	if code != exitAnswer {
		return code
	}

	unmet := expect.Unmet(tr, cfg.Expect)
	for _, line := range unmet {
		fmt.Fprintln(stderr, line)
	}
	if len(unmet) > 0 {
		return exitExpect
	}
	return code
}

// readings is what is said under the tree: the sentences the trace says about
// itself, and what has changed since the last walk of the same question.
func readings(cfg *cli.Config, tr *trace.Trace, stderr io.Writer) []explain.Finding {
	var findings []explain.Finding
	if cfg.Explain {
		findings = append(findings, explain.Findings(tr)...)
	}
	if cfg.Diff {
		findings = append(findings, changed(tr, stderr)...)
	}
	return findings
}

// changed holds this walk against the one remembered for the same question, and
// remembers this one in its place. Like the origin AS lookups it is metadata: a
// cache that cannot be read or written costs the comparison, says so in one
// line, and never the resolution.
func changed(tr *trace.Trace, stderr io.Writer) []explain.Finding {
	dir, err := history.Dir()
	if err != nil {
		fmt.Fprintln(stderr, "nothing to compare with: "+err.Error())
		return nil
	}

	now := history.Of(tr, time.Now())
	findings := history.Changes(history.Load(dir, tr.Question), now)
	if err := history.Save(dir, now); err != nil {
		fmt.Fprintln(stderr, "this walk will not be remembered: "+err.Error())
	}
	return findings
}

// resolve builds the resolution the flags asked for and runs it.
func resolve(ctx context.Context, cfg *cli.Config, log *slog.Logger, lookups *asn.Resolver, live *tree.Live) (*trace.Trace, error) {
	roots, err := rootServers(cfg)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := clientTLS(cfg)
	if err != nil {
		return nil, err
	}

	carrier := transport.Config{Timeout: cfg.Timeout, Port: cfg.Port, TLS: tlsConfig}
	config := resolver.Config{
		Transport: carry(cfg.Proto, carrier),
		Roots:     roots,
		DNSSEC:    cfg.DNSSEC,
		All:       cfg.All,
		Family:    cfg.Family,
		CheckNS:   cfg.CheckNS,
		Serial:    cfg.Serial,
		NSID:      cfg.NSID,
		Subnet:    cfg.Subnet,
		Retries:   cfg.Retries,
		Budget: resolver.Budget{
			MaxDepth:   cfg.MaxDepth,
			MaxQueries: cfg.MaxQueries,
			MaxCNAME:   cfg.MaxCNAME,
		},
	}
	config.Log = log
	if lookups != nil {
		config.Discovered = func(addr netip.Addr) { lookups.Start(ctx, addr) }
	}
	if live != nil {
		config.Stepped = live.Draw
		config.Asking = live.Asking
	}

	// Only a datagram can be truncated, and only plain DNS is worth falling
	// back to.
	if cfg.Proto == "udp" {
		config.TCP = transport.NewTCP(carrier)
	}
	if cfg.Fallback {
		config.Fallback = transport.NewUDP(carrier)
	}
	if cfg.TrustAnchors != "" {
		if config.Anchors, err = roothints.LoadAnchorsFile(cfg.TrustAnchors); err != nil {
			return nil, err
		}
	}

	engine, err := resolver.New(config)
	if err != nil {
		return nil, err
	}
	return engine.Resolve(ctx, cfg.Name, cfg.Type)
}

// rootServers is where the walk starts: the servers --root named, the hints
// file --root-hints pointed at, or the hints built into the binary.
func rootServers(cfg *cli.Config) ([]trace.Server, error) {
	if len(cfg.Roots) > 0 {
		servers := make([]trace.Server, 0, len(cfg.Roots))
		for _, root := range cfg.Roots {
			servers = append(servers, trace.Server{
				Name: root.Name,
				IP:   root.Addr.Addr(),
				Port: root.Addr.Port(),
			})
		}
		return servers, nil
	}

	hints, err := roothints.Default()
	if cfg.RootHints != "" {
		hints, err = roothints.LoadFile(cfg.RootHints)
	}
	if err != nil {
		return nil, err
	}
	return resolver.RootServers(hints), nil
}

// clientTLS is how the encrypted transports verify a server, nil when that is
// the host's own roots under the name the delegation gave it.
func clientTLS(cfg *cli.Config) (*tls.Config, error) {
	switch {
	case cfg.TLSInsecure:
		return &tls.Config{InsecureSkipVerify: true}, nil
	case cfg.TLSCA == "":
		return nil, nil
	}

	pem, err := os.ReadFile(cfg.TLSCA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificate to verify against", cfg.TLSCA)
	}
	return &tls.Config{RootCAs: roots}, nil
}

// compare puts the same question to a recursive server, and answers with the
// channel the timing arrives on. Nothing comes of a run that asked for no
// comparison, or of a host that will not say which server it resolves through.
func compare(ctx context.Context, cfg *cli.Config, log *slog.Logger) <-chan *trace.Resolver {
	if !cfg.Compare {
		return nil
	}
	server := cfg.Resolver
	if !server.IsValid() {
		server = recursive.System()
	}
	if !server.IsValid() {
		return nil
	}

	question := trace.Question{Name: cfg.Name, Type: cfg.Type, Class: "IN"}
	carrier := transport.NewUDP(transport.Config{Timeout: cfg.Timeout})

	timed := make(chan *trace.Resolver, 1)
	go func() {
		defer close(timed)
		answer, err := recursive.Ask(ctx, carrier, server, question, cfg.DNSSEC, cfg.Subnet)

		if err != nil {
			if log != nil {
				log.Debug("the resolver could not be asked", "server", server, "error", err)
			}
			return
		}
		if log != nil {
			log.Debug("asked a resolver the same question",
				"server", server, "took", answer.Elapsed, "rcode", answer.Rcode, "error", answer.Err)
		}
		timed <- answer
	}()
	return timed
}

// asnLookup is where the origin AS lookups go. A nil lookup leaves asn.New to
// use the host's own resolver, which is what the Cymru zones normally need.
func asnLookup(cfg *cli.Config) asn.Lookup {
	if !cfg.Resolver.IsValid() {
		return nil
	}

	// A resolver of its own, dialling the one server, so that the lookups can
	// be pointed somewhere the host knows nothing about.
	server := cfg.Resolver.String()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, server)
		},
	}
	return resolver.LookupTXT
}

func carry(proto string, cfg transport.Config) transport.Transport {
	switch proto {
	case "tcp":
		return transport.NewTCP(cfg)
	case "dot":
		return transport.NewDoT(cfg)
	case "doh":
		return transport.NewDoH(cfg)
	default:
		return transport.NewUDP(cfg)
	}
}

func render(w io.Writer, cfg *cli.Config, tr *trace.Trace) error {
	switch cfg.Format {
	case "json":
		return jsonout.Render(w, tr)
	case "dot":
		return dot.Render(w, tr)
	default:
		return tree.Render(w, tr, treeOptions(cfg))
	}
}

// treeOptions is how the tree is drawn, live and at the end alike.
func treeOptions(cfg *cli.Config) tree.Options {
	switch cfg.Format {
	case "ascii":
		// Plain enough to paste into a document, which means no escapes at all.
		return tree.Options{Charset: tree.ASCII, Color: tree.ColorNever}
	case "emoji":
		return tree.Options{Charset: tree.Emoji, Color: cfg.Color}
	default:
		return tree.Options{Charset: tree.Unicode, Color: cfg.Color}
	}
}

// verdict reads the trace the way a script would: a broken chain of trust
// outranks an answer, and an answer outranks nothing.
func verdict(tr *trace.Trace) int {
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.State == trace.Bogus {
			return exitBogus
		}
	}
	if tr.Result() == nil {
		return exitNoAnswer
	}
	return exitAnswer
}
