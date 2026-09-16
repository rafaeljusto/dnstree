// Command dnstree resolves a name iteratively from the root servers and draws
// the delegation path it followed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rafaeljusto/dnstree/internal/asn"
	"github.com/rafaeljusto/dnstree/internal/cli"
	"github.com/rafaeljusto/dnstree/internal/render/dot"
	"github.com/rafaeljusto/dnstree/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/internal/render/tree"
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
		lookups = asn.New(nil, log)
	}

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

	// The last frame stays up until there is something to put in its place.
	live.Clear()
	if err := render(stdout, cfg, tr); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	live.Summary(stdout, tr)
	return verdict(tr)
}

// resolve builds the resolution the flags asked for and runs it.
func resolve(ctx context.Context, cfg *cli.Config, log *slog.Logger, lookups *asn.Resolver, live *tree.Live) (*trace.Trace, error) {
	hints, err := rootHints(cfg)
	if err != nil {
		return nil, err
	}

	carrier := transport.Config{Timeout: cfg.Timeout, Port: cfg.Port}
	config := resolver.Config{
		Transport: carry(cfg.Proto, carrier),
		Roots:     resolver.RootServers(hints),
		DNSSEC:    cfg.DNSSEC,
		All:       cfg.All,
		Family:    cfg.Family,
		CheckNS:   cfg.CheckNS,
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

func rootHints(cfg *cli.Config) (*roothints.Hints, error) {
	if cfg.RootHints != "" {
		return roothints.LoadFile(cfg.RootHints)
	}
	return roothints.Default()
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
