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

// asnTimeout bounds the metadata lookups. A working lookup answers in
// milliseconds, so this is the patience of somebody who wants the trace, not of
// somebody who wants the AS numbers.
const asnTimeout = 2 * time.Second

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

	tr, err := resolve(ctx, cfg, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	if cfg.ASN {
		lookups, cancel := context.WithTimeout(ctx, asnTimeout)
		defer cancel()
		asn.New(nil).Annotate(lookups, tr)
	}

	if err := render(stdout, cfg, tr); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	return verdict(tr)
}

// resolve builds the resolution the flags asked for and runs it.
func resolve(ctx context.Context, cfg *cli.Config, stderr io.Writer) (*trace.Trace, error) {
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
	if cfg.Debug {
		config.Log = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
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
	case "ascii":
		// Plain enough to paste into a document, which means no escapes at all.
		return tree.Render(w, tr, tree.Options{Charset: tree.ASCII, Color: tree.ColorNever})
	case "json":
		return jsonout.Render(w, tr)
	case "dot":
		return dot.Render(w, tr)
	default:
		return tree.Render(w, tr, tree.Options{Charset: tree.Unicode, Color: cfg.Color})
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
