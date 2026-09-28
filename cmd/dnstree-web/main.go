// Command dnstree-web serves dnstree as a web page: a form that takes a name
// and a type, and the walk to it drawn in the browser.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/roothints"
	"github.com/rafaeljusto/dnstree/v2/internal/server"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// version is stamped into a release build.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stderr)
	stop() // os.Exit runs no deferred function

	os.Exit(code)
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("dnstree-web", flag.ContinueOnError)
	flags.SetOutput(stderr)

	// PORT is how most hosts that run a container say where to listen.
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	flags.StringVar(&addr, "addr", addr, "where to listen")
	timeout := flags.Duration("timeout", server.DefaultTimeout, "how long one walk may take")
	walks := flags.Int("walks", server.DefaultWalks, "how many walks run at once")
	perClient := flags.Int("per-client", server.DefaultPerClient, "how many walks one client may start in a minute")
	keep := flags.Duration("keep", server.DefaultKeep, "how long a finished walk is served again")
	clientHeader := flags.String("client-header", "", "the header a proxy in front puts the client's address in, such as Fly-Client-IP; only set it when every request comes through that proxy, since anyone else can send it")
	if err := flags.Parse(args); err != nil {
		return 1
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))

	hints, err := roothints.Default()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	carrier := transport.Config{}
	handler, err := server.New(server.Config{
		Roots:        resolver.RootServers(hints),
		Transport:    transport.NewUDP(carrier),
		TCP:          transport.NewTCP(carrier),
		Timeout:      *timeout,
		Walks:        *walks,
		PerClient:    *perClient,
		Keep:         *keep,
		ClientHeader: *clientHeader,
		Version:      version,
		Log:          log,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	log.Info("serving", "addr", addr, "version", version)
	if err := server.ListenAndServe(ctx, addr, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
