// Command dnstree resolves a name iteratively from the root servers and draws
// the delegation path it followed.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/asn"
	"github.com/rafaeljusto/dnstree/v2/internal/capture"
	"github.com/rafaeljusto/dnstree/v2/internal/cli"
	"github.com/rafaeljusto/dnstree/v2/internal/expect"
	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/history"
	"github.com/rafaeljusto/dnstree/v2/internal/rdap"
	"github.com/rafaeljusto/dnstree/v2/internal/recursive"
	"github.com/rafaeljusto/dnstree/v2/internal/render/dot"
	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/render/markdown"
	"github.com/rafaeljusto/dnstree/v2/internal/render/mermaid"
	"github.com/rafaeljusto/dnstree/v2/internal/render/openmetrics"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/roothints"
	"github.com/rafaeljusto/dnstree/v2/internal/spf"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
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

// rdapGrace is how long the registry may take once the walk is over. Its
// bootstrap file is read beside the walk; the domain cannot be asked about
// until the walk has said which it is.
const rdapGrace = 5 * time.Second

// Where --rdap finds the registries, and what it asks them with: the tests
// point both at a registry of their own.
var (
	rdapBootstrap = rdap.Bootstrap
	rdapHTTP      *http.Client
)

// version is stamped into a release build; see the dist target of the Makefile.
var version = "dev"

// stdin is where --from - reads a saved walk from.
var stdin io.Reader = os.Stdin

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
		cli.WriteVersion(stdout, version, treeOptions(cfg).Charset, cfg.Color)
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
	if cfg.ASN && cfg.From == "" {
		lookups = asn.New(asnLookup(cfg), log)
	}
	var registry *rdap.Client
	if cfg.RDAP && cfg.From == "" {
		registry = rdap.New(rdapHTTP, rdapBootstrap, log)
	}

	// The file to compare with is read before any server is asked, so that a
	// walk is not made only to find there is nothing to hold it against.
	var reference *history.Walk
	if cfg.Against != "" {
		if reference, err = against(cfg.Against); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		if cfg.From == "" {
			asked := trace.Question{Name: cfg.Name, Type: cfg.Type, Class: "IN"}
			if err := sameQuestion(reference, asked, cfg.Against); err != nil {
				fmt.Fprintln(stderr, err)
				return exitUsage
			}
		}
	}

	if cfg.Watch > 0 {
		return watch(ctx, cfg, log, lookups, registry, reference, stdout, stderr)
	}
	if cfg.From != "" {
		return one(ctx, cfg, log, lookups, registry, nil, reference, stdout, stderr)
	}

	questions, err := asked(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	// The file is made before any server is asked, so that a path that cannot
	// be written costs nothing but the line that says so.
	var rec *recording
	if cfg.Pcap != "" {
		if rec, err = record(cfg.Pcap); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		defer rec.close(stderr)
	}

	// Each question is a walk of its own from the root servers down, and the
	// run answers with the worst any of them earned.
	worst := exitAnswer
	for i, question := range questions {
		if i > 0 {
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintln(stdout)
		}
		walk := *cfg
		walk.Name, walk.Type = question.Name, question.Type
		if len(questions) > 1 && cfg.Format != "markdown" {
			// A report heads itself with its question already.
			tree.Asked(stdout, trace.Question{Name: fqdn(question.Name), Type: question.Type}, treeOptions(cfg))
		}
		code := one(ctx, &walk, log, lookups, registry, rec, reference, stdout, stderr)
		if code == exitUsage {
			return code
		}
		worst = worse(worst, code)
	}
	return worst
}

// asked is every question the run puts, read from --names where it was given,
// each checked before any of them is walked.
func asked(cfg *cli.Config) ([]cli.Question, error) {
	questions := cfg.Questions()
	if cfg.Names != "" {
		var err error
		if questions, err = names(cfg.Names); err != nil {
			return nil, err
		}
	}
	for _, question := range questions {
		if err := resolver.Askable(question.Name, question.Type); err != nil {
			if cfg.Names != "" {
				return nil, fmt.Errorf("%w: --names %s: %w", cli.ErrUsage, cfg.Names, err)
			}
			return nil, fmt.Errorf("%w: %w", cli.ErrUsage, err)
		}
	}
	return questions, nil
}

// names reads the questions --names lists, from a file or from the standard
// input where the name is "-".
func names(path string) ([]cli.Question, error) {
	if path == "-" {
		questions, err := cli.ReadQuestions(stdin)
		if err != nil {
			return nil, fmt.Errorf("the standard input: %w", err)
		}
		return questions, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, unopened("--names", err)
	}
	defer file.Close()

	questions, err := cli.ReadQuestions(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return questions, nil
}

// worse is the exit code that says more of two walks: a broken chain of trust,
// then no answer, then an unmet expectation, then an answer. It ranks them the
// way outcome does for one walk.
func worse(a, b int) int {
	rank := map[int]int{exitAnswer: 0, exitExpect: 1, exitNoAnswer: 2, exitBogus: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// one draws one walk, made now or read back with --from, with everything the
// run asked to be said under it.
func one(ctx context.Context, cfg *cli.Config, log *slog.Logger,
	lookups *asn.Resolver, registry *rdap.Client, rec *recording, reference *history.Walk, stdout, stderr io.Writer) int {

	var err error

	// The live drawing owns the screen until it is cleared, and the finished
	// tree is then written exactly where it stood.
	var live *tree.Live
	if cfg.Live {
		live = tree.NewLive(stdout, treeOptions(cfg))
		defer live.Clear()
	}

	var tr *trace.Trace
	if cfg.From != "" {
		if tr, err = saved("--from", cfg.From); err == nil && reference != nil {
			err = sameQuestion(reference, tr.Shown().Question, cfg.Against)
		}
	} else {
		tr, err = made(ctx, cfg, log, lookups, registry, rec, live)
		rec.save(stderr)
	}
	if err != nil {
		live.Clear()
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	// The last frame stays up until there is something to put in its place.
	live.Clear()
	unreported(cfg, tr, stderr)

	// A served walk is drawn in a browser rather than here, and the sentences
	// the run asked for go to the page with it.
	if cli.Serves(cfg.Format) {
		options := web.Options{
			Addr:    cfg.WebAddr,
			Browser: cfg.Browser,
			Scene:   cfg.Format == "web-3d",
			Color:   cfg.Color,
			Version: version,
		}
		if err := web.Serve(ctx, stdout, tr, readings(cfg, tr, reference, stderr), options); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		return outcome(cfg, tr, stderr)
	}

	// A report carries its summary and its sentences inside it, and it always
	// says what the walk came to, asked to explain or not.
	if cfg.Format == "markdown" {
		findings := readings(cfg, tr, reference, stderr)
		if !cfg.Explain {
			findings = append(explain.Findings(tr), findings...)
		}
		if err := markdown.Render(stdout, tr, findings); err != nil {
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
	} else if !cli.Programs(cfg.Format) {
		tree.Summary(stdout, tr, treeOptions(cfg))
	}
	if findings := readings(cfg, tr, reference, stderr); len(findings) > 0 {
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

// made is one whole walk: the resolution, the metadata that runs beside it, and
// the question put to a recursive server for comparison. A run makes one of
// these; --watch makes one after another.
func made(ctx context.Context, cfg *cli.Config, log *slog.Logger,
	lookups *asn.Resolver, registry *rdap.Client, rec *recording, live *tree.Live) (*trace.Trace, error) {

	// The comparison runs beside the walk rather than after it: a recursive
	// server answers in the time one hop of the walk takes, so waiting for it
	// separately would be time spent on metadata.
	timed := compare(ctx, cfg, log)
	checked := policy(ctx, cfg)
	if registry != nil {
		registry.Prepare(ctx)
	}

	tr, err := resolve(ctx, cfg, log, lookups, rec, live)
	if err != nil {
		return nil, err
	}
	if checked != nil {
		tr.SPF = <-checked
	}
	if registry != nil {
		grace, cancel := context.WithTimeout(ctx, rdapGrace)
		tr.Registration = registry.Check(grace, tr)
		cancel()
	}

	if lookups != nil {
		grace, cancel := context.WithTimeout(ctx, asnGrace)
		defer cancel()
		lookups.Annotate(grace, tr)
	}
	if timed != nil {
		tr.Resolvers = <-timed
		recursive.Compare(tr)
	}
	if cfg.Report {
		report(ctx, cfg, tr)
	}
	return tr, nil
}

// policy checks the sender policy of the name beside the walk, through the
// recursive server a mail server would ask. It never touches the trace the walk
// is building: what it found joins it once the walk is over.
func policy(ctx context.Context, cfg *cli.Config) <-chan *trace.SPF {
	if !cfg.SPF {
		return nil
	}
	server := transport.System()
	if len(cfg.Resolvers) > 0 {
		server = cfg.Resolvers[0]
	}
	carrier := transport.NewUDP(transport.Config{Timeout: cfg.Timeout})
	fallback := transport.NewTCP(transport.Config{Timeout: cfg.Timeout})

	checked := make(chan *trace.SPF, 1)
	go func() {
		if !server.IsValid() {
			checked <- &trace.SPF{Name: cfg.Name, Result: trace.SPFUndecided,
				Why: "there is no recursive server to ask; name one with --resolver"}
			return
		}
		lookup := func(ctx context.Context, name, qtype string) *trace.Resolver {
			answer, err := transport.Lookup(ctx, carrier, fallback, server, name, qtype, cfg.Retries)
			if err != nil {
				return nil
			}
			return answer
		}
		found := spf.Check(ctx, cfg.Name, lookup, cmp.Or(cfg.MaxQueries, resolver.DefaultMaxQueries))
		found.Server = trace.Server{IP: server.Addr(), Port: server.Port()}
		checked <- found
	}()
	return checked
}

// report tells the agent the broken zone named that its chain of trust is
// broken (RFC 9567), through the recursive server the comparison asks, the way
// a resolver that hit the failure would.
func report(ctx context.Context, cfg *cli.Config, tr *trace.Trace) {
	server := transport.System()
	if len(cfg.Resolvers) > 0 {
		server = cfg.Resolvers[0]
	}
	carrier := transport.NewUDP(transport.Config{Timeout: cfg.Timeout})
	fallback := transport.NewTCP(transport.Config{Timeout: cfg.Timeout})
	recursive.Report(tr, func(name string) (string, error) {
		if !server.IsValid() {
			return "", errors.New("there is no recursive server to send it through; name one with --resolver")
		}
		return transport.SendReport(ctx, carrier, fallback, server, name)
	})
}

// unreported says why --report sent nothing about a chain it found broken. A
// zone that names no agent has asked for no report, which is its choice; but
// the run asked for one, and silence would read as one sent.
func unreported(cfg *cli.Config, tr *trace.Trace, stderr io.Writer) {
	if !cfg.Report || tr.Report != nil {
		return
	}
	chain := tr.Shown().Chain()
	if chain == nil || chain.DNSSEC.State != trace.Bogus {
		return
	}
	zone := chain.DNSSEC.Zone
	if zone == "" {
		zone = "the zone"
	}
	fmt.Fprintf(stderr, "report: not sent: %s names no agent to report to (RFC 9567)\n", zone)
}

// saved is a walk --format json wrote, read back to be drawn again: from a
// file, or from the standard input where the name is "-". flag is the one that
// named it.
func saved(flag, path string) (*trace.Trace, error) {
	if path == "-" {
		tr, err := jsonout.Read(stdin)
		if err != nil {
			return nil, fmt.Errorf("the standard input: %w", err)
		}
		return tr, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, unopened(flag, err)
	}
	defer file.Close()

	tr, err := jsonout.Read(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return tr, nil
}

// against is the walk --against named, as a comparison reads it. It is dated
// by when it was made rather than when it was read, like any saved walk.
func against(path string) (*history.Walk, error) {
	tr, err := saved("--against", path)
	if err != nil {
		return nil, err
	}
	return history.Of(tr, tr.Started), nil
}

// sameQuestion refuses to compare walks of two questions: every difference
// between them would be one nobody needed telling about.
func sameQuestion(reference *history.Walk, asked trace.Question, path string) error {
	if reference.Asks(asked.Name, asked.Type, asked.Class) {
		return nil
	}
	return fmt.Errorf("%s is a walk of %s %s, and this one is of %s %s", source(path),
		reference.Question.Name, reference.Question.Type, asked.Name, asked.Type)
}

// source is how a saved walk is named in a sentence.
func source(path string) string {
	if path == "-" {
		return "the standard input"
	}
	return path
}

// watch draws the walk once and then keeps making it, saying only what has
// changed since the round before. A round that found nothing changed says
// nothing at all: the whole point of leaving it running is that it stays quiet
// until it does not.
//
// It ends when it is interrupted, or when everything --expect asked for holds,
// and it answers with whatever the last walk it made earned.
func watch(ctx context.Context, cfg *cli.Config, log *slog.Logger,
	lookups *asn.Resolver, registry *rdap.Client, reference *history.Walk, stdout, stderr io.Writer) int {

	var (
		previous *history.Walk
		last     *trace.Trace // the last walk that finished of its own accord
	)
	for round := 0; ; round++ {
		// A drawing cannot be cleared twice, so each round has one of its own:
		// the frames are scratch either way, and what is left behind is the
		// tree of the first round and the lines under it.
		var live *tree.Live
		if cfg.Live {
			live = tree.NewLive(stdout, treeOptions(cfg))
		}

		tr, err := made(ctx, cfg, log, lookups, registry, nil, live)
		live.Clear()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}

		// An interrupt part way through a walk is somebody stopping the watch,
		// not a finding about the name. What that half-made walk came to is
		// nothing to answer with, so the last one that finished on its own is;
		// where none has, nothing was ever established and the walk that was
		// cut short says so.
		if ctx.Err() != nil {
			if last != nil {
				return outcome(cfg, last, stderr)
			}
			return outcome(cfg, tr, stderr)
		}
		last = tr

		when := time.Now()
		current := history.Of(tr, when)

		if round == 0 {
			// The first round is an ordinary run, --diff and all: it is the
			// tree everything after it is read against.
			if err := render(stdout, cfg, tr); err != nil {
				fmt.Fprintln(stderr, err)
				return exitUsage
			}
			if live != nil {
				live.Summary(stdout, tr)
			} else {
				tree.Summary(stdout, tr, treeOptions(cfg))
			}
			if findings := readings(cfg, tr, reference, stderr); len(findings) > 0 {
				tree.Explain(stdout, findings, treeOptions(cfg))
			}
		} else {
			tree.Watched(stdout, history.Differences(previous, current), when, treeOptions(cfg))
		}
		previous = current

		// Nothing left to wait for: everything that was expected of the walk
		// holds, which is what --watch with --expect was asked to wait for.
		code := outcome(cfg, tr, io.Discard)
		if len(cfg.Expect) > 0 && code == exitAnswer {
			return code
		}

		select {
		case <-ctx.Done():
			return outcome(cfg, last, stderr)
		case <-time.After(cfg.Watch):
		}
	}
}

// readings is what is said under the tree: the sentences the trace says about
// itself, and what has changed since the last walk of the same question or
// differs from the one --against named.
func readings(cfg *cli.Config, tr *trace.Trace, reference *history.Walk, stderr io.Writer) []explain.Finding {
	var findings []explain.Finding
	if cfg.Explain {
		findings = append(findings, explain.Findings(tr)...)
	}
	if cfg.Diff {
		findings = append(findings, changed(tr, stderr)...)
	}
	if reference != nil {
		findings = append(findings, history.Against(reference, history.Of(tr, tr.Started), source(cfg.Against))...)
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
func resolve(ctx context.Context, cfg *cli.Config, log *slog.Logger,
	lookups *asn.Resolver, rec *recording, live *tree.Live) (*trace.Trace, error) {
	roots, err := rootServers(cfg)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := clientTLS(cfg)
	if err != nil {
		return nil, err
	}

	carrier := transport.Config{Timeout: cfg.Timeout, Port: cfg.Port, TLS: tlsConfig}
	outage := newOutage(cfg.Without)
	config := resolver.Config{
		Transport: outage.carry(rec.carry(carry(cfg.Proto, carrier))),
		Roots:     roots,
		DNSSEC:    cfg.DNSSEC,
		All:       cfg.All,
		Family:    cfg.Family,
		CheckNS:   cfg.CheckNS,
		CheckDS:   cfg.CheckDS,
		Serial:    cfg.Serial,

		CheckTransfer:  cfg.CheckAXFR,
		CheckRecursion: cfg.CheckRecursion,
		CheckEDNS:      cfg.CheckEDNS,
		CAA:            cfg.CAA,

		NSID:     cfg.NSID,
		Cookie:   cfg.Cookie,
		Minimise: cfg.Minimise,
		Subnet:   cfg.Subnet,
		Retries:  cfg.Retries,
		Budget: resolver.Budget{
			MaxDepth:   cfg.MaxDepth,
			MaxQueries: cfg.MaxQueries,
			MaxCNAME:   cfg.MaxCNAME,
		},
	}
	config.Log = log
	config.Try = cfg.Try
	if len(cfg.Without) > 0 {
		config.Down = outage.left
	}
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
		config.TCP = outage.carry(rec.carry(transport.NewTCP(carrier)))
	}
	if cfg.Fallback {
		config.Fallback = outage.carry(rec.carry(transport.NewUDP(carrier)))
	}
	if cfg.TrustAnchors != "" {
		if config.Anchors, err = roothints.LoadAnchorsFile(cfg.TrustAnchors); err != nil {
			return nil, unopened("--trust-anchors", err)
		}
	}

	engine, err := resolver.New(config)
	if err != nil {
		return nil, err
	}
	tr, err := engine.Resolve(ctx, cfg.Name, cfg.Type)
	outage.record(tr)
	return tr, err
}

// recording is what --pcap keeps of the run's walks, and the file it keeps it
// in. A nil recording keeps nothing.
type recording struct {
	path    string
	file    *os.File
	packets *capture.Capture
}

func record(path string) (*recording, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, unopened("--pcap", err)
	}
	return &recording{path: path, file: file, packets: capture.New()}, nil
}

// carry is inner, with what it sends kept. It goes inside --without, which
// sends nothing.
func (r *recording) carry(inner transport.Transport) transport.Transport {
	if r == nil {
		return inner
	}
	return transport.Recorded(inner, r.packets.Record)
}

// save writes the file over with every walk so far, so that it is whole after
// each of them: --format web serves its walk until it is interrupted. A file
// that cannot be written costs the capture, never the walk.
func (r *recording) save(stderr io.Writer) {
	if r == nil || r.file == nil {
		return
	}
	_, err := r.file.Seek(0, io.SeekStart)
	if err == nil {
		err = r.file.Truncate(0)
	}
	if err == nil {
		_, err = r.packets.WriteTo(r.file)
	}
	if err != nil {
		fmt.Fprintf(stderr, "the capture could not be written to %s: %v\n", r.path, err)
		_ = r.file.Close()
		r.file = nil
	}
}

func (r *recording) close(stderr io.Writer) {
	if r == nil || r.file == nil {
		return
	}
	if err := r.file.Close(); err != nil {
		fmt.Fprintf(stderr, "the capture could not be written to %s: %v\n", r.path, err)
	}
}

// outage is what --without leaves out of a walk, and which of it the walk
// would have asked had it been there.
type outage struct {
	down []transport.Down

	mu   sync.Mutex
	kept map[transport.Down]bool
}

func newOutage(down []transport.Down) *outage {
	return &outage{down: down, kept: make(map[transport.Down]bool)}
}

// left is why the walk may not ask a server, empty when it may. The walk
// draws the server it names as one nobody asked.
func (o *outage) left(server trace.Server) string {
	for _, down := range o.down {
		if down.Covers(server.IP, server.Name) {
			o.keep(down)
			return "left out by --without " + down.String()
		}
	}
	return ""
}

// carry is inner with the outage in front of it. The walk skips what is down
// before it asks; this keeps everything else it asks — the zone's own NS set,
// --serial, the exposure checks, a retry over TCP or the fallback — from
// reaching it either.
func (o *outage) carry(inner transport.Transport) transport.Transport {
	return transport.Without(inner, o.down, o.keep)
}

func (o *outage) keep(down transport.Down) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.kept[down] = true
}

// record writes the outage into the trace. A part the walk never tried to ask
// changed nothing, and an answer would otherwise read as surviving it.
func (o *outage) record(tr *trace.Trace) {
	if tr == nil || len(o.down) == 0 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, down := range o.down {
		tr.Without = append(tr.Without, down.String())
		if !o.kept[down] {
			tr.Warnings = append(tr.Warnings, "--without "+down.String()+
				" left nothing out: the walk came to no server by that name or address, so check the spelling if it should have")
		}
	}
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
		err = unopened("--root-hints", err)
	}
	if err != nil {
		return nil, err
	}
	return resolver.RootServers(hints), nil
}

// unopened names the flag a file that could not be opened was given to, which
// the error from os leaves the user to guess. Any other error passes through.
func unopened(flag string, err error) error {
	if pathErr, ok := errors.AsType[*fs.PathError](err); ok {
		return fmt.Errorf("%s %s: %w", flag, pathErr.Path, pathErr.Err)
	}
	return err
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
		return nil, unopened("--tls-ca", err)
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
func compare(ctx context.Context, cfg *cli.Config, log *slog.Logger) <-chan []*trace.Resolver {
	if !cfg.Compare {
		return nil
	}
	servers := cfg.Resolvers
	if len(servers) == 0 {
		if system := transport.System(); system.IsValid() {
			servers = []netip.AddrPort{system}
		}
	}
	if len(servers) == 0 {
		return nil
	}

	question := trace.Question{Name: cfg.Name, Type: cfg.Type, Class: "IN"}
	carrier := transport.NewUDP(transport.Config{Timeout: cfg.Timeout})
	fallback := transport.NewTCP(transport.Config{Timeout: cfg.Timeout})

	timed := make(chan []*trace.Resolver, 1)
	go func() {
		defer close(timed)

		// They are asked together and kept in the order they were named, so
		// that the same command draws the same line twice running.
		answers := make([]*trace.Resolver, len(servers))
		discovered := make([]*trace.Discovery, len(servers))
		var wait sync.WaitGroup
		for i, server := range servers {
			if cfg.DDR {
				wait.Go(func() { discovered[i] = transport.Discover(ctx, carrier, fallback, server) })
			}
			wait.Go(func() {
				answer, err := transport.Ask(ctx, carrier, server, question, cfg.DNSSEC, cfg.Subnet)
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
				answers[i] = answer
			})
		}
		wait.Wait()
		for i, answer := range answers {
			if answer != nil {
				answer.DDR = discovered[i]
			}
		}

		// A server that could not be asked at all leaves no room of its own:
		// what there is to say about it was said on stderr with --debug, and a
		// gap in the line would be read as a server that answered nothing.
		timed <- slices.DeleteFunc(answers, func(answer *trace.Resolver) bool { return answer == nil })
	}()
	return timed
}

// asnLookup is where the origin AS lookups go. A nil lookup leaves asn.New to
// use the host's own resolver, which is what the Cymru zones normally need.
func asnLookup(cfg *cli.Config) asn.Lookup {
	if len(cfg.Resolvers) == 0 {
		return nil
	}

	// A resolver of its own, dialling the one server, so that the lookups can
	// be pointed somewhere the host knows nothing about. The first of them is
	// the one: the lookups need somewhere to ask, not a poll.
	server := cfg.Resolvers[0].String()
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
	case "mermaid":
		return mermaid.Render(w, tr)
	case "waterfall-mermaid":
		return mermaid.Gantt(w, tr)
	case "waterfall", "waterfall-ascii":
		return tree.Waterfall(w, tr, treeOptions(cfg))
	case "openmetrics":
		return openmetrics.Render(w, tr)
	default:
		return tree.Render(w, tr, treeOptions(cfg))
	}
}

// treeOptions is how the tree is drawn, live and at the end alike.
func treeOptions(cfg *cli.Config) tree.Options {
	switch cfg.Format {
	case "ascii", "waterfall-ascii":
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
	if step := tr.Chain(); step != nil && step.DNSSEC.State == trace.Bogus {
		return exitBogus
	}
	if tr.Result() == nil {
		return exitNoAnswer
	}
	return exitAnswer
}

// fqdn is a name as the trace spells it, with the root's dot.
func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
