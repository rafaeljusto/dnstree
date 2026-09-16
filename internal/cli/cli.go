// Package cli turns command line flags into the configuration the resolver and
// the renderers read.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/render/tree"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// Summary is the one line that says what the tool is, for the places outside
// this package that have to introduce it: the man page, and the packages.
const Summary = "resolve a name from the root servers down, and draw the path it took"

// Usage is the whole help text, and the only description of the flag surface
// this repository keeps. cmd/mkman renders the man page from it, so a flag
// added here reaches the packages without being written out a second time.
const Usage = `usage: dnstree [flags] NAME [TYPE]

Resolve NAME from the root servers down, following every referral, and draw the
path it took. TYPE defaults to A.

  -4, -6                  ask only IPv4 or only IPv6 servers
  --udp, --tcp            carry the queries over plain DNS (--udp is the default)
  --dot, --doh            carry them encrypted, over TLS or HTTPS
  --fallback              let plain DNS pick up a hop the transport could not
  --all                   ask every nameserver of a zone, not just the first
  --dnssec                ask for signatures and follow the chain of trust
  --check-ns              ask each zone for its own NS set and compare
  --no-asn                skip the origin AS lookups
  --format FORMAT         tree, ascii, emoji, json or dot (default tree)
  --live                  draw the tree as the walk makes it
  --color WHEN            auto, always or never (default auto)
  --timeout DURATION      how long one query may take (default 2s)
  --retries N             how often to ask again after a silence (default 1)
  --max-depth N           zone cuts to follow (default 16)
  --max-queries N         queries to make in total (default 64)
  --max-cname N           aliases to chase (default 8)
  --port N                the port nameservers are asked on (default 53)
  --root-hints FILE       where the walk starts, instead of the built-in hints
  --trust-anchors FILE    the DS records to trust, instead of the built-in ones
  --debug                 report every hop on stderr as it is made
  --version               print the version and stop

Exit codes: 0 an answer, 1 a problem with the command, 2 nothing answered,
3 the chain of trust is broken.
`

// Config is a run of dnstree, as the command line asked for it.
type Config struct {
	Name string
	Type string

	Family     int    // 0, 4 or 6
	Proto      string // udp, tcp, dot or doh
	Fallback   bool
	All        bool
	DNSSEC     bool
	CheckNS    bool
	ASN        bool
	Format     string
	Live       bool
	Color      tree.ColorMode
	Timeout    time.Duration
	Retries    int
	MaxDepth   int
	MaxQueries int
	MaxCNAME   int
	Port       uint16

	RootHints    string
	TrustAnchors string
	Debug        bool

	// Version asks for the version and nothing else.
	Version bool
}

// ErrUsage is anything the command line itself got wrong, including a request
// for help.
var ErrUsage = errors.New("cli: the command line cannot be read")

// Parse reads the arguments. Anything it writes, including the usage, goes to
// output.
func Parse(args []string, output io.Writer) (*Config, error) {
	flags := flag.NewFlagSet("dnstree", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() { fmt.Fprint(output, Usage) }

	var (
		cfg           Config
		four, six     bool
		udp, tcp, dot bool
		doh           bool
		noASN         bool
		color, format string
		timeout       time.Duration
		port          uint
	)
	flags.BoolVar(&four, "4", false, "ask only IPv4 servers")
	flags.BoolVar(&six, "6", false, "ask only IPv6 servers")
	flags.BoolVar(&udp, "udp", false, "carry the queries over UDP")
	flags.BoolVar(&tcp, "tcp", false, "carry the queries over TCP")
	flags.BoolVar(&dot, "dot", false, "carry the queries over TLS")
	flags.BoolVar(&doh, "doh", false, "carry the queries over HTTPS")
	flags.BoolVar(&cfg.Fallback, "fallback", false, "let plain DNS pick up a hop the transport could not")
	flags.BoolVar(&cfg.All, "all", false, "ask every nameserver of a zone")
	flags.BoolVar(&cfg.DNSSEC, "dnssec", false, "follow the chain of trust")
	flags.BoolVar(&cfg.CheckNS, "check-ns", false, "compare the parent and child NS sets")
	flags.BoolVar(&noASN, "no-asn", false, "skip the origin AS lookups")
	flags.StringVar(&format, "format", "tree", "tree, ascii, emoji, json or dot")
	flags.BoolVar(&cfg.Live, "live", false, "draw the tree as the walk makes it")
	flags.StringVar(&color, "color", string(tree.ColorAuto), "auto, always or never")
	flags.DurationVar(&timeout, "timeout", transport.DefaultTimeout, "how long one query may take")
	flags.IntVar(&cfg.Retries, "retries", 1, "how often to ask again after a silence")
	flags.IntVar(&cfg.MaxDepth, "max-depth", 0, "zone cuts to follow")
	flags.IntVar(&cfg.MaxQueries, "max-queries", 0, "queries to make in total")
	flags.IntVar(&cfg.MaxCNAME, "max-cname", 0, "aliases to chase")
	flags.UintVar(&port, "port", 0, "the port nameservers are asked on")
	flags.StringVar(&cfg.RootHints, "root-hints", "", "where the walk starts")
	flags.StringVar(&cfg.TrustAnchors, "trust-anchors", "", "the DS records to trust")
	flags.BoolVar(&cfg.Debug, "debug", false, "report every hop on stderr")
	flags.BoolVar(&cfg.Version, "version", false, "print the version and stop")

	if err := flags.Parse(args); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUsage, err)
	}
	if cfg.Version {
		return &cfg, nil
	}

	switch flags.NArg() {
	case 0:
		flags.Usage()
		return nil, fmt.Errorf("%w: no name to resolve", ErrUsage)
	case 1:
		cfg.Name, cfg.Type = flags.Arg(0), "A"
	case 2:
		cfg.Name, cfg.Type = flags.Arg(0), strings.ToUpper(flags.Arg(1))
	default:
		return nil, fmt.Errorf("%w: only a name and a type were expected", ErrUsage)
	}

	if four && six {
		return nil, fmt.Errorf("%w: -4 and -6 ask for opposite things", ErrUsage)
	}
	switch {
	case four:
		cfg.Family = 4
	case six:
		cfg.Family = 6
	}

	var err error
	if cfg.Proto, err = proto(udp, tcp, dot, doh); err != nil {
		return nil, err
	}
	switch format {
	case "tree", "ascii", "emoji", "json", "dot":
		cfg.Format = format
	default:
		return nil, fmt.Errorf("%w: %q is not a format", ErrUsage, format)
	}
	if cfg.Live && (cfg.Format == "json" || cfg.Format == "dot") {
		return nil, fmt.Errorf("%w: %s is written once, at the end, so it cannot be drawn live",
			ErrUsage, cfg.Format)
	}
	switch mode := tree.ColorMode(color); mode {
	case tree.ColorAuto, tree.ColorAlways, tree.ColorNever:
		cfg.Color = mode
	default:
		return nil, fmt.Errorf("%w: %q is not a colour setting", ErrUsage, color)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%w: a timeout of %s leaves no time to answer", ErrUsage, timeout)
	}
	cfg.Timeout = timeout
	if cfg.Retries < 0 {
		return nil, fmt.Errorf("%w: %d retries is not a number of retries", ErrUsage, cfg.Retries)
	}
	if port > 65535 {
		return nil, fmt.Errorf("%w: %d is not a port", ErrUsage, port)
	}
	cfg.Port = uint16(port)
	cfg.ASN = !noASN

	return &cfg, nil
}

// proto settles which transport carries the queries, of which there can only be
// one.
func proto(udp, tcp, dot, doh bool) (string, error) {
	chosen := ""
	for _, carrier := range []struct {
		on   bool
		name string
	}{{udp, "udp"}, {tcp, "tcp"}, {dot, "dot"}, {doh, "doh"}} {
		if !carrier.on {
			continue
		}
		if chosen != "" {
			return "", fmt.Errorf("%w: --%s and --%s cannot both carry the queries", ErrUsage, chosen, carrier.name)
		}
		chosen = carrier.name
	}
	if chosen == "" {
		chosen = "udp"
	}
	return chosen, nil
}
