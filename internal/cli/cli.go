// Package cli turns command line flags into the configuration the resolver and
// the renderers read.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/render/tree"
	"github.com/rafaeljusto/dnstree/internal/render/web"
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
  --subnet PREFIX         ask as though from this client subnet (RFC 7871)
  --no-asn                skip the origin AS lookups
  --no-compare            do not time the same question against a resolver
  --format FORMAT         tree, ascii, emoji, json, dot or web (default tree)
  --web-addr ADDR         where --format web serves the page (default 127.0.0.1:0)
  --no-browser            do not open a browser at the page --format web serves
  --live                  draw the tree as the walk makes it
  --explain               say in sentences what the walk came to
  --diff                  say what has changed since the last walk remembered
  --color WHEN            auto, always or never (default auto)
  --timeout DURATION      how long one query may take (default 2s)
  --retries N             how often to ask again after a silence (default 1)
  --max-depth N           zone cuts to follow (default 16)
  --max-queries N         queries to make in total (default 64)
  --max-cname N           aliases to chase (default 8)
  --port N                the port nameservers are asked on (default 53)
  --root-hints FILE       where the walk starts, instead of the built-in hints
  --root [NAME@]ADDR      one server to start from, instead of a hints file
  --trust-anchors FILE    the DS records to trust, instead of the built-in ones
  --resolver ADDR         the recursive server to use, not the host's own
  --tls-ca FILE           verify --dot and --doh against these roots
  --tls-insecure          do not verify --dot and --doh at all
  --config FILE           take the defaults from FILE, instead of the usual one
  --no-config             take no defaults from a file at all
  --debug                 report every hop on stderr as it is made
  --schema                print the JSON Schema of the json format and stop
  --version               print the version and stop

Repeat --root for every server the walk may start from. Each takes an address,
which may carry a :PORT, optionally introduced by NAME@ to say what the server
answers under; without a port, --port says where it is asked. A walk that starts
somewhere other than the real root usually wants --trust-anchors with it, and
--tls-ca or --tls-insecure to reach a --dot or --doh server holding a test
certificate. --resolver points everything that needs a recursive server at one
of its own: the origin AS lookups, and the question dnstree times against an
ordinary resolution to say what the walk cost over it. --asn-resolver is the
older name for it, and still means the same thing.

--format web draws nothing in the terminal. It serves the finished walk as a
page instead, on this machine and on whatever port is free, and opens a browser
at it: the tree is the same walk with every hop worth clicking on, beside what
each server cost, who they belong to and the chain of trust over them. The page
is served until the command is interrupted. --web-addr moves it, which is what a
walk made on another machine needs, and --no-browser leaves the address to be
opened by hand. Whatever is pointed at the same server can read the walk as
--format json writes it, under /trace.json.

--subnet asks every server the question as though it came from somebody inside
that prefix, which is how a server that tailors its answers by network can be
asked what it tells somewhere else. A bare address is taken as a /24 or a /56,
since the point is the network and not the machine. Each hop says what scope
came back: a scope of zero means that server answers the same for everybody, and
a hop that echoes nothing ignored the subnet altogether. It is sent to every
server on the way down, which is more than any of them needs to know about where
the question came from, so it is off unless it is asked for.

What the command line leaves out is taken from a file of defaults: the one named
by $DNSTREE_CONFIG, then $XDG_CONFIG_HOME/dnstree/config (~/.config/dnstree/config
where that is unset), then ~/.dnstreerc. Each line of it is a long flag name and
the value it takes, such as "format = emoji", "dnssec" or "timeout = 3s". A line
opening with # is a comment, and anything the command line asks for wins. The
file may carry a root line for every server a walk starts from; one --root on
the command line replaces all of them rather than adding to them.

Exit codes:
  0 an answer
  1 a problem with the command
  2 nothing answered
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
	Compare    bool
	Format     string
	Live       bool
	Explain    bool
	Diff       bool
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

	// Roots is what --root asked for, in the order it was given. It replaces
	// the hints entirely, so the two cannot both be set.
	Roots []Root

	// Resolver is the recursive server the origin AS lookups and the timed
	// comparison go to, empty for the host's own.
	Resolver netip.AddrPort

	// TLSCA and TLSInsecure loosen the verification the encrypted transports
	// do, which is what it takes to reach a server holding a test certificate.
	TLSCA       string
	TLSInsecure bool

	// Subnet is the client subnet every query carries, so that a server which
	// answers by network can be asked what it tells somebody else. The zero
	// value sends none.
	Subnet netip.Prefix

	// WebAddr is where --format web serves the page, and Browser whether one is
	// opened at it. A walk names the servers it asked and the addresses they
	// answered from, so the page stays on this machine unless it is moved.
	WebAddr string
	Browser bool

	// ConfigFile is the file the defaults came from, empty when none was read.
	ConfigFile string

	// Schema asks for the JSON Schema of the json format and nothing else. Like
	// Version it answers a question about the command rather than resolving a
	// name, so it needs no name to resolve.
	Schema bool

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
		noCompare     bool
		noBrowser     bool
		noConfig      bool
		configPath    string
		color, format string
		subnet        string
		timeout       time.Duration
		port          uint
		roots         rootList
		resolverAddr  string
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
	flags.StringVar(&subnet, "subnet", "", "ask as though from this client subnet")
	flags.BoolVar(&noASN, "no-asn", false, "skip the origin AS lookups")
	flags.BoolVar(&noCompare, "no-compare", false, "do not time the question against a resolver")
	flags.StringVar(&format, "format", "tree", "tree, ascii, emoji, json, dot or web")
	flags.StringVar(&cfg.WebAddr, "web-addr", "", "where the served page listens")
	flags.BoolVar(&noBrowser, "no-browser", false, "do not open a browser at the served page")
	flags.BoolVar(&cfg.Live, "live", false, "draw the tree as the walk makes it")
	flags.BoolVar(&cfg.Explain, "explain", false, "say in sentences what the walk came to")
	flags.BoolVar(&cfg.Diff, "diff", false, "say what has changed since the last walk remembered")
	flags.StringVar(&color, "color", string(tree.ColorAuto), "auto, always or never")
	flags.DurationVar(&timeout, "timeout", transport.DefaultTimeout, "how long one query may take")
	flags.IntVar(&cfg.Retries, "retries", 1, "how often to ask again after a silence")
	flags.IntVar(&cfg.MaxDepth, "max-depth", 0, "zone cuts to follow")
	flags.IntVar(&cfg.MaxQueries, "max-queries", 0, "queries to make in total")
	flags.IntVar(&cfg.MaxCNAME, "max-cname", 0, "aliases to chase")
	flags.UintVar(&port, "port", 0, "the port nameservers are asked on")
	flags.StringVar(&cfg.RootHints, "root-hints", "", "where the walk starts")
	flags.Var(&roots, "root", "one server to start from")
	flags.StringVar(&cfg.TrustAnchors, "trust-anchors", "", "the DS records to trust")
	flags.StringVar(&resolverAddr, "resolver", "", "the recursive server to use")
	flags.StringVar(&resolverAddr, "asn-resolver", "", "the older name for --resolver")
	flags.StringVar(&cfg.TLSCA, "tls-ca", "", "verify the encrypted transports against these roots")
	flags.BoolVar(&cfg.TLSInsecure, "tls-insecure", false, "do not verify the encrypted transports")
	flags.StringVar(&configPath, "config", "", "take the defaults from this file")
	flags.BoolVar(&noConfig, "no-config", false, "take no defaults from a file")
	flags.BoolVar(&cfg.Debug, "debug", false, "report every hop on stderr")
	flags.BoolVar(&cfg.Schema, "schema", false, "print the JSON Schema of the json format and stop")
	flags.BoolVar(&cfg.Version, "version", false, "print the version and stop")

	// The file is parsed first and the command line over it, so a flag typed
	// out wins by being read last, and only the command line leaves positional
	// arguments behind.
	file, err := chosen(flags, args)
	if err != nil {
		return nil, err
	}
	fileArgs, read, err := defaults(flags, file)
	if err != nil {
		return nil, err
	}
	if read {
		cfg.ConfigFile = file.path
		flags.SetOutput(io.Discard) // the file names its own lines; the usage is about the command line
		err := flags.Parse(override(flags, fileArgs, args))
		flags.SetOutput(output)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrUsage, file.path, err)
		}
	}
	if err := flags.Parse(args); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUsage, err)
	}
	if cfg.Version || cfg.Schema {
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

	if cfg.Proto, err = proto(udp, tcp, dot, doh); err != nil {
		return nil, err
	}
	switch format {
	case "tree", "ascii", "emoji", "json", "dot", "web":
		cfg.Format = format
	default:
		return nil, fmt.Errorf("%w: %q is not a format", ErrUsage, format)
	}
	if cfg.Live && (cfg.Format == "json" || cfg.Format == "dot" || cfg.Format == "web") {
		return nil, fmt.Errorf("%w: %s is written once, at the end, so it cannot be drawn live",
			ErrUsage, cfg.Format)
	}
	if (cfg.Explain || cfg.Diff) && (cfg.Format == "json" || cfg.Format == "dot") {
		return nil, fmt.Errorf("%w: %s is read by a program, which has the whole trace already and no use for prose",
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
	cfg.Compare = !noCompare
	cfg.Browser = !noBrowser

	if cfg.Format == "web" {
		if cfg.WebAddr == "" {
			cfg.WebAddr = web.DefaultAddr
		}
	} else if cfg.WebAddr != "" || noBrowser {
		return nil, fmt.Errorf("%w: only --format web serves a page", ErrUsage)
	}

	if subnet != "" {
		if cfg.Subnet, err = clientSubnet(subnet); err != nil {
			return nil, fmt.Errorf("%w: --subnet %w", ErrUsage, err)
		}
	}

	if cfg.Roots = roots.servers; len(cfg.Roots) > 0 && cfg.RootHints != "" {
		return nil, fmt.Errorf("%w: --root and --root-hints both say where the walk starts", ErrUsage)
	}
	if resolverAddr != "" {
		if !cfg.ASN && !cfg.Compare {
			return nil, fmt.Errorf("%w: --no-asn and --no-compare leave --resolver nothing to answer", ErrUsage)
		}
		if cfg.Resolver, err = address(resolverAddr, transport.PortDNS); err != nil {
			return nil, fmt.Errorf("%w: --resolver %w", ErrUsage, err)
		}
	}
	if (cfg.TLSCA != "" || cfg.TLSInsecure) && cfg.Proto != "dot" && cfg.Proto != "doh" {
		return nil, fmt.Errorf("%w: only --dot and --doh use TLS", ErrUsage)
	}
	if cfg.TLSCA != "" && cfg.TLSInsecure {
		return nil, fmt.Errorf("%w: --tls-insecure verifies nothing, so --tls-ca has nothing to verify against", ErrUsage)
	}

	return &cfg, nil
}

// The prefix lengths a bare address is read as. The subnet says which network
// is asking, and a whole address would say which machine, which is more than
// the question needs and more than RFC 7871 wants sent.
const (
	defaultSubnetV4 = 24
	defaultSubnetV6 = 56
)

// clientSubnet reads what --subnet was given: a prefix, or a bare address that
// stands for the network around it.
func clientSubnet(value string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(value); err == nil {
		bits := defaultSubnetV4
		if !addr.Unmap().Is4() {
			bits = defaultSubnetV6
		}
		return netip.PrefixFrom(addr.Unmap(), bits).Masked(), nil
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither an address nor a prefix", value)
	}
	if prefix.Addr().Is4In6() {
		// An IPv4 address written the long way keeps IPv6 prefix lengths, which
		// would then be sent as an IPv6 subnet nobody is in.
		return netip.Prefix{}, fmt.Errorf("%q writes an IPv4 address as IPv6; give it as IPv4", value)
	}
	return prefix.Masked(), nil
}

// Root is a server a walk may start from, as --root spelled it. A zero port
// leaves the choice to the transport, the way the built-in hints do.
type Root struct {
	Name string
	Addr netip.AddrPort
}

// rootList collects the --root flags in the order they were given. The flag
// package has no repeated value of its own, so this is the seam for one.
type rootList struct{ servers []Root }

func (l *rootList) String() string {
	names := make([]string, 0, len(l.servers))
	for _, root := range l.servers {
		names = append(names, root.Addr.String())
	}
	return strings.Join(names, ",")
}

// Set reads one --root: an address, optionally carrying a port, and optionally
// introduced by the name the server answers under. The name is worth giving
// when the transport verifies a certificate against it, and shows in the tree
// either way.
func (l *rootList) Set(value string) error {
	name, addr, named := strings.Cut(value, "@")
	if !named {
		name, addr = "", value
	}
	if addr == "" {
		return fmt.Errorf("%q names no address", value)
	}

	// Zero leaves the port to the transport, so --port still reaches a root
	// that did not ask for one of its own.
	parsed, err := address(addr, 0)
	if err != nil {
		return err
	}
	l.servers = append(l.servers, Root{Name: fqdn(name), Addr: parsed})
	return nil
}

// address reads an IP address that may carry a port, falling back to standard
// when it does not. An IPv6 address only needs its brackets when a port
// follows it.
func address(value string, standard uint16) (netip.AddrPort, error) {
	if addr, err := netip.ParseAddr(value); err == nil {
		return netip.AddrPortFrom(addr, standard), nil
	}
	addrPort, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an address", value)
	}
	if addrPort.Port() == 0 {
		// Zero is how an address says it carries no port, so writing it out
		// would mean two things at once.
		return netip.AddrPort{}, fmt.Errorf("%q asks for port 0", value)
	}
	return addrPort, nil
}

// fqdn is a server name as the trace spells one, empty staying empty.
func fqdn(name string) string {
	if name == "" || strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
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
