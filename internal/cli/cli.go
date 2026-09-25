// Package cli turns command line flags into the configuration the resolver and
// the renderers read.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/expect"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
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

  -x ADDR                 resolve the PTR of this address, instead of a name
  -4, -6                  ask only IPv4 or only IPv6 servers
  --udp, --tcp            carry the queries over plain DNS (--udp is the default)
  --dot, --doh            carry them encrypted, over TLS or HTTPS
  --fallback              let plain DNS pick up a hop the transport could not
  --all                   ask every nameserver of a zone, not just the first
  --dnssec                ask for signatures and follow the chain of trust
  --check-ns              ask the zone that answered for its NS set and compare
  --check-ds              ask the zone for its CDS and CDNSKEY and compare
  --serial                ask every nameserver of the zone which copy it serves
  --nsid                  ask each server which of itself answered (RFC 5001)
  --cookie                send each server a DNS cookie and say how it answered
  --qmin                  ask each zone for no more of the name than it needs
  --subnet PREFIX         ask as though from this client subnet (RFC 7871)
  --no-asn                skip the origin AS lookups
  --no-compare            do not time the same question against a resolver
  --format FORMAT         tree, ascii, emoji, json, dot, mermaid or web
  --web-addr ADDR         where --format web serves the page (default 127.0.0.1:0)
  --no-browser            do not open a browser at the page --format web serves
  --live                  draw the tree as the walk makes it
  --watch DURATION        walk again this often, and say only what changed
  --explain               say in sentences what the walk came to
  --diff                  say what has changed since the last walk remembered
  --expect VALUE          require this of the walk, and exit 4 where it fails
  --from FILE             draw a walk --format json saved, instead of walking
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
  --resolver ADDR         a recursive server to use, not the host's own; repeat it
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

Repeat --resolver to put the question to every one of them at once, which is
how to ask from several places at the same moment: two resolvers answering
differently are two views of one name, and which of them somebody gets depends
only on which resolver they use. The summary says how far apart they were and
how many disagreed, and each one that did is named under the tree. The origin AS
lookups go to the first of them, since they need somewhere to ask rather than a
poll. One --resolver on the command line replaces every one the file of defaults
chose, rather than adding to them.

--format web draws nothing in the terminal. It serves the finished walk as a
page instead, on this machine and on whatever port is free, and opens a browser
at it: the tree is the same walk with every hop worth clicking on, beside what
each server cost, who they belong to and the chain of trust over them. The page
is served until the command is interrupted. --web-addr moves it, which is what a
walk made on another machine needs, and --no-browser leaves the address to be
opened by hand. Whatever is pointed at the same server can read the walk as
--format json writes it, under /trace.json.

-x resolves the PTR record of an address, the way dig -x does: 192.0.2.1 is
asked as 1.2.0.192.in-addr.arpa. and an IPv6 address under ip6.arpa. It takes
the place of NAME and TYPE. The reverse tree is delegated like any other, and
a delegation below a /24 (RFC 2317) arrives as an alias, which is followed.

--check-ds asks the zone the walk ends in for the CDS and CDNSKEY records it
publishes (RFC 7344, RFC 8078), which is how a zone asks its parent to change
the DS that vouches for it, and holds them against the DS the parent holds. A
zone asking for a key the parent has not published is a rollover waiting on
the parent; a zone asking for no DS at all is asking to be made insecure. The
request counts only once it is signed by the keys the chain of trust reached,
so it needs --dnssec; a file of defaults that sets it is heeded only by the
runs that check signatures. It costs two queries.

--format mermaid writes the same picture as --format dot, for the places that
draw Mermaid rather than Graphviz: pasted into a fenced mermaid block, GitHub,
GitLab and most wikis draw it where it stands.

--from reads a walk that --format json wrote, from FILE or from - for the
standard input, and draws it in whichever format was asked for, as though it
had just been made: a walk from a machine nobody else can reach can be drawn,
explained and checked with --expect anywhere. Nothing is asked of any server, so
it takes no name, refuses the flags that shape a walk being made, and a
signature's time left is read against when the walk was made rather than
against the clock. It cannot be drawn live, watched or held
against the walk remembered with --diff, since it is not a walk being made now.

--subnet asks every server the question as though it came from somebody inside
that prefix, which is how a server that tailors its answers by network can be
asked what it tells somewhere else. A bare address is taken as a /24 or a /56,
since the point is the network and not the machine. Each hop says what scope
came back: a scope of zero means that server answers the same for everybody, and
a hop that echoes nothing ignored the subnet altogether. It is sent to every
server on the way down, which is more than any of them needs to know about where
the question came from, so it is off unless it is asked for.

--watch draws the tree once and then walks the same question again, waiting
this long between one walk and the next, saying only what has changed since the
walk before it. A round that finds nothing changed says nothing: silence is what
it is for. Each round is a whole walk from the root servers down, so an interval
is a thing to choose rather than to make as small as possible, and anything
under a second is refused.

It ends when it is interrupted, and exits with whatever the last walk it made
earned. With --expect it ends as soon as everything expected of the walk holds,
which is how to wait for a change to arrive rather than to keep asking whether
it has. With --diff the first round is compared with the walk remembered from
last time and remembers itself in its place; the rounds after it compare with
the round before and write nothing.

--expect says what the walk should have come to, and is how a script asks
rather than reads. It takes one of the words that name how far the chain of
trust got (secure, insecure, bogus, indeterminate), or what the walk came to
(answer, cname, nodata, nxdomain), or fresh, which asks for a chain of trust
that holds and none of whose signatures is late in the life it was made for;
fresh:3d or fresh:36h asks instead that none runs out that soon. Or else it
takes the rdata of a record that has to be among the answers, such as an
address. Repeat it for every one that has to hold.
Those words win where a value could be read either way, so a record whose rdata
reads like one of them is asked for with a leading =, which expects rdata and
nothing else.

An expectation that fails is said on stderr and exits 4, and the walk's own
verdict wins where there is one: a broken chain of trust or an answer that never
came is a bigger fact than an address that is not the one somebody wanted, and a
script that read 4 for either would go looking in the wrong place.

--serial asks every nameserver of the zone the walk ends in for that zone's
start of authority, and says so when they do not all serve the same copy of it.
A walk stops at the first nameserver that answers, so a secondary left behind by
a zone transfer is invisible to everything else here: it answers the question
correctly, out of an older zone. It costs a query per nameserver, and which of
the serials is the newer one is not claimed, because serial arithmetic wraps.

--all sees the other half of the same thing without being asked to: where it
puts the question itself to every nameserver of a zone, it says so when they do
not all answer it alike.

--qmin asks each zone for no more of the name than it needs in order to say
where the next zone cut is (RFC 9156), the way resolvers do by default now: the
root is asked about com., not about www.example.com. Each hop that asked less
than the whole name says so in its margin. It is how to see a server that
answers NXDOMAIN for a name only because nothing is at it yet, which stops a
resolver that minimises and never troubles one that does not. It costs a query
for every label below the zone that answers.

--nsid asks every server for the name it goes by (RFC 5001), and draws it
beside the address. One anycast address is a great many machines in a great many
places, and the identifier is the only thing in a reply that says which of them
answered: two hops that look like the same server may be a continent apart. It
rides along on queries that are being made anyway and costs none of its own. A
server that publishes no identifier says nothing, and its hop reads as it would
without the flag.

--cookie sends every server a DNS cookie (RFC 7873) and says on each hop how it
answered: cookie, no cookie, cookie not ours, cookie malformed or cookie
rejected. A server that supports cookies is sent back the one it handed out, the
way a resolver would, and one that answers BADCOOKIE is asked again with it,
once. Each server gets a client cookie of its own, made fresh for the run. It
rides along on queries over udp and tcp, which are the ones it protects, and
costs none of its own.

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
  3 the chain of trust is broken
  4 an expectation was not met.

`

// Config is a run of dnstree, as the command line asked for it.
type Config struct {
	Name string
	Type string

	Family   int    // 0, 4 or 6
	Proto    string // udp, tcp, dot or doh
	Fallback bool
	All      bool
	DNSSEC   bool
	CheckNS  bool
	CheckDS  bool
	Serial   bool
	NSID     bool
	Cookie   bool
	Minimise bool
	ASN      bool
	Compare  bool
	Format   string
	Live     bool
	Explain  bool
	Diff     bool

	// Expect is what the run was told to require of the walk, in the order it
	// was asked for. Every one of them has to hold.
	Expect []expect.Expectation

	Color tree.ColorMode

	// Watch is how long to wait between one walk and the next, zero for a run
	// that makes one walk and stops.
	Watch time.Duration

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

	// Resolvers are the recursive servers the timed comparison goes to, in the
	// order they were named, empty for the host's own. The origin AS lookups
	// use the first of them: they need one server to ask, not a poll.
	Resolvers []netip.AddrPort

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

	// From is a walk --format json saved, to be drawn instead of making one:
	// a path, or "-" for the standard input. The name and the type are the
	// ones the walk was made for.
	From string

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
		reverse       string
		timeout       time.Duration
		port          uint
		roots         rootList
		wanted        expectList
		resolvers     resolverList
	)
	flags.StringVar(&reverse, "x", "", "resolve the PTR of this address")
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
	flags.BoolVar(&cfg.CheckDS, "check-ds", false, "compare the zone's CDS and CDNSKEY with its DS")
	flags.BoolVar(&cfg.Serial, "serial", false, "ask every nameserver of the zone which copy it serves")
	flags.BoolVar(&cfg.NSID, "nsid", false, "ask each server which of itself answered")
	flags.BoolVar(&cfg.Cookie, "cookie", false, "send each server a DNS cookie and say how it answered")
	flags.BoolVar(&cfg.Minimise, "qmin", false, "ask each zone for no more of the name than it needs")
	flags.StringVar(&subnet, "subnet", "", "ask as though from this client subnet")
	flags.BoolVar(&noASN, "no-asn", false, "skip the origin AS lookups")
	flags.BoolVar(&noCompare, "no-compare", false, "do not time the question against a resolver")
	flags.StringVar(&format, "format", "tree", "tree, ascii, emoji, json, dot, mermaid or web")
	flags.StringVar(&cfg.WebAddr, "web-addr", "", "where the served page listens")
	flags.BoolVar(&noBrowser, "no-browser", false, "do not open a browser at the served page")
	flags.BoolVar(&cfg.Live, "live", false, "draw the tree as the walk makes it")
	flags.DurationVar(&cfg.Watch, "watch", 0, "walk again this often, and say only what changed")
	flags.BoolVar(&cfg.Explain, "explain", false, "say in sentences what the walk came to")
	flags.BoolVar(&cfg.Diff, "diff", false, "say what has changed since the last walk remembered")
	flags.Var(&wanted, "expect", "require this of the walk")
	flags.StringVar(&cfg.From, "from", "", "draw a walk --format json saved")
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
	flags.Var(&resolvers, "resolver", "a recursive server to use")
	flags.Var(&resolvers, "asn-resolver", "the older name for --resolver")
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
	switch mode := tree.ColorMode(color); mode {
	case tree.ColorAuto, tree.ColorAlways, tree.ColorNever:
		cfg.Color = mode
	default:
		return nil, fmt.Errorf("%w: %q is not a colour setting", ErrUsage, color)
	}

	switch format {
	case "tree", "ascii", "emoji", "json", "dot", "mermaid", "web":
		cfg.Format = format
	default:
		return nil, fmt.Errorf("%w: %q is not a format", ErrUsage, format)
	}

	if cfg.Version || cfg.Schema {
		return &cfg, nil
	}

	switch n := flags.NArg(); {
	case cfg.From != "" && (n > 0 || reverse != ""):
		return nil, fmt.Errorf("%w: --from draws a walk already made, so there is no name to resolve", ErrUsage)
	case cfg.From != "":
	case reverse != "" && n > 0:
		return nil, fmt.Errorf("%w: -x names what to resolve, so a name cannot be given as well", ErrUsage)
	case reverse != "":
		addr, err := netip.ParseAddr(reverse)
		if err != nil {
			return nil, fmt.Errorf("%w: -x %q is not an address", ErrUsage, reverse)
		}
		cfg.Name, cfg.Type = reverseName(addr.Unmap()), "PTR"
	case n == 0:
		flags.Usage()
		return nil, fmt.Errorf("%w: no name to resolve", ErrUsage)
	case n == 1:
		cfg.Name, cfg.Type = flags.Arg(0), "A"
	case n == 2:
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
	if cfg.Live && once(cfg.Format) {
		return nil, fmt.Errorf("%w: %s is written once, at the end, so it cannot be drawn live",
			ErrUsage, cfg.Format)
	}
	if cfg.Watch != 0 && once(cfg.Format) {
		return nil, fmt.Errorf("%w: %s is written once, at the end, so there is nothing to watch it change",
			ErrUsage, cfg.Format)
	}
	if cfg.CheckDS && !cfg.DNSSEC {
		// Typed out, it is a mistake to say so. From the file it is a default
		// for the walks that check signatures, and this one does not.
		named := false
		scan(flags, args, func(name, _ string) { named = named || name == "check-ds" })
		if named {
			return nil, fmt.Errorf("%w: --check-ds weighs a signed request, and only --dnssec checks signatures", ErrUsage)
		}
		cfg.CheckDS = false
	}
	if cfg.From != "" {
		// Named on the command line, a flag that shapes the walk would read as
		// though the saved one had been made with it. The file's are about the
		// walks it makes, and are left alone.
		var walking []string
		scan(flags, args, func(name, _ string) {
			if walkFlags[name] {
				walking = append(walking, "--"+name)
			}
		})
		if len(walking) > 0 {
			return nil, fmt.Errorf("%w: --from draws a walk already made, which %s cannot change",
				ErrUsage, strings.Join(walking, " and "))
		}
		switch {
		case cfg.Live:
			return nil, fmt.Errorf("%w: --from draws a walk already made, so there is nothing to draw live", ErrUsage)
		case cfg.Watch != 0:
			return nil, fmt.Errorf("%w: --from draws a walk already made, so there is nothing to watch change", ErrUsage)
		case cfg.Diff:
			return nil, fmt.Errorf("%w: --from draws a walk already made, and remembering it would put an old walk in place of the last one", ErrUsage)
		}
	}
	// Every round is a whole walk from the root servers down. There is nothing
	// a change window needs below a second, and a loop tighter than that is
	// only a way of being rude to somebody else's nameservers.
	if cfg.Watch != 0 && cfg.Watch < time.Second {
		return nil, fmt.Errorf("%w: %s between one walk and the next is too little; a second is the least",
			ErrUsage, cfg.Watch)
	}
	if (cfg.Explain || cfg.Diff) && programs(cfg.Format) {
		return nil, fmt.Errorf("%w: %s is read by a program, which has the whole trace already and no use for prose",
			ErrUsage, cfg.Format)
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
	cfg.Expect = wanted.want
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
	if cfg.Resolvers = resolvers.servers; len(cfg.Resolvers) > 0 && !cfg.ASN && !cfg.Compare {
		return nil, fmt.Errorf("%w: --no-asn and --no-compare leave --resolver nothing to answer", ErrUsage)
	}
	if (cfg.TLSCA != "" || cfg.TLSInsecure) && cfg.Proto != "dot" && cfg.Proto != "doh" {
		return nil, fmt.Errorf("%w: only --dot and --doh use TLS", ErrUsage)
	}
	if cfg.TLSCA != "" && cfg.TLSInsecure {
		return nil, fmt.Errorf("%w: --tls-insecure verifies nothing, so --tls-ca has nothing to verify against", ErrUsage)
	}

	return &cfg, nil
}

// walkFlags are the flags that shape a walk being made, and say nothing about
// one already made.
var walkFlags = map[string]bool{
	"4": true, "6": true, "udp": true, "tcp": true, "dot": true, "doh": true, "fallback": true,
	"all": true, "dnssec": true, "check-ns": true, "check-ds": true, "serial": true, "nsid": true, "cookie": true, "qmin": true,
	"subnet": true, "no-asn": true, "no-compare": true, "timeout": true, "retries": true,
	"max-depth": true, "max-queries": true, "max-cname": true, "port": true, "root-hints": true,
	"root": true, "trust-anchors": true, "resolver": true, "asn-resolver": true,
	"tls-ca": true, "tls-insecure": true,
}

// once reports whether a format is written once, at the end, which leaves
// nothing to draw live and nothing to watch change.
func once(format string) bool {
	return programs(format) || format == "web"
}

// programs reports whether a format is read by a program rather than a person,
// which has the whole trace already and no use for prose under it.
func programs(format string) bool {
	return format == "json" || format == "dot" || format == "mermaid"
}

// reverseName is the name the PTR of an address is kept under: its octets in
// reverse under in-addr.arpa., or its nibbles in reverse under ip6.arpa.
func reverseName(addr netip.Addr) string {
	var labels []string
	if addr.Is4() {
		octets := addr.As4()
		for i := len(octets) - 1; i >= 0; i-- {
			labels = append(labels, strconv.Itoa(int(octets[i])))
		}
		return strings.Join(labels, ".") + ".in-addr.arpa."
	}
	const hex = "0123456789abcdef"
	bytes := addr.As16()
	for i := len(bytes) - 1; i >= 0; i-- {
		labels = append(labels, string(hex[bytes[i]&0x0f]), string(hex[bytes[i]>>4]))
	}
	return strings.Join(labels, ".") + ".ip6.arpa."
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

// expectList collects the --expect flags in the order they were given, reading
// each one as it arrives so that a value nothing can be made of is reported
// against the flag that carried it rather than at the end of the walk.
type expectList struct{ want []expect.Expectation }

func (l *expectList) String() string {
	said := make([]string, 0, len(l.want))
	for _, expectation := range l.want {
		said = append(said, expectation.String())
	}
	return strings.Join(said, ",")
}

func (l *expectList) Set(text string) error {
	expectation, err := expect.Parse(text)
	if err != nil {
		return err
	}
	l.want = append(l.want, expectation)
	return nil
}

// resolverList collects the --resolver flags in the order they were given. More
// than one asks the same question from more than one place at once, which is
// what says whether an answer has reached everybody yet.
type resolverList struct{ servers []netip.AddrPort }

func (l *resolverList) String() string {
	named := make([]string, 0, len(l.servers))
	for _, server := range l.servers {
		named = append(named, server.String())
	}
	return strings.Join(named, ",")
}

func (l *resolverList) Set(text string) error {
	server, err := address(text, transport.PortDNS)
	if err != nil {
		return err
	}
	l.servers = append(l.servers, server)
	return nil
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
