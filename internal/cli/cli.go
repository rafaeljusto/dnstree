// Package cli turns command line flags into the configuration the resolver and
// the renderers read.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/expect"
	"github.com/rafaeljusto/dnstree/v2/internal/idn"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/render/web"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// Summary is the one line that says what the tool is, for the places outside
// this package that have to introduce it: the man page, and the packages.
const Summary = "resolve a name from the root servers down, and draw the path it took"

// Usage is the whole help text, and the only description of the flag surface
// this repository keeps. cmd/mkman renders the man page from it, so a flag
// added here reaches the packages without being written out a second time.
const Usage = `usage: dnstree [flags] NAME [TYPE...]

Resolve NAME from the root servers down, following every referral, and draw the
path it took. TYPE defaults to A; ANY, AXFR and IXFR are refused. A NAME in any
script is asked in punycode, the way the DNS holds it. Several types are walked
one after another, each from the root servers down.

  -x ADDR                 resolve the PTR of this address, instead of a name
  --names FILE            walk every NAME [TYPE...] line of FILE, or of - for stdin
  -4, -6                  ask only IPv4 or only IPv6 servers
  --udp, --tcp            carry the queries over plain DNS (--udp is the default)
  --dot, --doh            carry them encrypted, over TLS or HTTPS
  --fallback              let plain DNS pick up a hop the transport could not
  --all                   ask every nameserver of a zone, not just the first
  --dnssec                ask for signatures and follow the chain of trust
  --check-ns              ask the zone for its NS set and glue, and compare
  --check-ds              ask the zone for its CDS and CDNSKEY and compare
  --serial                ask every nameserver of the zone which copy it serves
  --check-axfr            ask each nameserver of the zone to hand over all of it
  --check-recursion       ask each nameserver of the zone to resolve another name
  --check-edns            ask each nameserver of the zone the RFC 8906 edns tests
  --caa                   say which certificate authorities may issue for NAME
  --spf                   draw NAME's SPF policy and count the lookups it costs
  --mail                  check NAME's MX hosts for DANE, and its mail policies
  --svcb                  follow NAME's HTTPS or SVCB records to their servers
  --rdap                  ask the registry when the domain expires, and compare
  --propagation           say how long a change takes to reach every cache
  --check                 run the checks that grade a zone, and grade its health
  --nsid                  ask each server which of itself answered (RFC 5001)
  --cookie                send each server a DNS cookie and say how it answered
  --qmin                  ask each zone for no more of the name than it needs
  --without SERVER        treat a nameserver, address or prefix as down; repeat it
  --try-ns ZONE=SERVER    walk as though ZONE were delegated to SERVER; repeat it
  --subnet PREFIX         ask as though from this client subnet (RFC 7871)
  --no-asn                skip the origin AS lookups
  --no-compare            do not time the same question against a resolver
  --ddr                   ask each resolver which encrypted resolvers stand for it
  --report                report a bogus chain to the agent the zone names (RFC 9567)
  --format FORMAT         how to draw the walk: tree, waterfall, json, web; see below
  --web-addr ADDR         where --format web serves the page (default 127.0.0.1:0)
  --no-browser            do not open a browser at the page --format web serves
  --live                  draw the tree as the walk makes it
  --watch DURATION        walk again this often, and say only what changed
  --explain               say in sentences what the walk came to
  --diff                  say what has changed since the last walk remembered
  --expect VALUE          require this of the walk, and exit 4 where it fails
  --from FILE             draw a walk --format json saved, instead of walking
  --against FILE          say how the walk differs from one --format json saved
  --pcap FILE             save the walk's queries and answers as a packet capture
  --color WHEN            auto, always or never (default auto)
  --timeout DURATION      how long one query may take (default 2s)
  --retries N             how often to ask again after a silence (default 1)
  --max-depth N           zone cuts to follow (default 16)
  --max-queries N         queries to make in all (64; 256 --all, 512 --check)
  --max-cname N           aliases to chase (default 8)
  --port N                the port to ask on (53; 853 with --dot, 443 with --doh)
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
of its own: the origin AS lookups, the question dnstree times against an
ordinary resolution to say what the walk cost over it, the report --report
sends and the lookups --spf makes. --asn-resolver is the older name for it, and still means the same thing.

Repeat --resolver to put the question to every one of them at once, which is
how to ask from several places at the same moment: two resolvers answering
differently are two views of one name, and which of them somebody gets depends
only on which resolver they use. The summary says how far apart they were and
how many disagreed, and each one that did is named under the tree. The origin AS
lookups go to the first of them, since they need somewhere to ask rather than a
poll. One --resolver on the command line replaces every one the file of defaults
chose, rather than adding to them.

FORMAT is one of tree (the default), ascii, emoji, waterfall, waterfall-ascii,
waterfall-mermaid, markdown, json, dot, mermaid, openmetrics, web or web-3d.

--format web draws nothing in the terminal. It serves the finished walk as a
page instead, on this machine and on whatever port is free, and opens a browser
at it: the tree is the same walk with every hop worth clicking on, beside what
each server cost, who they belong to and the chain of trust over them. The page
is served until the command is interrupted. --web-addr moves it, which is what a
walk made on another machine needs, and --no-browser leaves the address to be
opened by hand. Whatever is pointed at the same server can read the walk as
--format json writes it, under /trace.json. --format web-3d serves the same walk
the same way, drawn as a scene to turn around rather than a tree to read, and
takes --web-addr and --no-browser as well.

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

--propagation reads the TTLs the walk saw and says how long each kind of
change to the zone it ended in takes to reach every cache: the answer, a
record that did not exist, the nameservers, the DS and the keys. Each is the
worst case, a cache filled just before the change; a resolver that caps TTLs
lets go sooner. The parent's NS TTL is read from the referral and the zone's
own only with --check-ns, the SOA from a denial or --serial, and the DS and
DNSKEY TTLs only with --dnssec. It asks nothing more, and works with --from.

--check runs together the checks that grade the zone the walk ends in, and
grades it one area at a time: the answer, the delegation, whether every
nameserver serves the same copy, the chain of trust, the zone's own servers,
EDNS and cookies, CAA, mail and the registration. It is --dnssec, --all,
--check-ns, --check-ds, --serial, --check-edns, --cookie, --caa, --spf, --mail
and --rdap together, with a budget of 512 queries unless --max-queries says
otherwise. Each area passed, is worth a look, is broken, or was skipped, and the
line says the worst of what it found. Zone transfers and recursion are asked of
the servers as a stranger would, which is for the zone's owner to choose, so
they are graded only when --check-axfr or --check-recursion is named as well.
A name that is an alias is graded at the zone its target is in, which is where
the checks run. It is drawn by tree, ascii, emoji, markdown and json, and
--from draws a saved one again. The exit code is the walk's own; --expect
check:ok fails on anything broken.

--report tells a zone its chain of trust is broken, the way RFC 9567 lets a
zone ask: when the walk comes out bogus and the broken zone named a reporting
agent, a TXT lookup of the name the RFC builds goes to the first --resolver,
or the host's own. Every hop that names an agent draws it, with or without
the flag. A report tells a third party that this machine looked up this name,
so it needs --dnssec, is never sent from --watch, and the file of defaults
cannot set it. A bogus zone that names no agent is said in one line on stderr.

--format mermaid writes the same picture as --format dot, for the places that
draw Mermaid rather than Graphviz: pasted into a fenced mermaid block, GitHub,
GitLab and most wikis draw it where it stands.

--format waterfall draws the walk as a timeline instead of a tree: one row per
query, a bar from when it went out to when it came back, on the scale of the
whole walk, the way the network tab of a browser draws a page loading. It shows
where the time went: a slow server, a detour to find a nameserver's address,
a retry after a silence, and with --all what was asked at the same time.
The asides are drawn lighter than the walk's own queries. waterfall-ascii
draws it with # and . for pasting into a document, and waterfall-mermaid
writes it as a Mermaid gantt chart. A walk saved with --format json before
dnstree kept when each query started cannot be drawn this way, and is refused.

--format markdown writes the walk as a report to paste into a ticket, an
incident write-up or a pull request: a heading that says what the walk came to
and when it was made, the tree in a code fence, what --explain would say about
it, and a table of what the resolvers answered. It always explains, and takes
--diff and --against to add what changed. Everything a server wrote is escaped,
so a name or a record cannot turn into a link, a mention or a table cell of its
own. With --from, a walk saved during an incident becomes a report afterwards.

--format openmetrics writes the walk as numbers for a monitoring system: how
it ended, what it and each hop on the path took, the chain of trust, the time
left on the signatures, what --check-ds found, which nameservers the
--check-axfr and --check-recursion probes found open, which --check-edns tests
passed, who --caa found free to issue, how many lookups --spf counted, how many
MX hosts --mail found DANE covering and which mail policies it found, how many
of the targets --svcb found have an address and how many of their hints are
stray, how long
--rdap found the registration has left and what the resolvers answered, each
labelled with the question. Run from cron into the
directory of node_exporter's textfile collector, it is what Prometheus alerts
on.

--from reads a walk that --format json wrote, from FILE or from - for the
standard input, and draws it in whichever format was asked for, as though it
had just been made: a walk from a machine nobody else can reach can be drawn,
explained and checked with --expect anywhere. Nothing is asked of any server, so
it takes no name, refuses the flags that shape a walk being made, and a
signature's time left is read against when the walk was made rather than
against the clock. It cannot be drawn live, watched or held
against the walk remembered with --diff, since it is not a walk being made now.

--against holds the walk against one --format json saved, and says under the
tree what differs: the answer, its TTL, the zone cuts, their nameservers and the
chain of trust over them, as --diff does. The walk drawn can be one made now or
one read with --from, so --from after.json --against before.json compares two
walks made before and after a change, or from two places. The file is read as the
walk before the one drawn, and the first line says how far apart the two were
made. Both have to be of the same question, and nothing is written to the disk.
It takes the place of --diff.

--pcap writes every query the walk sent, and every answer that came back, to
FILE as a packet capture for Wireshark or tcpdump -r. The messages are the bytes
that crossed the wire, and the servers, ports and times are real; the IP, UDP
and TCP headers around them are rebuilt, with dnstree's side written as
192.0.2.1 or 2001:db8::1, so the capture says nothing of the machine it was made
on. Only the walk's own queries are kept, retries and probes included: the
question timed against a resolver and the origin AS lookups are not. Over --dot
and --doh what crossed the wire was TLS, which a capture of plain DNS would
misrepresent, so they are refused. Every walk of the run goes into the one file,
which is written over; the file of defaults cannot set it.

--names reads the questions from FILE, or from the standard input where it is
-, one to a line and written as on the command line: a name, then the types to
ask of it, A where there are none. Blank lines and lines opening with # are
skipped. Every question is a walk of its own from the root servers down, with
nothing carried from one to the next, and each is drawn in turn under a line
that names it; a NAME given several types on the command line is the same.
Every name and type is checked before anything is asked. The run exits with
the worst any of them earned: a broken chain of trust over no answer, and no
answer over an answer. Several questions cannot be written as one json, dot,
mermaid, waterfall-mermaid, openmetrics or served page, held to one --expect
or --against, or watched, so those are refused; --diff compares each with the
last walk of its own question.

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
fresh:3d or fresh:36h asks instead that none runs out that soon. caa:CA, such as
caa:letsencrypt.org, asks that --caa found that authority free to issue for the
name, which is how a renewal about to be refused is caught. spf:ok asks that
--spf found a policy no check fails on, which is how a provider pushing the
count past ten is caught. registered:30d asks that --rdap found the domain
registered, not held, and with at least that long left to run, which is how a
renewal nobody paid is caught; registered alone asks only the first two.
check:ok asks that --check found nothing broken, and check:clean that it found
nothing to look at either, which is how a zone is held to its health in CI.
Or else it takes the rdata of a record that has to be among the answers, such as an
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
correctly, out of an older zone. It costs a query per nameserver, and a lookup
of each one named outside the zone that the walk did not need, and which of the
serials is the newer one is not claimed, because serial arithmetic wraps.

--check-axfr asks every nameserver of the zone the walk ends in for the whole
zone (AXFR), the way anybody could, and says on each which of them hand it
over. A transfer lists every name in the zone, and is meant for the zone's own
secondaries. Only the start of the reply is read, and nothing of it is kept or
drawn. It needs tcp, so --doh cannot ask it, and --dot asks it over tls.

--check-recursion asks each of them to look up a name outside its zones, and
says which of them do: an authoritative server that resolves for anyone is an
open resolver, which floods whoever an attacker points it at. It goes by what
comes back rather than by the flag that says a server recurses, which servers
set without doing it.

Both cost what --serial does, and are off unless asked for: a transfer
refused still shows up in the server's logs, so they are for zones you run or
have been asked to check. The root is never asked either, since its servers
hand out the root zone on purpose.

--check-edns asks every nameserver of the zone the walk ends in for its SOA in
the four shapes RFC 8906 tests: with EDNS0 alone, then with an EDNS version, an
option and a flag nobody has defined yet. A server has to answer the version
BADVERS and ignore the option and the flag, and one that drops them instead, or
a firewall in front of it that does, is unreachable for resolvers that stopped
working around it on DNS Flag Day 2019. Only a server that passed the first is
asked the rest: one that fails EDNS0, or does not serve the zone, would fail
them all for the same reason. It costs up to four queries per nameserver address.

--caa says which certificate authorities may issue a certificate for NAME, and
which CAA set decides it (RFC 8659). An authority looks at the name, then at
each name above it short of the root, and goes by the first set it finds,
following an alias for that one lookup; so does this, asking each name of the
zone the walk found it in, and drawing the climb under the tree. A set with no
issue property leaves it to any authority, one with no issuewild leaves
wildcards to issue, and a critical property nobody knows makes every authority
refuse. So does a lookup that fails in a zone with a chain of trust behind it;
elsewhere an authority may take the failure as leave to issue, and the climb is
left undecided. Either is said in a warning. With --dnssec the
verdict is the weakest on the way up: a name that has no set has to prove it,
since dropping a set is all it takes to lift a restriction. It costs a query
for each name asked.

--spf draws the SPF policy NAME publishes (RFC 7208) as the tree of lookups a
receiving mail server makes to check it, and counts them against the limits a
check is held to: ten lookups, and two that find nothing. Past either the check
is a permerror, which many receivers treat as a failure, and the count usually
creeps up in a provider's record rather than in NAME's own. The lookups go to
the first --resolver, or the host's own, which is where a mail server asks
them. Which term a check stops at depends on who is sending, so every term up
to all is followed, the way a sender that matches none of them is checked. A
term with a macro in it, and ptr, depend on the sender too, and are counted
without being asked. It spends a budget of --max-queries apart from the walk's.

--mail looks up NAME's mail path the way a sending server that checks DANE
does (RFC 7672): the MX hosts by preference, the addresses of each, and the
TLSA set at _25._tcp of each whose addresses are signed, then the MTA-STS,
TLS-RPT and DMARC records beside them, DMARC falling back to the
organisational domain. Each lookup is a walk of its own, from the deepest zone
the run has entered, drawn in the tree as an aside. A host is covered by DANE
only where --dnssec proves its addresses and a TLSA set a sender can use; a
host whose addresses do not validate, or whose TLSA set fails to look up or
validate, makes every sender that checks DANE hold the mail, which is said in a warning, and so is an
MX host left uncovered while others are covered. Nothing connects to a mail
server, and the MTA-STS policy file is not fetched. The lookups spend the
walk's budget.

--svcb follows NAME's HTTPS records (RFC 9460), or its SVCB records where TYPE
is SVCB, to the servers a client would connect to: down the aliases a record
in alias mode makes, each to the next name's own records, then to the A and
AAAA of every target the last set names, a target of . being the record's own
name. The addresses found are held against the ipv4hint and ipv6hint the
records carry, and a hint that is none of them is said in a warning, since a
client may connect on the hint before it looks. So is a target with no
address or whose addresses could not be looked up, a loop, an alias set that
mixes in service mode records, and an ECH key in a set that is not signed all
the way down, aliases included. Every record is followed,
not the one a client would pick, and --max-cname bounds the aliases. Each
lookup is a walk of its own, drawn in the tree as an aside, and spends the
walk's budget; a TYPE of HTTPS or SVCB is the first set itself. A NAME with a
port is asked as written, such as _8443._https.example.com.

--rdap asks the registry of the domain over RDAP (RFC 9083) when its
registration runs out, which statuses it carries, and which nameservers and DS
it holds, and says so when they are not what the TLD hands out: a change stuck
between the registry and the zone. A registration that lapses, or that the
registry puts on hold, takes the domain out of its TLD everywhere at once, and
the registry knew for weeks. The domain is the zone the walk was delegated to
below the TLD, or the TLD and one label of NAME where the TLD said it does not
exist. The registry is found in IANA's bootstrap file, over HTTPS, the only
requests dnstree makes that are not DNS; a registry that cannot be asked costs
the check and says so in one line, never the walk. The DS are compared only
with --dnssec, since a referral carries them only then.

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

--try-ns walks as though the parent already delegated ZONE to the servers named,
one --try-ns for each, which is how to check a move to new nameservers before
the parent is told. A server is a name, an address, or NAME@ADDR; one named
inside the zone it serves needs its address, as glue would. The referral the
parent really gave is drawn, marked as replaced, and the walk goes on to the
new servers, with the parent's DS still checked against them. One zone is tried
at a time, never the root, and neither --diff nor the file of defaults takes it.

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

--ddr asks every resolver the question is timed against which encrypted
resolvers stand for it (RFC 9462), and says under the tree what each one
offers: dot, doh or doq, at which name and port. It is how to learn whether a
resolver handed out as a bare address could have been used encrypted. Nothing
connects to what is offered, so no certificate is checked and an offer is only
what the plain resolver claims. It costs a query per resolver, and needs the
comparison that --no-compare turns off.

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
	// Name and Type are the question being walked. More are the questions
	// after it, each a walk of its own.
	Name string
	Type string
	More []Question

	// Names is the file --names reads the questions from, "-" for the
	// standard input, empty when they were on the command line.
	Names string

	Family   int    // 0, 4 or 6
	Proto    string // udp, tcp, dot or doh
	Fallback bool
	All      bool
	DNSSEC   bool
	CheckNS  bool
	CheckDS  bool
	Serial   bool

	CheckAXFR      bool
	CheckRecursion bool
	CheckEDNS      bool
	CAA            bool
	SPF            bool
	Mail           bool
	SVCB           bool
	RDAP           bool
	Propagation    bool

	// Check grades the zone's health one area at a time, and turns on every
	// check that grades one, bar the probes a zone's owner is the one to run.
	Check bool

	NSID     bool
	Cookie   bool
	Minimise bool
	ASN      bool
	Compare  bool
	DDR      bool
	Report   bool
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

	// Without is what the walk treats as down, in the order it was named:
	// the servers it may not ask, by name or by address.
	Without []transport.Down

	// Try is the delegation --try-ns puts in place of a zone's real one, nil
	// where the walk is of the DNS as it is.
	Try *trace.Trial

	// WebAddr is where --format web and web-3d serve the page, and Browser whether one is
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

	// Against is a walk --format json saved, to say how the one drawn differs
	// from it: a path, or "-" for the standard input.
	Against string

	// Pcap is the file --pcap writes the walk's packets to, empty for none.
	Pcap string

	// Schema asks for the JSON Schema of the json format and nothing else. Like
	// Version it answers a question about the command rather than resolving a
	// name, so it needs no name to resolve.
	Schema bool

	// Version asks for the version and nothing else.
	Version bool
}

// notLookups are the types a question can name that do not ask for one RRset.
// Every step of a walk, and the chain of trust over it, is about exactly one.
var notLookups = map[string]string{
	"ANY":    "servers answer it with a sample (RFC 8482); ask for the types you want",
	"AXFR":   "it transfers a zone rather than looking a name up",
	"IXFR":   "it transfers a zone rather than looking a name up",
	"OPT":    "it carries EDNS0 and is never asked for",
	"TSIG":   "it signs a message and is never asked for",
	"TKEY":   "it sets up a key and is never asked for",
	"NXNAME": "it marks a name that does not exist and is never asked for",
}

// The flag package says what went wrong in words of its own, and with one dash
// before every flag. These are its messages, which plain says again.
var (
	undefinedFlag = regexp.MustCompile(`^flag provided but not defined: -+(.+)$`)
	missingValue  = regexp.MustCompile(`^flag needs an argument: -+(.+)$`)
	invalidValue  = regexp.MustCompile(`^invalid (?:boolean )?value (".*") for (?:flag )?-+([^:]+): (.*)$`)
)

// plain says a mistake the flag package found the way the rest of the command
// line's are said: the flag as it is typed, the value, and what is wrong with
// it.
func plain(flags *flag.FlagSet, err error) error {
	text := err.Error()
	if m := undefinedFlag.FindStringSubmatch(text); m != nil {
		return fmt.Errorf("%s is not a flag; --help lists them", dashed(m[1]))
	}
	if m := missingValue.FindStringSubmatch(text); m != nil {
		return fmt.Errorf("%s needs a value", dashed(m[1]))
	}
	m := invalidValue.FindStringSubmatch(text)
	if m == nil {
		return err
	}
	value, name, why := m[1], m[2], m[3]
	if why != "parse error" && why != "value out of range" {
		return fmt.Errorf("%s %s", dashed(name), why) // the flag's own reason, which names the value
	}
	f := flags.Lookup(name)
	if f == nil {
		return err // a value whose own text the pattern took for the flag
	}
	what := "cannot be read"
	if getter, ok := f.Value.(flag.Getter); ok {
		switch getter.Get().(type) {
		case int, uint:
			what = "is not a number"
		case time.Duration:
			what = "is not a length of time, such as 2s"
		case bool:
			what = "is neither true nor false"
		}
	}
	if why == "value out of range" {
		what = "is out of range"
	}
	return fmt.Errorf("%s %s %s", dashed(name), value, what)
}

// dashed writes a flag the way the usage does: one dash for a letter, two for
// a name.
func dashed(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// testHookFlags is handed the flags once they are all defined, so that a test
// can hold each of them to the usage and to the lists that sort them.
var testHookFlags = func(*flag.FlagSet) {}

// ErrUsage is anything the command line itself got wrong, including a request
// for help.
var ErrUsage = errors.New("cli: the command line cannot be read")

// Parse reads the arguments. Anything it writes, including the usage, goes to
// output.
func Parse(args []string, output io.Writer) (*Config, error) {
	// The flag package writes the usage after every mistake, which buries the
	// one line that says what the mistake was. It is written for --help alone,
	// and every other error is said once, in the words the rest of the tool uses.
	flags := flag.NewFlagSet("dnstree", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}

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
		names         string
		timeout       time.Duration
		port          uint
		roots         rootList
		wanted        expectList
		resolvers     resolverList
		without       downList
		trial         trialList
	)
	flags.StringVar(&reverse, "x", "", "resolve the PTR of this address")
	flags.StringVar(&names, "names", "", "walk every question in this file")
	flags.BoolVar(&four, "4", false, "ask only IPv4 servers")
	flags.BoolVar(&six, "6", false, "ask only IPv6 servers")
	flags.BoolVar(&udp, "udp", false, "carry the queries over UDP")
	flags.BoolVar(&tcp, "tcp", false, "carry the queries over TCP")
	flags.BoolVar(&dot, "dot", false, "carry the queries over TLS")
	flags.BoolVar(&doh, "doh", false, "carry the queries over HTTPS")
	flags.BoolVar(&cfg.Fallback, "fallback", false, "let plain DNS pick up a hop the transport could not")
	flags.BoolVar(&cfg.All, "all", false, "ask every nameserver of a zone")
	flags.BoolVar(&cfg.DNSSEC, "dnssec", false, "follow the chain of trust")
	flags.BoolVar(&cfg.CheckNS, "check-ns", false, "compare the parent and child NS sets and glue")
	flags.BoolVar(&cfg.CheckDS, "check-ds", false, "compare the zone's CDS and CDNSKEY with its DS")
	flags.BoolVar(&cfg.Serial, "serial", false, "ask every nameserver of the zone which copy it serves")
	flags.BoolVar(&cfg.CheckAXFR, "check-axfr", false, "ask every nameserver of the zone for all of it")
	flags.BoolVar(&cfg.CheckRecursion, "check-recursion", false, "ask every nameserver of the zone to look up somebody else's name")
	flags.BoolVar(&cfg.CheckEDNS, "check-edns", false, "ask every nameserver of the zone the RFC 8906 edns tests")
	flags.BoolVar(&cfg.CAA, "caa", false, "say which certificate authorities may issue for the name")
	flags.BoolVar(&cfg.SPF, "spf", false, "draw the name's SPF policy and count the lookups it costs")
	flags.BoolVar(&cfg.Mail, "mail", false, "check the name's MX hosts for DANE, and its mail policies")
	flags.BoolVar(&cfg.SVCB, "svcb", false, "follow the name's HTTPS or SVCB records to their servers")
	flags.BoolVar(&cfg.RDAP, "rdap", false, "ask the registry when the domain expires, and compare")
	flags.BoolVar(&cfg.Check, "check", false, "run the checks that grade a zone, and grade its health")
	flags.BoolVar(&cfg.NSID, "nsid", false, "ask each server which of itself answered")
	flags.BoolVar(&cfg.Cookie, "cookie", false, "send each server a DNS cookie and say how it answered")
	flags.BoolVar(&cfg.Minimise, "qmin", false, "ask each zone for no more of the name than it needs")
	flags.StringVar(&subnet, "subnet", "", "ask as though from this client subnet")
	flags.Var(&without, "without", "walk as though this server or network were down")
	flags.Var(&trial, "try-ns", "walk as though ZONE were delegated to this nameserver")
	flags.BoolVar(&noASN, "no-asn", false, "skip the origin AS lookups")
	flags.BoolVar(&noCompare, "no-compare", false, "do not time the question against a resolver")
	flags.BoolVar(&cfg.DDR, "ddr", false, "ask each resolver which encrypted resolvers stand for it")
	flags.BoolVar(&cfg.Report, "report", false, "tell the agent a zone names that its chain of trust is bogus")
	flags.StringVar(&format, "format", "tree", orList(formatNames(nil)))
	flags.StringVar(&cfg.WebAddr, "web-addr", "", "where the served page listens")
	flags.BoolVar(&noBrowser, "no-browser", false, "do not open a browser at the served page")
	flags.BoolVar(&cfg.Live, "live", false, "draw the tree as the walk makes it")
	flags.DurationVar(&cfg.Watch, "watch", 0, "walk again this often, and say only what changed")
	flags.BoolVar(&cfg.Explain, "explain", false, "say in sentences what the walk came to")
	flags.BoolVar(&cfg.Propagation, "propagation", false, "say how long a change takes to reach every cache")
	flags.BoolVar(&cfg.Diff, "diff", false, "say what has changed since the last walk remembered")
	flags.Var(&wanted, "expect", "require this of the walk")
	flags.StringVar(&cfg.From, "from", "", "draw a walk --format json saved")
	flags.StringVar(&cfg.Against, "against", "", "say how the walk differs from one --format json saved")
	flags.StringVar(&cfg.Pcap, "pcap", "", "save the walk's queries and answers as a packet capture")
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
	testHookFlags(flags)

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
	// A value checked after the parse is blamed on the file when only the file
	// set it: the command line has nothing to point at.
	fromFile := make(map[string]bool)
	if read {
		cfg.ConfigFile = file.path
		if err := flags.Parse(override(flags, fileArgs, args)); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrUsage, file.path, plain(flags, err))
		}
		flags.Visit(func(f *flag.Flag) { fromFile[f.Name] = true })
		scan(flags, args, func(name, _ string) { delete(fromFile, name) })
	}
	inFile := func(name string) string {
		if fromFile[name] {
			return file.path + ": "
		}
		return ""
	}
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(output, Usage)
		return nil, fmt.Errorf("%w: %w", ErrUsage, err)
	} else if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUsage, plain(flags, err))
	}
	switch mode := tree.ColorMode(color); mode {
	case tree.ColorAuto, tree.ColorAlways, tree.ColorNever:
		cfg.Color = mode
	default:
		return nil, fmt.Errorf("%w: %s%q is not a colour setting", ErrUsage, inFile("color"), color)
	}

	if _, ok := lookupFormat(format); !ok {
		return nil, fmt.Errorf("%w: %s%q is not a format", ErrUsage, inFile("format"), format)
	}
	cfg.Format = format

	if cfg.Version || cfg.Schema {
		return &cfg, nil
	}

	switch n := flags.NArg(); {
	case cfg.From != "" && (n > 0 || reverse != "" || names != ""):
		return nil, fmt.Errorf("%w: --from draws a walk already made, so there is no name to resolve", ErrUsage)
	case cfg.From != "":
	case names != "" && (n > 0 || reverse != ""):
		return nil, fmt.Errorf("%w: --names says what to resolve, so a name cannot be given as well", ErrUsage)
	case names != "":
		cfg.Names = names
	case reverse != "" && n > 0:
		return nil, fmt.Errorf("%w: -x names what to resolve, so a name cannot be given as well", ErrUsage)
	case reverse != "":
		addr, err := netip.ParseAddr(reverse)
		if err != nil {
			return nil, fmt.Errorf("%w: -x %q is not an address", ErrUsage, reverse)
		}
		cfg.Name, cfg.Type = reverseName(addr.Unmap()), "PTR"
	case n == 0:
		fmt.Fprint(output, Usage)
		return nil, fmt.Errorf("%w: no name to resolve", ErrUsage)
	default:
		questions, err := ask(flags.Args())
		if err != nil {
			return nil, err
		}
		cfg.Name, cfg.Type = questions[0].Name, questions[0].Type
		if len(questions) > 1 {
			cfg.More = questions[1:]
		}
	}
	if err := several(&cfg, len(wanted.want) > 0); err != nil {
		return nil, err
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
	// A default from the file is heeded only by the formats that draw it.
	if cfg.Check && !propagates(cfg.Format) {
		if !fromFile["check"] {
			return nil, fmt.Errorf("%w: %s does not draw what --check grades; use %s",
				ErrUsage, cfg.Format, orList(formatNames(propagates)))
		}
		cfg.Check = false
	}
	if cfg.Check {
		// Zone transfers and recursion are asked of strangers' servers as a
		// stranger, which is for the zone's owner to choose, so they are only
		// run where they are named.
		cfg.DNSSEC, cfg.All, cfg.CheckNS, cfg.CheckDS, cfg.Serial = true, true, true, true, true
		cfg.CheckEDNS, cfg.Cookie, cfg.CAA, cfg.SPF, cfg.Mail, cfg.RDAP = true, true, true, true, true, true
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
		case cfg.Pcap != "":
			return nil, fmt.Errorf("%w: --from draws a walk already made, so nothing is sent to capture", ErrUsage)
		}
	}
	// Every round is a whole walk from the root servers down. There is nothing
	// a change window needs below a second, and a loop tighter than that is
	// only a way of being rude to somebody else's nameservers.
	if cfg.Watch != 0 && cfg.Watch < time.Second {
		return nil, fmt.Errorf("%w: %s between one walk and the next is too little; a second is the least",
			ErrUsage, cfg.Watch)
	}
	if cfg.Diff && len(without.down) > 0 {
		return nil, fmt.Errorf("%w: --diff remembers the walk, and one made --without part of the DNS is not what the name does", ErrUsage)
	}
	switch {
	case cfg.Against != "" && cfg.Diff:
		return nil, fmt.Errorf("%w: --against and --diff each hold the walk against another; ask for one", ErrUsage)
	case cfg.Against == "-" && cfg.From == "-":
		return nil, fmt.Errorf("%w: --from and --against cannot both read the standard input", ErrUsage)
	}
	// A default from the file is heeded only by the formats that draw it.
	if cfg.Propagation && !propagates(cfg.Format) {
		if !fromFile["propagation"] {
			return nil, fmt.Errorf("%w: %s does not draw what --propagation works out; use %s",
				ErrUsage, cfg.Format, orList(formatNames(propagates)))
		}
		cfg.Propagation = false
	}
	if (cfg.Explain || cfg.Diff || cfg.Against != "") && Programs(cfg.Format) {
		return nil, fmt.Errorf("%w: %s is read by a program, which has the whole trace already and no use for prose",
			ErrUsage, cfg.Format)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("%w: %sa timeout of %s leaves no time to answer", ErrUsage, inFile("timeout"), timeout)
	}
	cfg.Timeout = timeout
	if cfg.Retries < 0 {
		return nil, fmt.Errorf("%w: %s%d retries is not a number of retries", ErrUsage, inFile("retries"), cfg.Retries)
	}
	// Left alone they are zero, which the resolver reads as its default; set to
	// zero, they would quietly mean the opposite of what was typed.
	budgets := map[string]int{"max-depth": cfg.MaxDepth, "max-queries": cfg.MaxQueries, "max-cname": cfg.MaxCNAME}
	var none error
	flags.Visit(func(f *flag.Flag) {
		if value, ok := budgets[f.Name]; ok && value < 1 && none == nil {
			none = fmt.Errorf("%w: %s--%s %d is no budget at all; the least is 1", ErrUsage, inFile(f.Name), f.Name, value)
		}
	})
	if none != nil {
		return nil, none
	}
	// --all asks every address of every zone on the way, the root's
	// twenty-six included, and spends the ordinary budget before it is half way
	// down a large zone. Only the run asks for more: the resolver's default is
	// also what dnstree-web walks for strangers with.
	if cfg.Check && cfg.MaxQueries == 0 {
		cfg.MaxQueries = CheckMaxQueries
	}
	if cfg.All && cfg.MaxQueries == 0 {
		cfg.MaxQueries = AllMaxQueries
	}
	if port > 65535 {
		return nil, fmt.Errorf("%w: %d is not a port", ErrUsage, port)
	}
	cfg.Port = uint16(port)
	cfg.Expect = wanted.want
	cfg.Without = without.down
	cfg.Try = trial.trial
	cfg.ASN = !noASN
	cfg.Compare = !noCompare
	cfg.Browser = !noBrowser

	if Serves(cfg.Format) {
		if cfg.WebAddr == "" {
			cfg.WebAddr = web.DefaultAddr
		}
		// Checked here so that a typo costs nothing, rather than the walk the
		// page was going to show.
		_, port, err := net.SplitHostPort(cfg.WebAddr)
		if _, perr := strconv.ParseUint(port, 10, 16); err != nil || perr != nil {
			return nil, fmt.Errorf("%w: --web-addr %q is not a host and port, such as 127.0.0.1:8080", ErrUsage, cfg.WebAddr)
		}
	} else if cfg.WebAddr != "" || noBrowser {
		return nil, fmt.Errorf("%w: only --format web and web-3d serve a page", ErrUsage)
	}

	if subnet != "" {
		if cfg.Subnet, err = clientSubnet(subnet); err != nil {
			return nil, fmt.Errorf("%w: --subnet %w", ErrUsage, err)
		}
	}

	if cfg.Roots = roots.servers; len(cfg.Roots) > 0 && cfg.RootHints != "" {
		return nil, fmt.Errorf("%w: --root and --root-hints both say where the walk starts", ErrUsage)
	}
	if cfg.DDR && !cfg.Compare {
		// As with --check-ds, a default from the file is heeded only by the runs
		// it applies to, and typed out the contradiction is a mistake.
		named := false
		scan(flags, args, func(name, _ string) { named = named || name == "ddr" })
		if named {
			return nil, fmt.Errorf("%w: --ddr asks the resolvers --no-compare leaves unasked", ErrUsage)
		}
		cfg.DDR = false
	}
	if cfg.Try != nil && cfg.Diff {
		return nil, fmt.Errorf("%w: --diff remembers the DNS as it is, and --try-ns walks it as it is not", ErrUsage)
	}
	if cfg.Report && !cfg.DNSSEC {
		return nil, fmt.Errorf("%w: --report tells a zone its chain of trust is bogus, which only --dnssec can find", ErrUsage)
	}
	if cfg.Report && cfg.Watch != 0 {
		return nil, fmt.Errorf("%w: --report with --watch would send the same report every walk", ErrUsage)
	}
	if cfg.Resolvers = resolvers.servers; len(cfg.Resolvers) > 0 && !cfg.ASN && !cfg.Compare && !cfg.Report && !cfg.SPF {
		return nil, fmt.Errorf("%w: --no-asn and --no-compare leave --resolver nothing to answer", ErrUsage)
	}
	if cfg.Pcap != "" && (cfg.Proto == "dot" || cfg.Proto == "doh") {
		return nil, fmt.Errorf("%w: --%s carries the queries in TLS, which --pcap cannot write as plain DNS", ErrUsage, cfg.Proto)
	}
	if cfg.Pcap == "-" {
		return nil, fmt.Errorf("%w: --pcap - would write the capture into the drawing; name a file", ErrUsage)
	}
	if cfg.Pcap != "" && cfg.Watch != 0 {
		return nil, fmt.Errorf("%w: --pcap with --watch would keep every walk in memory until it is interrupted", ErrUsage)
	}
	if (cfg.TLSCA != "" || cfg.TLSInsecure) && cfg.Proto != "dot" && cfg.Proto != "doh" {
		return nil, fmt.Errorf("%w: only --dot and --doh use TLS", ErrUsage)
	}
	if cfg.TLSCA != "" && cfg.TLSInsecure {
		return nil, fmt.Errorf("%w: --tls-insecure verifies nothing, so --tls-ca has nothing to verify against", ErrUsage)
	}

	return &cfg, nil
}

// AllMaxQueries is the query budget of a run with --all that names none.
const AllMaxQueries = 256

// CheckMaxQueries is the query budget of a run with --check that names none:
// --all's, and the sweeps of every nameserver the checks make on top of it.
const CheckMaxQueries = 512

// Question is one name and one type to walk.
type Question struct {
	Name string
	Type string
}

// ask reads one question's worth of words, a name and the types to ask of it,
// as one question per type.
func ask(words []string) ([]Question, error) {
	name, err := idn.ASCII(words[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUsage, err)
	}
	types := words[1:]
	if len(types) == 0 {
		types = []string{"A"}
	}
	questions := make([]Question, 0, len(types))
	for _, qtype := range types {
		qtype = strings.ToUpper(qtype)
		if why, ok := notLookups[qtype]; ok {
			return nil, fmt.Errorf("%w: %s is not a lookup: %s", ErrUsage, qtype, why)
		}
		questions = append(questions, Question{Name: name, Type: qtype})
	}
	return questions, nil
}

// ReadQuestions reads what --names names: a line to a name and the types to ask
// of it, skipping blank lines and comments.
func ReadQuestions(r io.Reader) ([]Question, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var questions []Question
	line := 0
	for text := range strings.Lines(string(data)) {
		line++
		words := strings.Fields(text)
		if len(words) == 0 || strings.HasPrefix(words[0], "#") {
			continue
		}
		asked, err := ask(words)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		questions = append(questions, asked...)
	}
	if len(questions) == 0 {
		return nil, fmt.Errorf("%w: no name to resolve", ErrUsage)
	}
	return questions, nil
}

// Questions is every question the run asks, in the order it asks them.
func (c *Config) Questions() []Question {
	return append([]Question{{Name: c.Name, Type: c.Type}}, c.More...)
}

// several refuses what cannot be said of more than one walk. --names counts
// however many lines the file turns out to hold, so that what a run accepts
// does not hang on what is in it.
func several(cfg *Config, expecting bool) error {
	if len(cfg.More) == 0 && cfg.Names == "" {
		return nil
	}
	switch {
	case Programs(cfg.Format) || Serves(cfg.Format):
		return fmt.Errorf("%w: %s writes one walk, and several questions make several", ErrUsage, cfg.Format)
	case expecting:
		return fmt.Errorf("%w: --expect cannot say which of several questions it is about", ErrUsage)
	case cfg.Against != "":
		return fmt.Errorf("%w: --against holds a walk of one question, and several were asked", ErrUsage)
	case cfg.Watch != 0:
		return fmt.Errorf("%w: --watch follows one question, and several were asked", ErrUsage)
	}
	return nil
}

// walkFlags are the flags that shape a walk being made, and say nothing about
// one already made.
var walkFlags = map[string]bool{
	"4": true, "6": true, "udp": true, "tcp": true, "dot": true, "doh": true, "fallback": true,
	"all": true, "dnssec": true, "check-ns": true, "check-ds": true, "serial": true, "check-axfr": true, "check-recursion": true, "check-edns": true, "caa": true, "spf": true, "mail": true, "svcb": true, "rdap": true, "check": true, "nsid": true, "cookie": true, "qmin": true,
	"subnet": true, "without": true, "try-ns": true, "no-asn": true, "no-compare": true, "ddr": true, "report": true, "timeout": true, "retries": true,
	"max-depth": true, "max-queries": true, "max-cname": true, "port": true, "root-hints": true,
	"root": true, "trust-anchors": true, "resolver": true, "asn-resolver": true,
	"tls-ca": true, "tls-insecure": true,
}

// format is what the rest of the run needs to know about one --format.
type format struct {
	name string
	// once is a format written once, at the end, which leaves nothing to draw
	// live and nothing to watch change. A waterfall is one because its scale
	// is the whole walk, which is not known until it is over, and a report
	// because it is pasted whole.
	once bool
	// propagates is a format that draws what --propagation works out, and what
	// --check grades.
	propagates bool
	serves     bool // a page served to a browser
	programs   bool // read by a program rather than a person
}

// formats are every --format there is, in the order the help lists them. A
// new one is a row here, a renderer in main, and the usage text.
var formats = []format{
	{name: "tree", propagates: true},
	{name: "ascii", propagates: true},
	{name: "emoji", propagates: true},
	{name: "waterfall", once: true},
	{name: "waterfall-ascii", once: true},
	{name: "waterfall-mermaid", once: true, programs: true},
	{name: "markdown", once: true, propagates: true},
	{name: "json", once: true, propagates: true, programs: true},
	{name: "dot", once: true, programs: true},
	{name: "mermaid", once: true, programs: true},
	{name: "openmetrics", once: true, programs: true},
	{name: "web", once: true, serves: true},
	{name: "web-3d", once: true, serves: true},
}

// lookupFormat is the format called name, false where there is none.
func lookupFormat(name string) (format, bool) {
	i := slices.IndexFunc(formats, func(f format) bool { return f.name == name })
	if i < 0 {
		return format{}, false
	}
	return formats[i], true
}

// formatNames are the formats keep says yes to, every one where keep is nil.
func formatNames(keep func(string) bool) []string {
	var names []string
	for _, f := range formats {
		if keep == nil || keep(f.name) {
			names = append(names, f.name)
		}
	}
	return names
}

// orList is names as a sentence would list them: "a, b or c".
func orList(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

func once(name string) bool {
	f, _ := lookupFormat(name)
	return f.once
}

func propagates(name string) bool {
	f, _ := lookupFormat(name)
	return f.propagates
}

// Serves reports whether a format is a page served to a browser rather than
// anything written here.
func Serves(name string) bool {
	f, _ := lookupFormat(name)
	return f.serves
}

// Programs reports whether a format is read by a program rather than a person,
// which has the whole trace already and no use for prose under it.
func Programs(name string) bool {
	f, _ := lookupFormat(name)
	return f.programs
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

// downList collects the --without flags in the order they were given.
type downList struct{ down []transport.Down }

func (l *downList) String() string {
	named := make([]string, 0, len(l.down))
	for _, down := range l.down {
		named = append(named, down.String())
	}
	return strings.Join(named, ",")
}

// Set reads one --without: a prefix, an address, or the name of a nameserver.
func (l *downList) Set(text string) error {
	down, err := parseDown(text)
	if err != nil {
		return err
	}
	if !slices.Contains(l.down, down) {
		l.down = append(l.down, down)
	}
	return nil
}

func parseDown(text string) (transport.Down, error) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		// The servers are held to their IPv4 address, so a prefix written over
		// the IPv4 addresses mapped into IPv6 is held to the IPv4 part of it.
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return transport.Down{}, fmt.Errorf("%q reaches past the IPv4 addresses it is written over", text)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return transport.Down{Prefix: prefix.Masked()}, nil
	}
	if addr, err := netip.ParseAddr(text); err == nil {
		addr = addr.Unmap()
		return transport.Down{Prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
	}

	switch {
	case text == "" || text == ".":
		return transport.Down{}, errors.New("names nothing to leave out")
	case asNumber(text):
		return transport.Down{}, fmt.Errorf("%q is a network by its AS, which cannot be left out yet; name its servers or a prefix", text)
	case strings.ContainsAny(text, ":/@ \t"):
		return transport.Down{}, fmt.Errorf("%q is neither an address, a prefix nor a name", text)
	}
	name, err := idn.ASCII(text)
	if err != nil {
		return transport.Down{}, err
	}
	return transport.Down{Name: fqdn(strings.ToLower(name))}, nil
}

// trialList collects the --try-ns flags into the one delegation they stand in
// for. Several of them name the nameservers of one zone, the way a referral
// does; a run tries one move at a time.
type trialList struct{ trial *trace.Trial }

func (l *trialList) String() string {
	if l.trial == nil {
		return ""
	}
	return l.trial.Zone + "=" + strings.Join(l.trial.NS, ",")
}

// Set reads one --try-ns: the zone, and a nameserver for it by its name, its
// address, or its name and address as --root writes them.
func (l *trialList) Set(value string) error {
	zone, server, ok := strings.Cut(value, "=")
	if !ok || zone == "" || server == "" {
		return fmt.Errorf("%q is not ZONE=SERVER", value)
	}
	zone, err := idn.ASCII(zone)
	if err != nil {
		return err
	}
	zone = fqdn(strings.ToLower(zone))
	if zone == "." {
		return errors.New("the root has no parent to delegate it, so it cannot be moved; use --root")
	}
	if l.trial == nil {
		l.trial = &trace.Trial{Zone: zone, Addrs: map[string][]netip.Addr{}}
	} else if l.trial.Zone != zone {
		return fmt.Errorf("--try-ns names %s and %s, and a walk tries one zone at a time", l.trial.Zone, zone)
	}

	name, written, named := strings.Cut(server, "@")
	if !named {
		name, written = server, ""
		if _, err := netip.ParseAddr(server); err == nil {
			written = server
		}
	}
	if _, err := netip.ParseAddr(name); err != nil {
		if strings.ContainsAny(name, ":/@ \t") {
			return fmt.Errorf("%q is neither a name nor an address", name)
		}
		if name, err = idn.ASCII(name); err != nil {
			return err
		}
		name = fqdn(strings.ToLower(name))
	}
	// Like a delegation without glue, a nameserver inside the zone it serves
	// can only be reached at an address it is given.
	if written == "" && (name == zone || strings.HasSuffix(name, "."+zone)) {
		return fmt.Errorf("%s is inside %s, so nothing can look its address up; give it as %s@ADDR", name, zone, strings.TrimSuffix(name, "."))
	}
	if !slices.Contains(l.trial.NS, name) {
		l.trial.NS = append(l.trial.NS, name)
	}
	if written != "" {
		addr, err := netip.ParseAddr(written)
		if err != nil {
			return fmt.Errorf("%q is not an address", written)
		}
		if !slices.Contains(l.trial.Addrs[name], addr.Unmap()) {
			l.trial.Addrs[name] = append(l.trial.Addrs[name], addr.Unmap())
		}
	}
	return nil
}

// asNumber reports whether text names an autonomous system, as AS13335.
func asNumber(text string) bool {
	if len(text) < 3 || !strings.EqualFold(text[:2], "as") {
		return false
	}
	_, err := strconv.ParseUint(text[2:], 10, 32)
	return err == nil
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
