# dnstree

[![release](https://img.shields.io/github/v/release/rafaeljusto/dnstree)](https://github.com/rafaeljusto/dnstree/releases)
[![ci](https://github.com/rafaeljusto/dnstree/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaeljusto/dnstree/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**[rafaeljusto.github.io/dnstree](https://rafaeljusto.github.io/dnstree/)**

Resolve a name the way a resolver does — from the root servers down, following
every referral — and draw the path it took.

![dnstree --live resolving www.example.com from the root servers, each referral joining the tree as it lands](docs/demo-hero.gif)

```
$ dnstree www.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  AS19836  241ms  NOERROR  referral → com.
│   ├── l.gtld-servers.net. 192.41.162.30  AS19836  247ms  NOERROR  referral → example.com.
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  AS13335  233ms  NOERROR  AA
│   │   │   ├── www.example.com. 300 A 172.66.147.243
│   │   │   └── www.example.com. 300 A 104.20.23.154
│   │   ├── hera.ns.cloudflare.com. 172.64.32.162  (not queried)
│   │   ├── hera.ns.cloudflare.com. 173.245.58.162  (not queried)
│   │   ├── hera.ns.cloudflare.com. 2606:4700:50::adf5:3aa2  (not queried)
│   │   └── (and 8 more not queried)
│   ├── l.gtld-servers.net. 2001:500:d937::30  (not queried)
│   ├── j.gtld-servers.net. 192.48.79.30  (not queried)
│   ├── j.gtld-servers.net. 2001:502:7094::30  (not queried)
│   └── (and 22 more not queried)
├── a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
├── b.root-servers.net. 170.247.170.2  (not queried)
├── b.root-servers.net. 2801:1b8:10::b  (not queried)
└── (and 22 more not queried)
✔ answered in 722ms · resolver in 243ms · 3 queries · 3 servers
```

`dig +trace` tells you the same story in prose. `dnstree` draws it, and says
what it found on the way: which servers were lame, which delegations are
broken, how long each hop took, which AS announces each address, and whether
the chain of trust holds.

## Installing

```
go install github.com/rafaeljusto/dnstree/cmd/dnstree@latest
```

Or run it straight from a container:

```
docker run --rm ghcr.io/rafaeljusto/dnstree www.example.com A
```

Every [release](https://github.com/rafaeljusto/dnstree/releases) also carries a
binary for macOS, Linux, FreeBSD and Windows, a Debian, RPM and Alpine package
for amd64, arm64 and armhf, and a Homebrew formula. The packages install a man
page: `man dnstree`. `checksums.txt` covers every file in the release.
[`packaging/`](packaging/) says how they are built.

<details>
<summary>Installing a downloaded package</summary>

The release notes give the command for each; taking the packages of `v1.1.1`
as the example:

```
# Debian, Ubuntu
sudo dpkg -i dnstree_1.1.1_amd64.deb

# Fedora, RHEL
sudo rpm -i dnstree-1.1.1-1.x86_64.rpm

# Alpine
sudo apk add --allow-untrusted dnstree_1.1.1_x86_64.apk

# Homebrew
brew install --formula ./dnstree.rb
```

</details>

## Using it

```
dnstree [flags] NAME [TYPE]
```

`TYPE` defaults to `A`.

| Flag | What it does |
| --- | --- |
| `-4`, `-6` | ask only IPv4 or only IPv6 servers; the others are drawn unqueried |
| `--udp`, `--tcp` | carry the queries over plain DNS (`--udp` is the default) |
| `--dot`, `--doh` | carry them encrypted, over TLS or HTTPS |
| `--fallback` | let plain DNS pick up a hop the transport could not |
| `--all` | ask every nameserver of a zone, not just the first that answers |
| `--dnssec` | ask for signatures and follow the chain of trust |
| `--check-ns` | ask each zone for its own NS set and compare it with the delegation |
| `--serial` | ask every nameserver of the zone which copy of it they serve, and compare |
| `--nsid` | ask each server which of itself answered, and draw it beside the address |
| `--subnet` | ask as though from this client subnet, and say what each server made of it |
| `--no-asn` | skip the origin AS lookups |
| `--no-compare` | skip the question put to a recursive resolver, and the comparison with it |
| `--format` | `tree` (the default), `ascii`, `emoji`, `json`, `dot` or `web` |
| `--web-addr`, `--no-browser` | where `--format web` serves the page, and whether a browser is opened at it |
| `--live` | draw the tree as the walk makes it, hop by hop |
| `--watch` | walk again this often, and say only what changed since the walk before |
| `--explain` | say in sentences what the walk came to, under the tree |
| `--diff` | say what has changed since the last walk of the same question |
| `--expect` | require this of the walk, and exit 4 where it does not hold; repeat it |
| `--color` | `auto` (the default), `always` or `never` |
| `--timeout`, `--retries` | how long one query may take (2s), and how often to ask again after a silence (once) |
| `--max-depth`, `--max-queries`, `--max-cname` | the budgets that keep a walk finite: 16 zone cuts, 64 queries, 8 aliases |
| `--port` | the port nameservers are asked on (53) |
| `--root-hints`, `--trust-anchors` | start somewhere other than the built-in root |
| `--root` | one server to start from, instead of a hints file; repeat it for more |
| `--resolver` | the recursive server to use, instead of the host's own |
| `--tls-ca`, `--tls-insecure` | how `--dot` and `--doh` verify a server, or that they do not |
| `--config`, `--no-config` | take the defaults from this file, or from no file at all |
| `--debug` | report every hop on stderr as it is made |
| `--schema` | print the JSON Schema of `--format json` and stop |
| `--version` | print the version and stop |

### Defaults

Flags you always type belong in a file instead. `dnstree` reads the first of
`$DNSTREE_CONFIG`, `$XDG_CONFIG_HOME/dnstree/config` (`~/.config/dnstree/config`
where that is unset) and `~/.dnstreerc`:

```
# ~/.dnstreerc
format = emoji
dnssec
timeout = 3s
```

One long flag name per line, with the value it takes. `name value` works as well
as `name = value`, the dashes of a pasted command line are allowed and ignored,
and a flag that stands on its own needs no value. A line opening with `#` is a
comment; a `#` partway along a line is part of the value, so a setting and what
it is for go on separate lines. A name that is not a flag, or one missing the
value it takes, is reported against the line that wrote it, and so are `config`,
`no-config` and `version`: those three ask something of the run rather than set
a default for it.

> [!NOTE]
> A file named outright — by `$DNSTREE_CONFIG` or by `--config` — has to be
> there, and a missing one is an error. The two conventional locations are
> simply read if they exist.

The command line wins over the file, so `--format ascii` overrides the line
above and `--dnssec=false` turns a flag it set back off. Flags that answer one
question in different ways give way as a group, rather than colliding: naming
any of `--udp`, `--tcp`, `--dot` or `--doh` drops whichever transport the file
chose, and so it goes for `-4` and `-6`, for `--root` and `--root-hints`, and
for `--tls-ca` and `--tls-insecure`. `--format json` and `--format dot` drop a
`live` the file set, since both are written once at the end, and so does
`--format web`; a format that serves no page drops a `web-addr` it set. `--config FILE`
reads somewhere else, and `--no-config` reads nowhere.

`root` is the one line worth repeating: a file may carry as many as the walk
should start from, in the order they are written. One `--root` on the command
line replaces every one of them, rather than adding to them, and so does
`--root-hints`.

> [!TIP]
> [`dnstreerc.example`](dnstreerc.example) is a file of every setting worth
> making, annotated and commented out. Copy it and uncomment what you want.

### Pointing it somewhere else

Nothing about the walk assumes the real root. `--root` names the servers it
starts from, one flag each, and each may carry the port the server listens on:

```
$ dnstree --root a.root-servers.net@127.0.0.1:5353 --port 5354 \
    --trust-anchors ./anchors.xml --dnssec www.test A
```

A root that carries no port is asked on `--port`, and so is everything reached
by glue below it — glue carries addresses and never ports, so a hierarchy on
one host wants its root on a port of its own and the rest on `--port`.
`--root` and `--root-hints` say the same thing two ways, so only one of them
may be given.

The metadata has its own way out: `--resolver ADDR` points everything that
needs a recursive server at one of your own — the origin AS lookups, and the
question put to an ordinary resolution and held against the walk's own answer —
while `--no-asn` and `--no-compare` skip either of those altogether. Asking for
both leaves `--resolver` nothing to answer, which is refused rather than
quietly ignored. `--asn-resolver` is the older name for `--resolver` and still
works. For `--dot` and `--doh`, `--tls-ca FILE` verifies against a CA of your
own.

> [!CAUTION]
> `--tls-insecure` verifies nothing at all. It is there to reach a server
> holding a test certificate, and it is worth nothing anywhere else.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | something answered |
| 1 | the command line, or the question, could not be read |
| 2 | the walk ended without an answer |
| 3 | the chain of trust is broken |
| 4 | an expectation given with `--expect` was not met |

### DNSSEC

`--dnssec` follows the chain from the trust anchors down: the DS each parent
publishes, the keys each child serves, and the signatures over the answer.

```
$ dnstree --dnssec --no-asn cloudflare.com A
. (root)  [secure RSASHA256/SHA256]
├── a.root-servers.net. 198.41.0.4  243ms  NOERROR  DO  referral → com.  [secure ECDSAP256SHA256/SHA256]
│   ├── a.root-servers.net. 198.41.0.4  251ms  NOERROR  AA DO  (DNSKEY of .)
│   ├── l.gtld-servers.net. 192.41.162.30  262ms  NOERROR  DO  referral → cloudflare.com.  [secure ECDSAP256SHA256/SHA256]
│   │   ├── l.gtld-servers.net. 192.41.162.30  257ms  NOERROR  AA DO  (DNSKEY of com.)
│   │   ├── ns3.cloudflare.com. 162.159.0.33  240ms  NOERROR  AA DO  [secure ECDSAP256SHA256]
│   │   │   ├── cloudflare.com. 300 A 104.16.132.229
│   │   │   ├── cloudflare.com. 300 A 104.16.133.229
│   │   │   └── ns3.cloudflare.com. 162.159.0.33  235ms  NOERROR  AA DO  (DNSKEY of cloudflare.com.)
│   │   ├── ns3.cloudflare.com. 162.159.7.226  (not queried)
│   │   ├── ns3.cloudflare.com. 2400:cb00:2049:1::a29f:21  (not queried)
│   │   ├── ns3.cloudflare.com. 2400:cb00:2049:1::a29f:7e2  (not queried)
│   │   └── (and 16 more not queried)
│   ├── l.gtld-servers.net. 2001:500:d937::30  (not queried)
│   ├── j.gtld-servers.net. 192.48.79.30  (not queried)
│   ├── j.gtld-servers.net. 2001:502:7094::30  (not queried)
│   └── (and 22 more not queried)
├── a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
├── b.root-servers.net. 170.247.170.2  (not queried)
├── b.root-servers.net. 2801:1b8:10::b  (not queried)
└── (and 22 more not queried)
✔ answered in 1.5s · resolver in 14ms · 6 queries · 3 servers
```

A zone whose parent proves it publishes no DS reads `[insecure]`, and everything
below it stays that way. A parent that publishes neither a DS nor the signed
proof that it has none is not taken at its word: dropping the DS out of a
referral is all it would take to walk the chain off the secure path. A link that
cannot be checked at all — an algorithm this build does not know — reads
`[indeterminate]`, which is not the same as `[bogus]`.

Denial of existence is proved. NSEC and NSEC3 are read, opt-out included, so an
answer with nothing in it is checked like any other: an NXDOMAIN has to show the
gap the name falls in and the gap the wildcard would have answered from, a
NODATA has to name the types the name does hold, and an answer a wildcard was
stretched over has to show there was nothing closer to answer with.

A registry that serves its own domains from the machines of its ccTLD answers
for a child zone with no referral to it, so the cut is invisible from the walk.
The signatures name the zone that made them, and the same server holds the
parent side of the cut, so it is asked for the child's DS — an aside reading
`(DS of registro.br.)` — and the chain crosses the cut before the answer is
checked.

### What a server said about its answer

An rcode says what happened. The extended errors of RFC 8914 say why, and they
are the only thing in a reply that tells an answer somebody kept back from an
answer that was never there:

```
$ dnstree blocked.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  21ms  NOERROR  referral → com.
│   ├── l.gtld-servers.net. 192.41.162.30  19ms  NOERROR  referral → example.com.
│   │   └── ns1.example.com. 192.0.2.53  4ms  REFUSED  filtered  ede Prohibited (18): not from this network
│   └── (and 25 more not queried)
└── (and 25 more not queried)
✘ filtered in 61ms · 3 queries · 3 servers
```

Without the code on the end that hop reads as a lame server — one with no
business serving the zone, which is a fault to take to whoever runs it. With it,
the server is working exactly as somebody configured it, and the fault, if there
is one, is not the zone's. They are different findings and the tree now says
which one it found. The same goes for an NXDOMAIN carrying `Blocked (15)`: the
name is not missing, it is being denied, and a walk that ends that way reports
`filtered` rather than `no answer`.

A code that claims nothing of the sort — a stale answer served from a cache,
say — is carried on the hop and changes nothing else. Every code reaches
`--format json` as `extended`, with a `withheld` flag on the ones that mean
somebody decided the answer, so a script need not carry the list itself.

Exit code 2 covers a filtered walk, as it does any other walk that ends without
an answer.

### ECH, and what makes it worth anything

Encrypted client hello hides the name a client is about to connect to. The
configuration that does the hiding is published in DNS, in the HTTPS record of
the name itself, which means the thing being protected travels in the same
answer as the protection. Anything that can rewrite that answer can drop the
configuration out of it, and a client that finds none does not fail: it connects
the old way and sends the name in the clear.

So `dnstree` reads the service parameters of an HTTPS or SVCB record rather than
only printing them, marks the records that publish a configuration, and says
when nothing vouched for the answer that carried it:

```
$ dnstree --dnssec www.example.com HTTPS
...
└── ns3.example.com. 192.0.2.53  18ms  NOERROR  AA DO  [secure ECDSAP256SHA256]
    └── www.example.com. 300 HTTPS 1 . alpn="h2,h3" ech="AEX+DQBB..."  [ech]
```

> [!WARNING]
> Without `--dnssec`, or against a zone whose answer comes back `insecure` or
> `bogus`, the same record earns a warning: the configuration is there, and
> nothing here can tell whether it is the one the zone published.

The parameters are in `--format json` under `service`, `ech` included.

### Asking from somewhere else

A server that answers by where the question came from — which is every CDN —
tells a walk from your desk about your desk. `--subnet` asks it the question
somebody else would be asking:

```
$ dnstree --subnet 203.0.113.0/24 www.example.com A
...
└── ns3.example.com. 192.0.2.53  18ms  NOERROR  AA  ecs scope /24
    └── www.example.com. 60 A 198.51.100.7
```

`ecs scope /24` is the server saying it used the whole prefix to choose that
answer, so somebody else in that /24 gets the same one. A scope of `/0` is the
server saying the answer is the same everywhere, and a hop that echoes nothing
at all ignored the subnet, which earns a warning: what came back is what that
server tells everybody, and the question went unanswered.

A bare address is read as the /24 or /56 around it, since the point is the
network and not the machine.

> [!IMPORTANT]
> The subnet is sent to every server on the way down, which is more than the
> root servers need to know about where you are, so it is never sent unless it
> is asked for.

### Whether they all have the same zone

A walk stops at the first nameserver that answers, which is what a resolver
does and what makes a secondary left behind by a zone transfer invisible: it is
reachable, it is authoritative, and it answers the question correctly out of an
older zone. `--serial` asks every one of them which copy it is holding:

```
$ dnstree --serial --no-asn wikipedia.org A
...
│   │   ├── ns2.wikimedia.org. 198.35.27.27  246ms  NOERROR  AA
│   │   │   ├── wikipedia.org. 180 A 185.15.59.224
│   │   │   ├── ns2.wikimedia.org. 198.35.27.27  274ms  NOERROR  AA  (SOA of wikipedia.org.: 2026060420)
│   │   │   ├── ns2.wikimedia.org. 2a02:ec80:53::1  14ms  NOERROR  AA  (SOA of wikipedia.org.: 2026060420)
│   │   │   ├── ns0.wikimedia.org. 208.80.154.238  340ms  NOERROR  AA  (SOA of wikipedia.org.: 2026060420)
│   │   │   ├── ns0.wikimedia.org. 2620:0:861:53::1  134ms  NOERROR  AA  (SOA of wikipedia.org.: 2026060420)
│   │   │   ├── ns1.wikimedia.org. 208.80.153.231  358ms  NOERROR  AA  (SOA of wikipedia.org.: 2026060420)
│   │   │   └── ns1.wikimedia.org. 2620:0:860:53::1  158ms  NOERROR  AA  (SOA of wikipedia.org.: 2026060420)
...
✔ answered in 1.3s · resolver in 249ms · 9 queries · 8 servers
```

Six addresses, one zone, and nothing to report. Where they do not all hold the
same copy, the walk says so above the summary, naming who holds what:

> the nameservers of test. are serving different copies of it: 2 at ns1.test., 1 at ns2.test.

Which of the serials is the newer one is deliberately not claimed. Serial
arithmetic wraps around (RFC 1982), so the larger number is not reliably the
later zone, and a tool that guessed would send somebody to restart the wrong
server.

It costs a query per nameserver and is off unless asked for. It does not need
`--all`: the sweep is one cheap question to each of them, rather than the whole
resolution done over again.

`--all` sees the other half of the same thing, and needs no flag of its own to
say it. Where it has put the question itself to every nameserver of a zone, two
of them answering differently is worth a line:

> the nameservers of test. do not answer www.test. A alike: 192.0.2.10 at ns1.test., 192.0.2.99 at ns2.test.

Answers are held against each other as sets, so a nameserver rotating an RRset
between one question and the next is not a nameserver that disagrees. A real
difference is not by itself a fault — a zone served by something that answers by
where the question came from will do this honestly, and so will an RRset caught
halfway through a change — but nothing else in a trace says it at all.

### Which machine answered

An address is not a server. `a.root-servers.net.` is one address announced from
hundreds of places at once, and so is every nameserver of every large zone, so
a hop that says `198.41.0.4` has named a network and not a machine. `--nsid`
asks each server for the identifier it publishes for itself (RFC 5001) and
draws it beside the address:

```
$ dnstree --nsid --no-asn www.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  @a.r.ams5.nlams-0  259ms  NOERROR  referral → com.
│   ├── l.gtld-servers.net. 192.41.162.30  @nnn1-ams5  252ms  NOERROR  referral → example.com.
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  @52m278  239ms  NOERROR  AA
│   │   │   ├── www.example.com. 300 A 104.20.23.154
│   │   │   └── www.example.com. 300 A 172.66.147.243
...
✔ answered in 750ms · resolver in 258ms · 3 queries · 3 servers
```

Two hops to the one address can come back with two identifiers, which is not a
contradiction: it is two machines, and it is the answer to why one of them is
slow and the other is not, or why one of them is serving an older zone. It
rides along on queries that are being made anyway and costs none of its own.

The identifier is opaque bytes that the server alone chooses. Operators write
names into them, and those are drawn as names; anything else is drawn as the
hex it arrived as, and an identifier longer than a line has room for is cut.
A server that publishes none says nothing, which is most of them below the
root, and its hop reads as it would without the flag.

### Against your resolver

Every walk also puts the question to a recursive resolver — the host's own, or
whichever `--resolver` names — and keeps the answer as well as the clock. When
the two disagree, the tree says so, under the walk and above the summary:

```
$ dnstree intranet.example.com A
...
differs: 192.168.1.1 answers 10.4.2.9, the walk found 203.0.113.80
✔ answered in 412ms · resolver in 3ms (differs) · 4 queries · 4 servers
```

> [!IMPORTANT]
> A difference is not by itself a wrong answer. The two questions were asked
> from different places, so a CDN will honestly answer them differently, and a
> short TTL can turn over between one and the other. What it might instead be is
> the reason the line is there: a split horizon, a filtering resolver, a policy
> answering in the zone's place. `dnstree` reports the difference and leaves the
> reading to you.

Agreement is worth no room and gets none. `--no-compare` turns the whole thing
off, which is also the only way to keep the name being resolved from reaching a
resolver at all.

### Asking rather than reading

Everything above is for a person looking at a resolution. `--expect` is for a
script that already knows what the answer should be and wants to be told when
it is not:

```
$ dnstree --expect 203.0.113.8 www.example.com A
...
✔ answered in 759ms · resolver in 244ms · 3 queries · 3 servers
expected 203.0.113.8, got 104.20.23.154 and 172.66.147.243

$ echo $?
4
```

It takes one of the words that name how far the chain of trust got — `secure`,
`insecure`, `bogus`, `indeterminate` — or what the walk came to — `answer`,
`cname`, `nodata`, `nxdomain` — or else the rdata of a record that has to be
among the answers. Repeat it for each thing that has to hold:

```
$ dnstree --dnssec --expect secure --expect 104.20.23.154 www.example.com A
...
✔ answered in 2s · resolver in 243ms · 6 queries · 3 servers
```

Addresses are compared as addresses and names the way DNS compares names, so
`2001:0db8::1` finds a record written `2001:db8::1` and the case of a name does
not matter. An expectation about the chain of trust is met only by a walk that
followed one: a run that forgot `--dnssec` checked nothing, and reading that as
`secure` would be the tool claiming more than it did.

> [!NOTE]
> The words win where a value could be read either way. A zone that serves a
> record whose rdata reads like one of them — a `TXT` of `secure`, say — is
> asked for with a leading `=`: `--expect =secure` expects rdata and nothing
> else.

What went unmet is written to stderr, because it is the reason for the exit
code rather than something to read alongside the tree, and it is said whether
or not `--explain` was asked for.

The walk's own verdict wins wherever there is one. A broken chain of trust
still exits 3 and a walk that answered nothing still exits 2, even where an
expectation also failed: those are the bigger facts, and a script reading 4 for
either would go looking in the wrong place.

### Saying what happened

`--explain` writes a handful of sentences under the tree: what the walk came
to, how long it goes on being served after it changes, what the chain of trust
made of it, what the zone's nameservers have in common, which servers made it
harder, and whether a recursive resolver agreed.

```
$ dnstree --explain www.example.com
...
✔ answered in 758ms · resolver in 261ms · 3 queries · 3 servers

· www.example.com. A is 104.20.23.154 and 172.66.147.243, answered by hera.ns.cloudflare.com. for example.com.
· a cache may hold this answer for 5 minutes, and the delegation to example.com. for 2 days
```

That second line is the one a change window turns on. Every TTL it reads is one
the walk already recorded — the answer carries its own, the referral above it
carries the parent's — and the two are usually days apart: changing a record is
over in minutes, changing the nameservers that serve it is not. A name that is
not there has no records to carry a lifetime, so the zone's SOA says how long
being denied lasts instead, the shorter of the two fields that can say it.

The resolver the walk is timed against says the other half, where it has
something to say: an answer it had to go and fetch comes back with the zone's
lifetime entire, and one it is serving out of its own cache comes back with
less.

```
$ dnstree --explain www.iana.org
...
✔ answered in 1.6s · resolver in 252ms · 6 queries · 5 servers

· www.iana.org. A is 104.18.24.232 and 104.18.25.232, answered by ns1.cloudflare.net. for cloudflare.net., after 1 alias
· a cache may hold this answer for 5 minutes, and the delegation to cloudflare.net. for 2 days
· 8.8.8.8 is answering this from its cache, with 4 minutes 57 seconds left on the copy it is serving
```

Every sentence is read off the trace the walk recorded, and nothing is worked
out a second time, so the sentences and the tree above them cannot come to
disagree. It is the same reason none of them claims more than the walk checked:
a chain this build could not check reads as unchecked, never as broken.

```
$ dnstree --dnssec --explain dnssec-failed.org
...
✘ bogus in 4.5s · resolver in 453ms (SERVFAIL) · 12 queries · 5 servers

· dnssec-failed.org. A is 96.99.227.255, answered by dns101.comcast.net. for dnssec-failed.org.
· a cache may hold this answer for 5 minutes, and the delegation to dnssec-failed.org. for 1 hour
· the chain of trust breaks at dnssec-failed.org.: no DNSKEY of the zone matches the DS its parent published, so a resolver that validates answers SERVFAIL for this name
```

There is nothing in them that is not already in the tree. They are for the walk
you did not draw yourself — a paste from somebody else, a run out of a script —
and they leave the exit code alone.

What the nameservers of a zone have in common is what it can lose the whole of
at once, so that is read too — but only as far as the walk went. A walk asks one
nameserver of a zone and lists the rest, and the origin AS of a nameserver
nobody asked is never looked up, so it takes `--all` to say anything about the
set:

```
$ dnstree --all --explain www.example.com
...
✔ answered in 3.3s · resolver in 258ms · 64 queries · 64 servers

· www.example.com. A is 104.20.23.154 and 172.66.147.243, answered by elliott.ns.cloudflare.com. for example.com.
· all 2 nameservers of example.com. are in AS13335, so one operator's outage takes the whole zone with it
```

A set that is not all accounted for is not held against itself: a nameserver
that was never asked, or one the AS lookups did not answer for, leaves the whole
question unanswered rather than half answered. The address families are read off
the parent's glue instead, which is whole whether or not the servers were asked,
so a zone with no IPv4 anywhere in its delegation is named without `--all`.

`--format json` and `--format dot` refuse `--explain`: both are read by a
program, which has the same facts in fields already.

### What has changed since last time

Most of diagnosis is working out what is different. `--diff` holds the walk
against the last one it remembers of the same question, says what moved, and
remembers this one in its place:

```
$ dnstree --diff www.example.com
...
✔ answered in 745ms · resolver in 254ms · 3 queries · 3 servers

· nothing to compare: this is the first walk of www.example.com. A that was remembered
```

```
$ dnstree --diff www.example.com
...
✔ answered in 754ms · resolver in 261ms · 3 queries · 3 servers

· nothing has changed since the walk of www.example.com. A moments ago
```

It always says something. Silence would read as nothing having changed when it
may mean nothing was remembered.

What it watches is the answer and the path to it: an answer that changed, a name
that stopped answering or stopped existing, a TTL cut short before a move, a
nameserver that came or went, a zone cut that appeared or disappeared, and the
chain of trust over each zone — a zone that was signed and is not any more, or
one that has gone bogus since, which is the line worth being woken up for.

Answers are compared as sets, so a nameserver rotating an RRset between one
walk and the next is not a change. Neither is a fact only one of the two walks
kept: a run without `--dnssec` follows no chain and remembers no verdict, and
that is not a zone that stopped being signed.

> [!NOTE]
> `--diff` is the only thing in `dnstree` that writes to the disk, and it writes
> the names you looked up and when. One small file per question goes under
> `$DNSTREE_CACHE`, or `$XDG_CACHE_HOME/dnstree`, or `~/.cache/dnstree` —
> readable, and safe to delete at any time. Without the flag, nothing is read
> and nothing is kept.

### Watching it happen

`--live` redraws the tree in place as the walk makes it, so the referrals
arrive one at a time instead of all at once at the end. The hop that just
landed is pointed at, `└─▸`, so the eye finds it without reading the tree
again.

Under the tree sits the part that moves on its own, on a timer rather than on a
hop — here, half a second into a walk:

```
. (root)
├── a.root-servers.net. 198.41.0.4  250ms  NOERROR  referral → com.
│   └─▸ l.gtld-servers.net. 192.41.162.30  260ms  NOERROR  referral → example.com.
├── a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
├── b.root-servers.net. 170.247.170.2  (not queried)
└── (and 23 more not queried)
    ⠧ asking hera.ns.cloudflare.com. 108.162.192.162  example.com.  51ms

⠧  562ms · 3 queries · 3 servers · . → com. → example.com.
```

A query is named there from the moment it goes out until the moment it comes
back, which is what tells a walk waiting on a silent server apart from a walk
that has hung — nothing joins the tree until an answer does. The footer carries
the clock, what the walk has spent, and the zones it has come down through.

The frames are scratch: when the walk is over they are wiped and the finished
tree is written where they stood, which is exactly what a run without `--live`
prints, followed by one line saying how it went:

```
✔ answered in 747ms · 3 queries · 3 servers
```

> [!NOTE]
> Off a terminal the flag does nothing, and it cannot be combined with
> `--format json` or `--format dot`, both of which are written once, at the end.

### Leaving it running

`--live` watches one walk being made. `--watch` watches the same question over
and over: it draws the tree once, then walks it again every interval and says
only what has changed since the walk before it.

```
$ dnstree --watch 30s www.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  AS19836  241ms  NOERROR  referral → com.
...
✔ answered in 711ms · 3 queries · 3 servers
```

And then nothing, until something moves:

> `14:22:07` the answer changed: 203.0.113.8 became 198.51.100.4

A round that finds nothing changed says nothing at all. Silence is what it is
for: it is meant to be left in the corner of a screen through a change window,
and a heartbeat every thirty seconds would be something to learn to ignore.

Each round is a whole walk from the root servers down, so the interval is worth
choosing rather than making as small as possible. Anything under a second is
refused.

It watches what `--diff` watches, and for the same reason — the answer, the TTL
on it, the nameservers of each zone on the way down, the zone cuts, and the
chain of trust over them. With `--diff` the first round is held against the walk
remembered from last time and remembers itself in its place; every round after
that is held against the round before it and writes nothing.

> [!TIP]
> With `--expect` it stops as soon as what was asked for holds, which turns it
> from a thing to glance at into a thing to wait on:
>
> ```
> $ dnstree --watch 30s --expect 198.51.100.4 www.example.com A && deploy
> ```

Interrupting it ends it, and it exits with whatever the last walk it finished
earned — so a wait for something that never arrived still exits 4, and a name
that stopped resolving altogether still exits 2. A walk cut off part way through
by the interrupt is not read as a finding about the name: the last one that
finished on its own is what answers.

`--format json`, `dot` and `web` are written once, at the end, so there is
nothing for a watch to change; all three refuse it, as they refuse `--live`.

### Other formats

`--format emoji` tells the same walk in emoji — a 🛰️ for a referral, a 🎯 for
the answer, a 💤 for a server nobody asked, ⚡ and 🐢 for the fast and the slow.
It pairs well with `--live`.

<details>
<summary>The same walk, in emoji</summary>

```
$ dnstree --format emoji --live www.example.com
🌍  . (root)
├── 🛰️  a.root-servers.net. 198.41.0.4  AS19836  248ms  NOERROR  referral → com.
│   ├── 🛰️  l.gtld-servers.net. 192.41.162.30  AS19836  251ms  NOERROR  referral → example.com.
│   │   ├── 🎯  hera.ns.cloudflare.com. 108.162.192.162  AS13335  236ms  NOERROR  AA
│   │   │   ├── 📍 www.example.com. 300 A 172.66.147.243
│   │   │   └── 📍 www.example.com. 300 A 104.20.23.154
│   │   ├── 💤  hera.ns.cloudflare.com. 172.64.32.162  (not queried)
│   │   ├── 💤  hera.ns.cloudflare.com. 173.245.58.162  (not queried)
│   │   ├── 💤  hera.ns.cloudflare.com. 2606:4700:50::adf5:3aa2  (not queried)
│   │   └── 💤  (and 8 more not queried)
│   ├── 💤  l.gtld-servers.net. 2001:500:d937::30  (not queried)
│   ├── 💤  j.gtld-servers.net. 192.48.79.30  (not queried)
│   ├── 💤  j.gtld-servers.net. 2001:502:7094::30  (not queried)
│   └── 💤  (and 22 more not queried)
├── 💤  a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
├── 💤  b.root-servers.net. 170.247.170.2  (not queried)
├── 💤  b.root-servers.net. 2801:1b8:10::b  (not queried)
└── 💤  (and 22 more not queried)
✔ answered in 749ms · resolver in 11ms · 3 queries · 3 servers
```

</details>

`--format web` draws nothing in the terminal at all. It serves the finished walk
as a page on this machine and opens a browser at it:

```
$ dnstree --format web --dnssec www.example.com
the walk is at http://127.0.0.1:52341/
it is served until this command is interrupted
```

The page is the same walk with every hop worth clicking on — the records it
returned, the delegation it pointed at, what the server said about its own
answer — beside three other ways to read it: what each server cost, who the
addresses belong to grouped by origin AS, and the chain of trust cut by cut.
`--explain` and `--diff` put their sentences on the page rather than under a
tree. Nothing is fetched from anywhere: the page is in the binary, and the walk
behind it is served under `/trace.json`, byte for byte what `--format json`
writes.

It listens on `127.0.0.1` and a free port, and answers only a request that
reached it by address — a walk names the servers it asked and the addresses they
answered from, which is nobody else's business. `--web-addr :8080` moves it,
which is what a walk made on another machine needs, and says so in a line when
the address it was given is not this machine's alone. `--no-browser` leaves the
address to be opened by hand.

`--format ascii` swaps the branches for `` |-- `` and drops the colour, for
pasting into documents. `--format json` writes a versioned document with
durations in milliseconds. `--format dot` writes a Graphviz graph, one node per
query, clustered by zone:

```
dnstree --format dot www.example.com | dot -Tsvg > trace.svg
```

![dnstree dot format example](docs/demo-dot.svg "dnstree dot format example")

`--schema` prints the JSON Schema of that document and stops, so whatever reads
the output can be held against the shape of it — and told what a field means —
without reading the source:

```
dnstree --schema > trace.schema.json
dnstree --format json www.example.com | check-jsonschema --schemafile trace.schema.json -
```

It describes one version of the shape, the one the binary it came out of
writes. `schema_version` is raised whenever a field changes meaning or goes
away, never for one that is merely added, so nothing in the schema forbids
properties it does not name: a reader that understands a version keeps
understanding it.

The same schema is served at
[rafaeljusto.github.io/dnstree/trace.schema.json](https://rafaeljusto.github.io/dnstree/trace.schema.json),
which is the address its `$id` names, so a validator can be pointed at it with
no binary to hand.

## How it walks

Every hop is a question to one server, and every answer is classified before
anything is followed:

- A **referral** is NOERROR with the AA bit clear, an empty answer, and one NS
  RRset whose owner sits strictly below the zone that was asked and covers the
  name being chased. Because a referral only ever goes down, a zone cannot
  repeat, and the walk cannot circle.
- **Glue** is taken only from a server entitled to give it: addresses at or
  below the zone that server holds. That is how the root can hand out the
  addresses of the gTLD servers while a `com.` server cannot vouch for a name in
  `.net`. A nameserver named elsewhere with no usable address is found with a
  walk of its own, drawn as a branch.
- A nameserver **inside the zone it serves, with no glue**, cannot be reached by
  anything: the delegation is broken, and the walk says so rather than looping.
- **Aliases** start again from the root for the target, bounded and cycle
  checked. **Truncation** brings the answer back over TCP, and a server that
  cannot parse EDNS0 is asked again without it; both stay on the hop that needed
  them.
- Query, depth and alias **budgets** bound every walk, so the tool always
  terminates and always draws what it learned.

The root hints and the DNSSEC trust anchors are embedded in the binary.
`make roothints` refreshes them, verifying ICANN's signature over the anchors
before believing a byte.

## Developing

```
make check        # build, lint, test -race, vuln
make lint         # go vet and golangci-lint
make lint-docker  # hadolint against the Dockerfile
make vuln         # govulncheck against the vulnerability database
make live         # the smoke test that goes out to the real root servers
make demos        # re-record the terminal demos in docs/ from tapes/
make roothints    # refresh the embedded root hints and trust anchors
make dist         # cross compile a release into dist/
make image        # build the container image for this machine
```

A release is cut by running the `release` workflow from `main`: it reads the
commits since the last tag, works out the version their prefixes ask for,
creates the tag, and publishes the archives alongside a multi-architecture
image on `ghcr.io`. The same commits become the changelog, carried by both the
annotated tag and the release notes. `dry_run` reports the version it
would pick without tagging anything, and `bump` overrides it. See
[cmd/next-version](cmd/next-version/) for how a subject earns a bump, and what
changes while the major version is still zero.

The engine is tested offline against in-process authoritative servers
(`internal/testutil/fakens`), signed hierarchies included, so every delegation
failure this tool reports has a test that produces it on purpose.

The recordings under `docs/` are written by [vhs](https://github.com/charmbracelet/vhs)
from the tapes in [tapes/](tapes/), one per scene. `make demos` rebuilds the
binary and records all four; it needs `ttyd` and `ffmpeg` on the PATH, and it
walks the real root servers, so the timings in a recording are whatever the
link gave that day. `make check` leaves them alone.

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers
how to get a change reviewed, how the tests work, and why your commit subject
decides the next version number. Everyone taking part is expected to follow the
[code of conduct](CODE_OF_CONDUCT.md).

Found a security problem? Please do not open an issue: the
[security policy](SECURITY.md) says where to send it.

## Licence

[MIT](LICENSE).
