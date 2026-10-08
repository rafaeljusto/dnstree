<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
  <img src="docs/logo.svg" alt="dnstree" width="272" height="80">
</picture>

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

- [Installing](#installing)
  - [For an AI assistant](#for-an-ai-assistant)
- [Using it](#using-it)
  - [Reverse lookups](#reverse-lookups)
  - [Exit codes](#exit-codes)
- [The guide](#the-guide)
- [How it walks](#how-it-walks)
- [Contributing](#contributing)
- [Licence](#licence)

## Installing

```
go install github.com/rafaeljusto/dnstree/v2/cmd/dnstree@latest
```

Or run it straight from a container:

```
docker run --rm ghcr.io/rafaeljusto/dnstree www.example.com A
```

Every [release](https://github.com/rafaeljusto/dnstree/releases) also carries a
binary for macOS, Linux, FreeBSD and Windows, a Debian, RPM and Alpine package
for amd64, arm64 and 32-bit arm, and a Homebrew formula. The packages install a man
page: `man dnstree`. `checksums.txt` covers every file in the release.
[`packaging/`](packaging/) says how they are built.

<details>
<summary>Installing a downloaded package</summary>

The release notes give the command for each, with the version in place of
`X.Y.Z`:

```
# Debian, Ubuntu
sudo dpkg -i dnstree_X.Y.Z_amd64.deb

# Fedora, RHEL
sudo rpm -i dnstree-X.Y.Z-1.x86_64.rpm

# Alpine
sudo apk add --allow-untrusted dnstree_X.Y.Z_x86_64.apk

# Homebrew
brew install --formula ./dnstree.rb
```

</details>

### For an AI assistant

A [skill](packaging/plugin/skills/dnstree/SKILL.md) teaches a model which
flags answer which question, how to read the exit codes, and what not to run
without asking. In Claude Code:

```
/plugin marketplace add rafaeljusto/dnstree
/plugin install dnstree@dnstree
```

Other agents that read `SKILL.md` folders can copy
[`packaging/plugin/skills/dnstree/`](packaging/plugin/skills/dnstree/) into
their skills directory. Either way, dnstree itself has to be installed.

## Using it

```
dnstree [flags] NAME [TYPE...]
```

`TYPE` defaults to `A`. Give several and each is walked in turn, from the root
servers down; [`--names`](docs/guide/scripting.md#several-questions-in-one-run)
reads a list of them from a file. A type names one RRset, so `ANY` and the zone transfers
`AXFR` and `IXFR` are refused: servers answer `ANY` with a sample of their
choosing (RFC 8482), and a walk would draw that as the whole answer.

A name in any script is asked in punycode, which is how the DNS holds it:
`dnstree münchen.de` walks to `xn--mnchen-3ya.de`, and draws it that way.

| Flag | What it does |
| --- | --- |
| [`-x`](#reverse-lookups) | resolve the PTR of this address, in place of a name and a type |
| [`--names`](docs/guide/scripting.md#several-questions-in-one-run) | walk every `NAME [TYPE...]` line of a file, or of `-` for the standard input, one after another |
| `-4`, `-6` | ask only IPv4 or only IPv6 servers; the others are drawn unqueried |
| [`--udp`](docs/guide/configuring.md#carrying-the-queries), `--tcp` | carry the queries over plain DNS (`--udp` is the default) |
| [`--dot`](docs/guide/configuring.md#carrying-the-queries), `--doh` | carry them encrypted, over TLS or HTTPS |
| [`--fallback`](docs/guide/configuring.md#carrying-the-queries) | let plain DNS pick up a hop the transport could not |
| `--all` | ask every nameserver of a zone, not just the first that answers |
| [`--dnssec`](docs/guide/dnssec.md#following-the-chain-of-trust) | ask for signatures and follow the chain of trust |
| [`--check-ns`](docs/guide/zones.md#whether-the-parent-and-the-child-agree) | ask the zone that answered for its own NS set, its nameservers' addresses and its CSYNC, and compare them with the delegation and its glue |
| [`--check-ds`](docs/guide/dnssec.md#what-the-zone-asks-its-parent) | ask the zone for its CDS and CDNSKEY and compare them with the parent's DS, or, for a zone with none, check the bootstrap signals of RFC 9615 |
| [`--report`](docs/guide/dnssec.md#telling-the-zone-it-is-broken) | tell the agent a zone names that its chain of trust is bogus (RFC 9567) |
| [`--serial`](docs/guide/zones.md#whether-they-all-have-the-same-zone) | ask every nameserver of the zone which copy of it they serve, and compare |
| [`--check-axfr`](docs/guide/zones.md#what-they-give-a-stranger) | ask every nameserver of the zone for the whole of it, as a stranger, and say which hand it over |
| [`--check-recursion`](docs/guide/zones.md#what-they-give-a-stranger) | ask every nameserver of the zone to look up somebody else's name, and say which do |
| [`--check-edns`](docs/guide/zones.md#how-they-handle-edns) | ask every nameserver of the zone the RFC 8906 EDNS tests, and say which fail them |
| [`--caa`](docs/guide/zones.md#who-may-issue-certificates-for-it) | say which certificate authorities may issue for the name, and which CAA set decides it (RFC 8659) |
| [`--spf`](docs/guide/zones.md#what-a-check-of-its-mail-costs) | draw the name's SPF policy as the tree of lookups a mail server makes, and count them against the limit of ten (RFC 7208) |
| [`--mail`](docs/guide/zones.md#whether-its-mail-can-be-sent-verified) | check the name's MX hosts the way a sender that checks DANE does, and its MTA-STS, TLS-RPT and DMARC records (RFC 7672) |
| [`--tlsa`](docs/guide/zones.md#whether-the-certificates-match) | connect to each MX host DANE covers, start TLS, and match the certificate it presents against its TLSA set; needs `--mail` and `--dnssec` |
| [`--svcb`](docs/guide/zones.md#where-a-browser-connects) | follow the name's HTTPS or SVCB records to the servers they name, and hold their address hints against what the servers resolve to (RFC 9460) |
| [`--deps`](docs/guide/zones.md#what-it-depends-on) | list every zone the name depends on: the walk's own, and those the lookups of every nameserver of each go through in turn, with which are unsigned |
| [`--rdap`](docs/guide/zones.md#whether-its-registration-is-about-to-run-out) | ask the domain's registry when the registration runs out and whether it is held, and compare its nameservers and DS with the TLD's (RFC 9083) |
| [`--propagation`](docs/guide/zones.md#how-long-a-change-takes-to-reach-everyone) | say how long each kind of change to the zone takes to reach every cache, from the TTLs the walk saw |
| [`--check`](docs/guide/zones.md#all-of-it-at-once) | run the checks that grade a zone together, and grade its health one area at a time: passed, worth a look, broken or skipped |
| [`--nsid`](docs/guide/zones.md#which-machine-answered) | ask each server which of itself answered, and draw it beside the address |
| [`--cookie`](docs/guide/zones.md#which-servers-support-dns-cookies) | send each server a DNS cookie (RFC 7873), and say how it answered |
| [`--qmin`](docs/guide/zones.md#asking-only-what-each-zone-needs) | ask each zone for no more of the name than it needs, the way resolvers do (RFC 9156) |
| [`--without`](docs/guide/zones.md#whether-it-still-answers-with-a-server-down) | walk as though this nameserver, address or prefix were down, and see whether the name still answers; repeat it |
| [`--try-ns`](docs/guide/zones.md#whether-it-will-answer-on-new-nameservers) | walk as though `ZONE` were already delegated to `SERVER`, before the registry is told; repeat it for each new nameserver |
| [`--subnet`](docs/guide/resolvers.md#asking-from-somewhere-else) | ask as though from this client subnet, and say what each server made of it |
| [`--no-asn`](docs/guide/configuring.md#pointing-it-somewhere-else) | skip the origin AS lookups |
| [`--no-compare`](docs/guide/resolvers.md#against-your-resolver) | skip the question put to a recursive resolver, and the comparison with it |
| [`--ddr`](docs/guide/resolvers.md#whether-a-resolver-can-be-used-encrypted) | ask each resolver which encrypted resolvers stand for it (RFC 9462), and say what they offer |
| [`--format`](docs/guide/output.md#other-formats) | `tree` (the default), `ascii`, `emoji`, `waterfall`, `waterfall-ascii`, `waterfall-mermaid`, `markdown`, `json`, `dot`, `mermaid`, `openmetrics`, `web` or `web-3d` |
| [`--web-addr`](docs/guide/output.md#other-formats), `--no-browser` | where `--format web` and `web-3d` serve the page, and whether a browser is opened at it |
| [`--live`](docs/guide/output.md#watching-it-happen) | draw the tree as the walk makes it, hop by hop |
| [`--watch`](docs/guide/scripting.md#leaving-it-running) | walk again this often, and say only what changed since the walk before |
| [`--explain`](docs/guide/output.md#saying-what-happened) | say in sentences what the walk came to, under the tree |
| [`--diff`](docs/guide/scripting.md#what-has-changed-since-last-time) | say what has changed since the last walk of the same question |
| [`--expect`](docs/guide/scripting.md#asking-rather-than-reading) | require this of the walk, and exit 4 where it does not hold; repeat it |
| [`--from`](docs/guide/scripting.md#drawing-a-walk-again) | draw a walk `--format json` saved, from a file or `-`, instead of making one |
| [`--against`](docs/guide/scripting.md#drawing-a-walk-again) | say how the walk differs from one `--format json` saved, from a file or `-` |
| [`--pcap`](docs/guide/output.md#the-bytes-on-the-wire) | save the walk's queries and answers as a packet capture, for Wireshark or `tcpdump -r` |
| `--color` | `auto` (the default: only on a terminal, and off where `NO_COLOR` is set or `TERM` is unset or `dumb`), `always` or `never` |
| `--timeout`, `--retries` | how long one query may take (2s), and how often to ask again after a silence (once) |
| `--max-depth`, `--max-queries`, `--max-cname` | the budgets that keep a walk finite: 16 zone cuts, 64 queries (256 with `--all`, 512 with `--check` or `--deps`), 8 aliases |
| [`--port`](docs/guide/configuring.md#pointing-it-somewhere-else) | the port nameservers are asked on (53; 853 with `--dot`, 443 with `--doh`) |
| [`--root-hints`](docs/guide/configuring.md#pointing-it-somewhere-else) | where the walk starts, instead of the built-in hints |
| [`--trust-anchors`](docs/guide/configuring.md#pointing-it-somewhere-else) | the DS records to trust, instead of the built-in ones |
| [`--root`](docs/guide/configuring.md#pointing-it-somewhere-else) | one server to start from, instead of a hints file; repeat it for more |
| [`--resolver`](docs/guide/configuring.md#pointing-it-somewhere-else) | a recursive server to use, instead of the host's own; repeat it to ask several |
| [`--tls-ca`](docs/guide/configuring.md#carrying-the-queries), `--tls-insecure` | how `--dot` and `--doh` verify a server, or that they do not |
| [`--config`](docs/guide/configuring.md#defaults), `--no-config` | take the defaults from this file, or from no file at all |
| `--debug` | report every hop on stderr as it is made |
| [`--schema`](docs/guide/output.md#other-formats) | print the JSON Schema of `--format json` and stop |
| `--version` | print the version and stop |

### Reverse lookups

`-x ADDR` asks for the PTR record of an address, the way `dig -x` does:
`192.0.2.1` is asked as `1.2.0.192.in-addr.arpa.`, and an IPv6 address nibble
by nibble under `ip6.arpa.`. It takes the place of the name and the type. The
reverse tree is delegated like any other, only more deeply, and its
nameservers are usually named somewhere else entirely, so a reverse walk is
where the side walks that resolve a nameserver's own name are most often seen.
A delegation below a /24 (RFC 2317) arrives as an alias, and is followed.

<details>
<summary>The walk to the PTR of 8.8.8.8</summary>

```
$ dnstree -x 8.8.8.8 --no-asn
. (root)
├── a.root-servers.net. 198.41.0.4  164ms  NOERROR  referral → in-addr.arpa.
│   ├── f.in-addr-servers.arpa. 193.0.9.1  244ms  NOERROR  referral → 8.in-addr.arpa.
│   │   ├── . (root)  (resolving r.arin.net.)
│   │   │   ├── a.root-servers.net. 198.41.0.4  178ms  NOERROR  referral → net.
│   │   │   │   ├── m.gtld-servers.net. 192.55.83.30  178ms  NOERROR  referral → arin.net.
│   │   │   │   │   ├── ns1.arin.net. 199.212.0.108  149ms  NOERROR  AA
│   │   │   │   │   │   └── r.arin.net. 43200 A 199.180.180.63
│   │   │   │   │   ├── ns1.arin.net. 2001:500:13::108  (not queried)
│   │   │   │   │   ├── ns2.arin.net. 199.71.0.108  (not queried)
│   │   │   │   │   ├── ns2.arin.net. 2001:500:31::108  (not queried)
│   │   │   │   │   └── (and 4 more not queried)
│   │   │   │   ├── m.gtld-servers.net. 2001:501:b1f9::30  (not queried)
│   │   │   │   ├── k.gtld-servers.net. 192.52.178.30  (not queried)
│   │   │   │   ├── k.gtld-servers.net. 2001:503:d2d::30  (not queried)
│   │   │   │   └── (and 22 more not queried)
│   │   │   ├── a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
│   │   │   ├── b.root-servers.net. 170.247.170.2  (not queried)
│   │   │   ├── b.root-servers.net. 2801:1b8:10::b  (not queried)
│   │   │   └── (and 22 more not queried)
│   │   └── r.arin.net. 199.180.180.63  172ms  NOERROR  referral → 8.8.8.in-addr.arpa.
│   │       ├── . (root)  (resolving ns1.google.com.)
│   │       │   ├── a.root-servers.net. 198.41.0.4  150ms  NOERROR  referral → com.
│   │       │   │   ├── l.gtld-servers.net. 192.41.162.30  191ms  NOERROR  referral → google.com.
│   │       │   │   │   ├── ns2.google.com. 2001:4860:4802:34::a  63ms  NOERROR  AA
│   │       │   │   │   │   └── ns1.google.com. 345600 A 216.239.32.10
│   │       │   │   │   ├── ns2.google.com. 216.239.34.10  (not queried)
│   │       │   │   │   ├── ns1.google.com. 2001:4860:4802:32::a  (not queried)
│   │       │   │   │   ├── ns1.google.com. 216.239.32.10  (not queried)
│   │       │   │   │   └── (and 4 more not queried)
│   │       │   │   ├── l.gtld-servers.net. 2001:500:d937::30  (not queried)
│   │       │   │   ├── j.gtld-servers.net. 192.48.79.30  (not queried)
│   │       │   │   ├── j.gtld-servers.net. 2001:502:7094::30  (not queried)
│   │       │   │   └── (and 22 more not queried)
│   │       │   ├── a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
│   │       │   ├── b.root-servers.net. 170.247.170.2  (not queried)
│   │       │   ├── b.root-servers.net. 2801:1b8:10::b  (not queried)
│   │       │   └── (and 22 more not queried)
│   │       └── ns1.google.com. 216.239.32.10  58ms  NOERROR  AA
│   │           └── 8.8.8.8.in-addr.arpa. 86400 PTR dns.google.
│   ├── f.in-addr-servers.arpa. 2a13:27c0:30::1  (not queried)
│   ├── b.in-addr-servers.arpa. 199.253.183.183  (not queried)
│   ├── b.in-addr-servers.arpa. 2001:500:87::87  (not queried)
│   └── (and 8 more not queried)
├── a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
├── b.root-servers.net. 170.247.170.2  (not queried)
├── b.root-servers.net. 2801:1b8:10::b  (not queried)
└── (and 22 more not queried)
✔ answered in 1.5s · resolver in 9ms · 10 queries · 8 servers
```

</details>

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | something answered |
| 1 | the command line, a file it names, or the address `--format web` or `web-3d` serves on could not be used |
| 2 | the walk ended without an answer |
| 3 | the chain of trust is broken |
| 4 | an expectation given with `--expect` was not met |

The tree, the summary, `--explain` and the address `--format web` serves on go
to stdout; errors, `--debug`, an unmet expectation, a cache `--diff` could not
use and a report `--report` could not send go to stderr. `-h` prints
the usage on stderr and exits 1.

## The guide

Each feature has a section of its own in [`docs/guide/`](docs/guide/), with real output:

- [Configuring](docs/guide/configuring.md): the file of defaults, pointing a walk
  at servers other than the real root, and the transports.
- [DNSSEC](docs/guide/dnssec.md): the chain of trust, `--check-ds`, `--report`, and
  what DNSSEC is worth to ECH.
- [Checking a zone](docs/guide/zones.md): parent and child NS sets, serials, zone
  transfers and open recursion, how they handle EDNS, aliases where they may not
  be, who may issue certificates, what a check of its mail costs, which servers
  a browser connects to, how long a change takes to reach every cache, extended
  errors, NSID, cookies, `--qmin`, `--without`, `--try-ns` and answer sizes.
- [Resolvers](docs/guide/resolvers.md): how the walk compares with the resolvers
  people use, from here or from another subnet, and whether they offer
  encryption.
- [Reading a walk](docs/guide/output.md): `--explain`, `--live`, the waterfall,
  every other format, `--schema` and `--pcap`.
- [Scripts and monitoring](docs/guide/scripting.md): `--expect`, `--diff`, several
  questions and `--names`, `--watch`, saved walks and OpenMetrics.
- [dnstree-web](docs/guide/dnstree-web.md): the same walk behind a form, as a
  service.

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

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers
how to get a change reviewed, how the tests work, the `make` targets, and why
your commit subject decides the next version number. Everyone taking part is
expected to follow the [code of conduct](CODE_OF_CONDUCT.md).

Found a security problem? Please do not open an issue: the
[security policy](SECURITY.md) says where to send it.

## Licence

[MIT](LICENSE).
