# dnstree

[![ci](https://github.com/rafaeljusto/dnstree/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaeljusto/dnstree/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rafaeljusto/dnstree)](https://goreportcard.com/report/github.com/rafaeljusto/dnstree)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Resolve a name the way a resolver does — from the root servers down, following
every referral — and draw the path it took.

```
$ dnstree www.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  270ms  NOERROR  referral → com.
│   ├── l.gtld-servers.net. 192.41.162.30  246ms  NOERROR  referral → example.com.
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  231ms  NOERROR  AA
│   │   │   ├── www.example.com. 300 A 104.20.23.154
│   │   │   └── www.example.com. 300 A 172.66.147.243
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
```

`dig +trace` tells you the same story in prose. dnstree draws it, and says what
it found on the way: which servers were lame, which delegations are broken, how
long each hop took, which AS announces each address, and whether the chain of
trust holds. (These are real runs, recorded on a slow link and with the origin
AS lookups unable to reach anything; on a normal network the hops are quicker
and each address carries the AS that announces it.)

## Installing

```
go install github.com/rafaeljusto/dnstree/cmd/dnstree@latest
```

Or take a binary from the [releases](https://github.com/rafaeljusto/dnstree/releases),
or run it straight from a container:

```
docker run --rm ghcr.io/rafaeljusto/dnstree www.example.com A
```

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
| `--no-asn` | skip the origin AS lookups |
| `--format` | `tree`, `ascii`, `json` or `dot` |
| `--color` | `auto`, `always` or `never` |
| `--timeout`, `--retries` | how long one query may take, and how often to ask again |
| `--max-depth`, `--max-queries`, `--max-cname` | the budgets that keep a walk finite |
| `--port` | the port nameservers are asked on |
| `--root-hints`, `--trust-anchors` | start somewhere other than the built-in root |
| `--debug` | report every hop on stderr as it is made |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | something answered |
| 1 | the command line, or the question, could not be read |
| 2 | the walk ended without an answer |
| 3 | the chain of trust is broken |

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
```

A zone whose parent publishes no DS reads `[insecure]`, and everything below it
stays that way. A link that cannot be checked at all — an algorithm this build
does not know — reads `[indeterminate]`, which is not the same as `[bogus]`.
Denial of existence is not proved: NSEC and NSEC3 are not read, so an empty
answer in a signed zone is reported as indeterminate rather than claimed.

### Other formats

`--format ascii` swaps the branches for `` |-- `` and drops the colour, for
pasting into documents. `--format json` writes a versioned document with
durations in milliseconds. `--format dot` writes a Graphviz graph, one node per
query, clustered by zone:

```
dnstree --format dot www.example.com | dot -Tsvg > trace.svg
```

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
`scripts/refresh-roothints.sh` refreshes them, verifying ICANN's signature over
the anchors before believing a byte.

## Developing

```
make check        # build, lint, test -race, vuln
make lint         # go vet and golangci-lint
make lint-docker  # hadolint against the Dockerfile
make vuln         # govulncheck against the vulnerability database
make live         # the smoke test that goes out to the real root servers
make dist         # cross compile a release into dist/
make image        # build the container image for this machine
```

A release is cut by running the `release` workflow from `main`: it reads the
commits since the last tag, works out the version their prefixes ask for,
creates the tag, and publishes the archives alongside a multi-architecture
image on `ghcr.io`. `dry_run` reports the version it
would pick without tagging anything, and `bump` overrides it. See
[cmd/next-version](cmd/next-version/) for how a subject earns a bump, and what
changes while the major version is still zero.

The engine is tested offline against in-process authoritative servers
(`internal/testutil/fakens`), signed hierarchies included, so every delegation
failure this tool reports has a test that produces it on purpose.

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers
how to get a change reviewed, how the tests work, and why your commit subject
decides the next version number. Everyone taking part is expected to follow the
[code of conduct](CODE_OF_CONDUCT.md).

Found a security problem? Please do not open an issue: the
[security policy](SECURITY.md) says where to send it.

## Licence

[MIT](LICENSE).
