# Scripts and monitoring

Holding a walk to what it should find, comparing walks, and feeding a monitoring
system.

- [Asking rather than reading](#asking-rather-than-reading)
- [What has changed since last time](#what-has-changed-since-last-time)
- [Several questions in one run](#several-questions-in-one-run)
- [Leaving it running](#leaving-it-running)
- [Drawing a walk again](#drawing-a-walk-again)
- [Numbers for a monitoring system](#numbers-for-a-monitoring-system)

## Asking rather than reading

The rest of the guide is for a person looking at a resolution. `--expect` is
for a script that already knows what the answer should be and wants to be told
when it is not:

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
`cname`, `nodata`, `nxdomain` — or `fresh`, below — or `caa:` and a
certificate authority, below that — or else the rdata of a record that has to
be among the answers. Repeat it for each thing that has to
hold:

```
$ dnstree --dnssec --expect secure --expect 104.20.23.154 www.example.com A
...
✔ answered in 2s · resolver in 243ms · 6 queries · 3 servers
```

`fresh` asks for a chain of trust that holds and none of whose signatures is
late in the life it was made for, which is what a signer that is still working
leaves behind it. `fresh:3d` or `fresh:36h` asks instead that none of them runs
out that soon, whatever it was made for. The difference is worth having: a zone
signed on the fly, as Cloudflare signs, hands out signatures that last a day and
are always fresh and never three days ahead:

```
$ dnstree --dnssec --expect fresh --expect fresh:3d www.example.com A
...
✔ answered in 1.1s · resolver in 33ms · 6 queries · 3 servers
expected fresh:3d, got signatures over example.com. that run out in 1 day 1 hour

$ echo $?
4
```

`caa:letsencrypt.org` asks that `--caa` found that authority free to issue for
the name, which is how a renewal about to be refused is caught before it is.
For a wildcard such as `*.example.com` it asks the same of `issuewild`.
A failed lookup, or a critical property nobody knows, fails it whatever the set
names:

```
$ dnstree --caa --expect caa:letsencrypt.org --no-asn --no-compare mail.google.com
...
✔ answered in 726ms · 5 queries · 3 servers
expected caa:letsencrypt.org, got pki.goog

$ echo $?
4
```

Addresses are compared as addresses and names the way DNS compares names, so
`2001:0db8::1` finds a record written `2001:db8::1`, the case of a name does not
matter, and a name typed in another script finds the punycode the zone holds. An expectation about the chain of trust is met only by a walk that
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

## What has changed since last time

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
> `$DNSTREE_CACHE`, or `$XDG_CACHE_HOME/dnstree`, or `~/.cache/dnstree`
> (`%LocalAppData%\dnstree` on Windows) — readable, and safe to delete at any
> time. Without the flag, nothing is read and nothing is kept. A cache that
> cannot be read or written costs the comparison and says so in one line on
> stderr; the walk still runs.

## Several questions in one run

Give a name several types and each is walked in turn, under a line that says
which question the tree answers:

```
$ dnstree example.com A MX
example.com. A
. (root)
├── a.root-servers.net. 198.41.0.4  356ms  NOERROR  referral → com.
│   ├── l.gtld-servers.net. 192.41.162.30  244ms  NOERROR  referral → example.com.
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  231ms  NOERROR  AA
│   │   │   ├── example.com. 300 A 104.20.23.154
│   │   │   └── example.com. 300 A 172.66.147.243
...
✔ answered in 832ms · resolver in 355ms · 3 queries · 3 servers

example.com. MX
. (root)
├── a.root-servers.net. 198.41.0.4  240ms  NOERROR  referral → com.
│   ├── l.gtld-servers.net. 192.41.162.30  302ms  NOERROR  referral → example.com.
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  234ms  NOERROR  AA
│   │   │   └── example.com. 300 MX 0 .
...
✔ answered in 776ms · resolver in 237ms · 3 queries · 3 servers
```

`--names` reads the questions from a file, or from the standard input where it
is given `-`: a line to a name, written as on the command line, with the types
to ask of it after it and `A` where there are none. Blank lines and lines
opening with `#` are skipped, so a list kept beside a change can say what it is
for:

```
# before moving the mail
example.com MX TXT
www.example.com A AAAA
```

```
$ dnstree --names before-the-move.txt
example.com. MX
...
www.example.com. AAAA
...
✔ answered in 708ms · resolver in 242ms · 3 queries · 3 servers
```

Every question is a walk of its own from the root servers down, with its own
budgets, and nothing is carried from one to the next: the second walk to
`example.com.` asks the root again, as a resolver with an empty cache would.
Every name and type is checked before anything is asked, so a misspelt one
fails the run straight away rather than after the walks before it.

The run exits with the worst any of the walks earned: 3 where a chain of trust
broke, then 2 where one came to no answer, and 0 only where they all answered.
`--diff` holds each walk against the last one of its own question, and `--live`
draws each as it is made. What can only be said of one walk is refused:
`--expect`, which could not say which question it was about, `--against`,
`--watch`, and the formats written as one document — `json`, `dot`, `mermaid`,
`waterfall-mermaid`, `openmetrics`, `web` and `web-3d`. `--format markdown`
writes a report per question, each headed with its own.

## Leaving it running

`--live` watches one walk being made. `--watch` watches the same question over
and over: it draws the tree once, then walks it again every interval and says
only what has changed since the walk before it.

```
$ dnstree --watch 30s www.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  AS19836  248ms  NOERROR  referral → com.
...
✔ answered in 711ms · resolver in 242ms · 3 queries · 3 servers
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

Every format but `tree`, `ascii` and `emoji` is written once, at the end, so
there is nothing for a watch to change; all of them refuse it, as they refuse
`--live`.

## Drawing a walk again

`--format json` is also a way to keep a walk. `--from` reads one back and draws
it in whichever format was asked for, as though it had just been made, without
asking any server anything — so a walk made from a machine nobody else can
reach can be drawn, explained and checked somewhere else:

```
ssh far-away dnstree --dnssec --format json www.example.com > walk.json
dnstree --from walk.json --explain
dnstree --from walk.json --format mermaid
dnstree --from - --expect secure < walk.json
```

It takes no name, since the file says what was asked, and refuses the flags
that shape a walk being made — `--dnssec`, `--qmin`, a transport, a budget —
since none of them can change one that is over. `--expect` and the exit
codes read the saved walk as they would a new one, and a signature's time left
is read against when the walk was made rather than against the clock. It cannot
be drawn live, watched or held against the last walk with `--diff`: none of
those is about a walk that is over. A document of another `schema_version` is
refused rather than guessed at.

`--against` holds the walk against one saved the same way, and says what
differs, as `--diff` does — the answer, its TTL, the zone cuts, their
nameservers and the chain of trust over them. The walk drawn can be one read
with `--from`, which compares two walks made before and after a change, or from
two places, or one made now:

```
$ dnstree --from after.json --against before.json
...
✔ answered in 855ms · resolver in 373ms · 3 queries · 3 servers

· nothing differs from the walk of www.example.com. A in before.json, made within a minute of this one
```

The file is read as the walk before the one drawn, and the first line says how
far apart the two were made. Two walks of different questions are refused, and
nothing is written to the disk. Different is not wrong: a name served from
many places answers each of them in its own way. It takes the place of
`--diff`, and cannot be set in the file of defaults.

## Numbers for a monitoring system

`--format openmetrics` writes the walk as numbers in the
[OpenMetrics](https://prometheus.io/docs/specs/om/open_metrics_spec/) text
format, each labelled with the question: how it ended, how long it and each hop
on the path took, how many queries failed, the chain of trust, the time left on
the first signature to run out, what `--check-ds` found, which nameservers
`--check-axfr` and `--check-recursion` found open, who `--caa` found free to
issue, the TTL the zone gives the answer, and how long each resolver took,
whether it agreed and the TTL it handed out. Only gauges are used, so the older
Prometheus text format reads it too. A family the walk has nothing to say about
is left out rather than written as zero: a walk without `--dnssec` says nothing
about trust.

It is written once, so the repeating is cron's: written into the directory of
node_exporter's
[textfile collector](https://github.com/prometheus/node_exporter#textfile-collector),
it reaches Prometheus with the rest of the machine's metrics.

```
*/5 * * * * dnstree --dnssec --format openmetrics www.example.com > /var/lib/node_exporter/example.prom.$$ && mv /var/lib/node_exporter/example.prom.$$ /var/lib/node_exporter/example.prom
```

The rename keeps the collector from reading a file half written. The exit code
is not in the output, since the walk's own numbers say the same: `dnstree_result`
with `kind` of `none` or `filtered` is exit 2, and `dnstree_dnssec` with
`state="bogus"` is exit 3, which outranks both. A hop is labelled with the
server that answered it, so a walk that picks another nameserver of a zone next
time starts a series of its own rather than moving the old one.

<details>
<summary>What the walk to www.example.com writes</summary>

```
# TYPE dnstree_result gauge
# HELP dnstree_result how the walk ended, one of answer, cname, nodata, nxdomain, filtered or none
dnstree_result{name="www.example.com.",type="A",kind="answer"} 1
dnstree_result{name="www.example.com.",type="A",kind="cname"} 0
dnstree_result{name="www.example.com.",type="A",kind="nodata"} 0
dnstree_result{name="www.example.com.",type="A",kind="nxdomain"} 0
dnstree_result{name="www.example.com.",type="A",kind="filtered"} 0
dnstree_result{name="www.example.com.",type="A",kind="none"} 0
# TYPE dnstree_walk_seconds gauge
# UNIT dnstree_walk_seconds seconds
# HELP dnstree_walk_seconds how long the walk took
dnstree_walk_seconds{name="www.example.com.",type="A"} 1.9746477919999998
# TYPE dnstree_queries gauge
# HELP dnstree_queries the queries the walk sent
dnstree_queries{name="www.example.com.",type="A"} 6
# TYPE dnstree_failed_queries gauge
# HELP dnstree_failed_queries the queries that timed out, failed or reached a lame server
dnstree_failed_queries{name="www.example.com.",type="A"} 0
# TYPE dnstree_hop_seconds gauge
# UNIT dnstree_hop_seconds seconds
# HELP dnstree_hop_seconds how long each query on the path took, a timeout included
dnstree_hop_seconds{name="www.example.com.",type="A",zone=".",server="a.root-servers.net.",address="198.41.0.4",asked="www.example.com."} 0.245787625
dnstree_hop_seconds{name="www.example.com.",type="A",zone="com.",server="l.gtld-servers.net.",address="192.41.162.30",asked="www.example.com."} 0.244679917
dnstree_hop_seconds{name="www.example.com.",type="A",zone="example.com.",server="hera.ns.cloudflare.com.",address="108.162.192.162",asked="www.example.com."} 0.232406958
# TYPE dnstree_dnssec gauge
# HELP dnstree_dnssec how far the chain of trust got, one of secure, insecure, bogus or indeterminate
dnstree_dnssec{name="www.example.com.",type="A",state="secure"} 1
dnstree_dnssec{name="www.example.com.",type="A",state="insecure"} 0
dnstree_dnssec{name="www.example.com.",type="A",state="bogus"} 0
dnstree_dnssec{name="www.example.com.",type="A",state="indeterminate"} 0
# TYPE dnstree_signature_left_seconds gauge
# UNIT dnstree_signature_left_seconds seconds
# HELP dnstree_signature_left_seconds how long the first signature to run out had left when the walk was made
dnstree_signature_left_seconds{name="www.example.com.",type="A"} 90001.49201
# TYPE dnstree_answer_ttl_seconds gauge
# UNIT dnstree_answer_ttl_seconds seconds
# HELP dnstree_answer_ttl_seconds the TTL the zone gives the answer
dnstree_answer_ttl_seconds{name="www.example.com.",type="A"} 300
# TYPE dnstree_resolver_seconds gauge
# UNIT dnstree_resolver_seconds seconds
# HELP dnstree_resolver_seconds how long each recursive server took to answer the same question
dnstree_resolver_seconds{name="www.example.com.",type="A",resolver="8.8.8.8"} 0.244470625
# TYPE dnstree_resolver_agrees gauge
# HELP dnstree_resolver_agrees whether each recursive server answered what the walk found
dnstree_resolver_agrees{name="www.example.com.",type="A",resolver="8.8.8.8"} 1
# TYPE dnstree_resolver_ttl_seconds gauge
# UNIT dnstree_resolver_ttl_seconds seconds
# HELP dnstree_resolver_ttl_seconds the TTL each recursive server handed its answer out with
dnstree_resolver_ttl_seconds{name="www.example.com.",type="A",resolver="8.8.8.8"} 300
# TYPE dnstree_warnings gauge
# HELP dnstree_warnings what the walk could not do
dnstree_warnings{name="www.example.com.",type="A"} 0
# EOF
```

</details>
