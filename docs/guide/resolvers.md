# Resolvers

Holding the walk against the recursive resolvers people actually use.

- [Against your resolver](#against-your-resolver)
- [When a resolver answers SERVFAIL](#when-a-resolver-answers-servfail)
- [Asking from several places at once](#asking-from-several-places-at-once)
- [Keeping an answer longer than the zone allows](#keeping-an-answer-longer-than-the-zone-allows)
- [Asking from somewhere else](#asking-from-somewhere-else)
- [Whether a resolver can be used encrypted](#whether-a-resolver-can-be-used-encrypted)
- [How a resolver behaves](#how-a-resolver-behaves)

## Against your resolver

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

## When a resolver answers SERVFAIL

A SERVFAIL says something went wrong and nothing about what. When a resolver
answers one where the walk found an answer, it is asked once more, straight
away, with checking disabled
([RFC 4035](https://www.rfc-editor.org/rfc/rfc4035)), and the line under the
tree says what the failure most likely came of:

```
$ dnstree --resolver 1.1.1.1 --explain dnssec-failed.org A
...
servfail: 1.1.1.1 answers SERVFAIL where the walk found 96.99.227.255: with checking disabled it answers, so it fails validation; --dnssec checks the chain the walk took (it says: DNSKEY Missing (9): no SEP matching the DS found for dnssec-failed.org.)
✔ answered in 1.4s · resolver in 488ms (SERVFAIL) · 6 queries · 5 servers

· dnssec-failed.org. A is 96.99.227.255, answered by dns105.comcast.net. for dnssec-failed.org.
· a cache may hold this answer for 5 minutes, and the delegation to dnssec-failed.org. for 1 hour
· 1.1.1.1 answers SERVFAIL, and answers once asked with checking disabled, so it fails validation; the walk did not check the chain, which --dnssec does (it says: DNSKEY Missing (9): no SEP matching the DS found for dnssec-failed.org.)
```

With `--dnssec` the walk checks the chain too, and the line says whose problem
it is:

```
$ dnstree --resolver 1.1.1.1 --dnssec dnssec-failed.org A
...
servfail: 1.1.1.1 answers SERVFAIL where the walk found 96.99.227.255: it fails validation as the walk does, so the zone's chain of trust is what to fix (it says: DNSKEY Missing (9): no SEP matching the DS found for dnssec-failed.org.)
✘ bogus in 4.5s · resolver in 232ms (SERVFAIL) · 12 queries · 5 servers
```

| The line says | When |
| --- | --- |
| fails validation as the walk does | it answers with checking disabled, and the walk found the chain broken: the zone is what to fix |
| fails validation | it answers with checking disabled, or its extended error says validation failed, where the walk found the chain intact: look at the resolver's clock, its trust anchor, or an algorithm it does not know |
| serving a failure it cached | it still fails, and its extended error says the failure is cached (code 13) |
| could not get an answer the walk got | it still fails with checking disabled and says nothing of DNSSEC: a firewall, a nameserver it cannot reach, one that answers only some networks |

> [!NOTE]
> Every reading is a suggestion. A cached failure and a failing network look
> much alike from outside, and the second question can land on a fresh cache
> or another machine behind the same address. A resolver that ignores checking
> disabled fails twice; its extended error is then all that tells validation
> apart, and the line says it ignored the bit.

With several `--resolver`s each one gets its own line, which shows quickly
whether one resolver fails or all of them do. `--format json` carries the second
answer as `unchecked` and the reading as `failed`, and `--format openmetrics`
as `dnstree_resolver_failed`. A resolver that answers while the walk finds the
chain broken is the other way round — it does not validate — and is not read
here.

## Asking from several places at once

Repeat `--resolver` and the question goes to all of them at the same moment.
Two resolvers that answer differently are two views of one name, and which of
them somebody gets depends on nothing but which resolver they happen to use:

```
$ dnstree --resolver 1.1.1.1 --resolver 8.8.8.8 --resolver 9.9.9.9 --explain akamai.com A
...
differs: 1.1.1.1 answers 2.19.176.208, 2.19.176.211, the walk found 2.18.27.18, 2.18.27.35
differs: 9.9.9.9 answers 2.16.145.4, 2.16.145.8, the walk found 2.18.27.18, 2.18.27.35
✔ answered in 1.4s · resolvers in 282ms-312ms (2 of 3 differ) · 6 queries · 5 servers

· akamai.com. A is 2.18.27.18 and 2.18.27.35, answered by a5-66.akam.net. for akamai.com.
· a cache may hold this answer for 20 seconds, and the delegation to akamai.com. for 2 days
· 1.1.1.1 and 9.9.9.9 answered this question differently, which a name whose answer is tailored to where it is asked from does honestly, and nothing else should
```

Each one that disagreed is named on a line of its own, since two resolvers can
disagree with the walk for two different reasons. The summary says how far apart
they were and how many of them differed; where they all agree it says only the
range, because agreement is what the reader is expecting.

What each of them has left on its copy is read too, which is what says whether
an answer has reached everybody yet: a resolver that had to go and fetch the
answer hands back the zone's lifetime entire, and one still serving an older
answer says how long it will go on doing so.

> [!TIP]
> This pairs with `--subnet`, which asks every one of them the question as
> though it came from somebody else's network. Between them they are the two
> halves of "does this name look the same from where my users are".

The origin AS lookups go to the first `--resolver` named: they need somewhere to
ask rather than a poll. There is deliberately no shorthand for "the public
resolvers" — that would put a list of somebody else's addresses in the binary
and send the name being looked up to all of them. A set worth having every day
belongs in the [file of defaults](configuring.md#defaults), which may carry a `resolver` line for each.

## Keeping an answer longer than the zone allows

The TTL a resolver hands its answer out with is read against the one the zone
gives it. A resolver that raises short TTLs to a floor of its own is named on a
line under the tree, because a change the zone means to take effect in a second
takes as long as that floor for everybody using it:

```
$ dnstree --resolver 94.140.14.14 --explain news.ycombinator.com A
...
ttl: 94.140.14.14 keeps this with ttl 60, the zone gives 1
✔ answered in 741ms · resolver in 250ms · 3 queries · 3 servers

· news.ycombinator.com. A is 209.216.230.207, answered by ns-225.awsdns-28.com. for ycombinator.com.
· a cache may hold this answer for 1 second, and the delegation to ycombinator.com. for 2 days
· 94.140.14.14 keeps this for 1 minute where the zone allows 1 second, so a change to it takes that long to reach the clients using it
```

An answer that differs from the walk's, that no server of the zone gave it, and
that carries 30 seconds or less on a name the zone keeps for longer, looks
stale: 30 seconds is what a resolver serving past an answer's life hands out
([RFC 8767](https://www.rfc-editor.org/rfc/rfc8767)). It is said as a look, not
a finding — the number is a suggestion, not a rule — and with `--all` an
answer any of the zone's servers gave the walk is not stale, only tailored.
`--format openmetrics` carries both TTLs, `dnstree_answer_ttl_seconds` and
`dnstree_resolver_ttl_seconds`, for a monitoring system to hold one against
the other.

## Asking from somewhere else

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

## Whether a resolver can be used encrypted

A resolver handed out by the network is a bare address, and a bare address
speaks plain DNS: every name asked of it crosses the network readable, and
changeable, by anyone on the way. `--ddr` asks each resolver the question is
timed against whether it has an encrypted version too (RFC 9462), and draws
what it offers under the tree:

```
$ dnstree --ddr --resolver 1.1.1.1 --resolver 8.8.8.8 --resolver 9.9.9.9 --explain www.isc.org
...
ddr: 1.1.1.1 offers doh at https://one.one.one.one:443/dns-query{?dns}, dot at one.one.one.one:853 (not verified)
ddr: 8.8.8.8 offers dot at dns.google, doh at https://dns.google/dns-query{?dns} (not verified)
ddr: 9.9.9.9 offers doh at https://dns.quad9.net/dns-query{?dns}, dot at dns.quad9.net, doq at dns.quad9.net (not verified)
✔ answered in 1.1s · resolvers in 348ms-348ms · 3 queries · 3 servers
...
· 1.1.1.1 says it can also be reached encrypted, over doh and dot at one.one.one.one.; trust it only once the certificate there names 1.1.1.1, which --ddr does not check
```

It is one query per resolver, for `_dns.resolver.arpa`, and it only asks: it
does not connect to what is offered. A client is meant to use an offer only once
the certificate it finds there names the plain resolver's own address, since
otherwise whoever answered the plain question could point it anywhere. That
check is not made here, which is why every offer is marked as not verified.
A resolver that designates nothing says so, and one that cannot be asked says
why. Without `--resolver` the question goes to the host's own resolver;
`--no-compare` leaves nothing to ask.

## How a resolver behaves

From outside, most resolvers look alike: you ask, you get an answer. A few
habits set them apart where it matters. One that does not validate DNSSEC lets
a forged answer for a signed name through as though it were real. One that
rewrites NXDOMAIN answers a name that does not exist with the address of a page
of its own, which breaks whatever relies on being told a name is not there. One
that sends ECS tells the servers it asks which network you are on, and one that
does not minimise its queries shows the root and the top-level domains every
name you look up. `--check-resolver` puts questions whose right answers are
known to each resolver the question is timed against, and says under the tree
what each one was seen to do:

```
$ dnstree --check-resolver --resolver 1.1.1.1 --resolver 8.8.8.8 --resolver 4.2.2.2 --explain www.isc.org
...
resolver: 1.1.1.1 validates DNSSEC and leaves NXDOMAIN alone
resolver: 1.1.1.1 sends ECS (/24) to akamai but not google and minimises queries
resolver: 8.8.8.8 validates DNSSEC and leaves NXDOMAIN alone
resolver: 8.8.8.8 sends ECS (/24) to google and akamai and minimises queries
resolver: 4.2.2.2 does not validate DNSSEC and leaves NXDOMAIN alone
resolver: 4.2.2.2 sends no ECS to google or akamai and minimises queries
✔ answered in 920ms · resolvers in 317ms-399ms · 3 queries · 3 servers
...
· 1.1.1.1 sends ECS: akamai's servers were told the /24 the question came from, so the zones it sends it to learn which network its clients are on (RFC 7871)
· 8.8.8.8 sends ECS: google's and akamai's servers were told the /24 the question came from, so the zones it sends it to learn which network its clients are on (RFC 7871)
· 4.2.2.2 does not validate DNSSEC: it answered dnssec-failed.org, whose chain of trust is broken on purpose, so a forged answer for a signed name reaches whoever uses it as though it were real
```

- **Validation** rests on `dnssec-failed.org`, a zone Comcast keeps broken on
  purpose. A resolver that answers it SERVFAIL, and answers once told not to
  check (the CD bit), refused it for its signatures: it validates. One that
  answers it outright does not, unless it marks the root's SOA authentic (the
  AD bit), in which case the zone is likelier to have been fixed than the
  resolver to validate everything but it, and the line says it cannot tell.
- **NXDOMAIN rewriting** rests on a name made up for the run under `com.`. An
  NXDOMAIN is the truth; an address is a rewrite, and the line names it.
- **ECS** ([RFC 7871](https://www.rfc-editor.org/rfc/rfc7871)) rests on two
  names whose servers report what reached them: `o-o.myaddr.l.google.com` and
  `whoami.ds.akahelp.net`. A resolver chooses for each zone whether to send
  a subnet, so the line names the zones that were sent one and those that
  were not, and a "no" says nothing of any other zone. Only the prefix length
  is shown: both answers are cached for under a minute, and the address in
  one may be another client's.
- **QNAME minimisation** ([RFC 9156](https://www.rfc-editor.org/rfc/rfc9156))
  rests on `qnamemintest.internet.nl`, whose servers say in words whether the
  name reached them a label at a time.

Whatever the answers leave open is said as "may or may not", never guessed:
a resolver that forwards to another, or treats these names specially, is
something the questions cannot see past. It costs up to seven queries per
resolver, and sets no exit code: a resolver is not the name being asked about.

> [!NOTE]
> Every check depends on a zone somebody else runs. Should one of them be
> fixed, change its answers or go away, its check reads as "may or may not"
> rather than as a wrong answer.
