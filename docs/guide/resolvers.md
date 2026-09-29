# Resolvers

Holding the walk against the recursive resolvers people actually use.

- [Against your resolver](#against-your-resolver)
- [Asking from several places at once](#asking-from-several-places-at-once)
- [Asking from somewhere else](#asking-from-somewhere-else)
- [Whether a resolver can be used encrypted](#whether-a-resolver-can-be-used-encrypted)

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
