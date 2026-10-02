# Checking a zone

The questions a walk can put to a zone beyond the one it was given, and what a
server says about its own answer.

- [Whether the parent and the child agree](#whether-the-parent-and-the-child-agree)
- [Whether they all have the same zone](#whether-they-all-have-the-same-zone)
- [What they give a stranger](#what-they-give-a-stranger)
- [Who may issue certificates for it](#who-may-issue-certificates-for-it)
- [What a server said about its answer](#what-a-server-said-about-its-answer)
- [Which machine answered](#which-machine-answered)
- [Which servers support DNS cookies](#which-servers-support-dns-cookies)
- [Asking only what each zone needs](#asking-only-what-each-zone-needs)
- [Whether it still answers with a server down](#whether-it-still-answers-with-a-server-down)
- [How much room an answer had](#how-much-room-an-answer-had)

## Whether the parent and the child agree

The delegation a walk follows is the parent's word for who serves the zone. The
zone keeps its own NS RRset, and nothing above it ever reads that one, so the
two drift apart quietly: a nameserver retired in the zone and left in the
registry answers nothing, and one added to the zone and never registered is
never asked. `--check-ns` puts the question to the zone that answered and holds
the two lists against each other:

```
$ dnstree --check-ns --no-asn www.example.com A
...
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  222ms  NOERROR  AA
│   │   │   ├── www.example.com. 300 A 172.66.147.243
│   │   │   ├── www.example.com. 300 A 104.20.23.154
│   │   │   └── hera.ns.cloudflare.com. 108.162.192.162  224ms  NOERROR  AA  (parent/child NS check)
...
✔ answered in 936ms · resolver in 245ms · 4 queries · 3 servers
```

The check rides in as a hop of its own, marked for what it is, so the query it
cost is visible in the tree rather than hidden in the count. Two lists that
match are worth no room and get none. Where they differ, the walk says so above
the summary, in whichever direction it found:

> test. delegates to ns3.test., which the zone itself does not list

> test. lists ns4.test., which the delegation does not carry

Neither is fatal — the name still resolves, which is exactly why nobody notices
— and both are a fault to take to whoever holds the other half. A zone that
answers the question with no NS records of its own is reported too, since a zone
that cannot name its own nameservers is a stranger thing than a list that has
drifted.

It costs one query, asked of the server that answered the question, and it is
off unless asked for.

The zone's own NS set carries a TTL of its own, too, and it is rarely the
parent's: the parent's is often the registry's to choose. Resolvers differ over
whose copy they keep once they have seen both, so a change of nameservers takes
the longer of the two to reach everybody. `--explain` says so where they differ:

```
$ dnstree --check-ns --explain --no-asn www.example.com A
...
✔ answered in 384ms · resolver in 21ms · 4 queries · 3 servers

...
· the parent hands out the nameservers of example.com. for 2 days and the zone gives its own for 1 day, so a change of nameservers takes up to 2 days to reach every resolver
```

## Whether they all have the same zone

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

## What they give a stranger

Two old mistakes let a zone's nameservers give anybody more than answers about
the zone: handing over the whole zone, which lists every name in it, and looking
up other people's names, which makes an open resolver somebody can point at a
victim. `--check-axfr` asks every nameserver of the zone the walk ends in for a
zone transfer, and `--check-recursion` asks each of them to look up a name
outside its zones:

```
$ dnstree --check-axfr --check-recursion --explain --no-asn --no-compare zonetransfer.me
...
│   │   └── nsztm1.digi.ninja. 81.4.108.41  310ms  NOERROR  AA  ede Prohibited (18)
│   │       ├── zonetransfer.me. 7200 A 5.196.105.14
│   │       ├── nsztm1.digi.ninja. 81.4.108.41  514ms  NOERROR  AA  axfr open
│   │       └── nsztm1.digi.ninja. 81.4.108.41  248ms  REFUSED  recursion closed
...
· zone transfers of zonetransfer.me. are open to anyone at nsztm1.digi.ninja., which lists every name in the zone to whoever asks; allow them only to the zone's own secondaries
· no nameserver of zonetransfer.me. looked up another name for a stranger
```

`zonetransfer.me` is left open on purpose, as a demonstration. A zone that keeps
both to itself says so once for each check:

```
$ dnstree --check-axfr --check-recursion --explain --no-asn --no-compare www.isc.org
...
│   │   ├── ns1.isc.org. 149.20.2.26  478ms  NOERROR  AA
│   │   │   ├── www.isc.org. 300 A 151.101.131.42
...
│   │   │   ├── ns1.isc.org. 149.20.2.26  736ms  REFUSED  axfr closed
│   │   │   ├── ns1.isc.org. 149.20.2.26  367ms  REFUSED  recursion closed
...
· no nameserver of isc.org. handed the zone to a stranger
· no nameserver of isc.org. looked up another name for a stranger
```

Only the start of a transfer is read, and nothing of the zone is kept or drawn.
A transfer needs TCP: over `--dot` it is asked over TLS (RFC 9103), and `--doh`
cannot ask it at all. Recursion is judged by what comes back, the root's NS set
from a server that does not serve the root, rather than by the flag that says a
server recurses, which plenty of servers set without doing it. A server that
takes the connection and resets it once the transfer is asked for, the way
Route 53 refuses one, is `closed`; one that cannot be reached at all is
`unchecked`, never `closed`.

Each costs a query per nameserver, is off unless asked for, and leaves the exit
code alone. A refused
transfer still lands in the server's logs, so these are for zones you run or
have been asked to check. The root is never asked: its servers hand out the
root zone on purpose (RFC 8806). Like `--serial`, only the nameservers the walk
found an address for are asked. `--format json` carries each check as a `probe`
on its hop, and `--format openmetrics` as `dnstree_open`.

## Who may issue certificates for it

A CAA record (RFC 8659) says which certificate authorities may issue for a
name, and every public authority checks it before issuing. It does not only
look at the name: where the name has no set, it asks the name above, and so on
short of the root, and goes by the first set it finds. That is why a renewal
refused because of CAA is hard to explain with `dig`: the set that decided it is
often one somebody added at the top of the domain years ago. `--caa` makes the
same climb, asking each name of the zone the walk found it in, and says under
the tree which set decided and what it allows:

```
$ dnstree --caa --dnssec --explain --no-asn --no-compare www.isc.org
...
│   │   ├── ns1.isc.org. 149.20.2.26  361ms  1180 of 1232 bytes  NOERROR  AA DO  [secure ECDSAP256SHA256]
│   │   │   ├── www.isc.org. 300 A 151.101.195.42
...
│   │   │   ├── ns1.isc.org. 149.20.2.26  362ms  NOERROR  AA DO  no data  [secure]  (CAA of www.isc.org.)
│   │   │   └── ns1.isc.org. 149.20.2.26  456ms  1181 of 1232 bytes  NOERROR  AA DO  [secure ECDSAP256SHA256]  (CAA of isc.org.)
│   │   │       ├── isc.org. 7200 CAA 0 issuewild "sectigo.com"
│   │   │       ├── isc.org. 7200 CAA 0 issuewild "certainly.com"
│   │   │       ├── isc.org. 7200 CAA 0 iodef "mailto:hostmaster@isc.org"
...
caa: none at www.isc.org.; isc.org. decides it [secure ECDSAP256SHA256]
caa: may issue: digicert.com, sectigo.com, certainly.com, pki.goog, globalsign.com, letsencrypt.org, comodoca.com; wildcards: sectigo.com, certainly.com, usertrust.com, comodoca.com, globalsign.com, trust-provider.com; reports to mailto:hostmaster@isc.org
...
· the CAA set at isc.org. lets only digicert.com, sectigo.com, certainly.com, pki.goog, globalsign.com, letsencrypt.org and comodoca.com issue for www.isc.org., and only sectigo.com, certainly.com, usertrust.com, comodoca.com, globalsign.com and trust-provider.com issue wildcards below it
```

The rules are the authorities' own. A set with no `issue` property restricts
nobody, and one with no `issuewild` leaves wildcards to `issue`. An `issue`
naming no domain, `";"`, lets nobody issue. An alias is followed for the
lookup it was met on, and the climb goes on from the alias rather than from its
target. A critical property no authority knows makes every authority refuse. A
lookup that fails, a timeout or a `SERVFAIL` rather than an empty answer, stops
the climb: in a zone `--dnssec` found a chain of trust behind, every authority
has to refuse, but elsewhere one that retried may take the failure as leave to
issue (the CA/Browser Forum's Baseline Requirements, 3.2.2.8), so the climb is
left undecided. A climb cut short by dnstree's own budget is undecided too.
Each of these is said in a warning. Parameters
such as `accounturi` and `validationmethods` (RFC 8657) are drawn with the
record, but not read: authorities differ on them.

With `--dnssec` the verdict is the weakest on the way up. A name with no set has
to prove it, the way any NODATA does, since dropping a set is all it takes to
lift a restriction, and a set or a denial that does not verify is a broken
chain of trust like any other, which exits 3. Otherwise the exit code is left
alone, unless `--expect caa:` asks for an authority by name
([Asking rather than reading](scripting.md#asking-rather-than-reading)). It
costs a query for each name asked, or a walk for one that is an alias.
`--format json` carries it as `caa`, and `--format openmetrics` as
`dnstree_caa`.

## What a server said about its answer

An rcode says what happened. The extended errors of RFC 8914 say why, and they
are the only thing in a reply that tells an answer somebody kept back from an
answer that was never there. Drawn against the test servers, whose last one
refuses with a reason:

```
$ dnstree blocked.example.com A
. (root)
└── a.root-servers.net. 192.0.2.1  690µs  NOERROR  referral → com.
    └── ns.com. 192.0.2.2  430µs  NOERROR  referral → example.com.
        └── ns1.example.com. 192.0.2.53  370µs  REFUSED  filtered  ede Prohibited (18): not from this network
✘ filtered in 2ms · 3 queries · 3 servers
```

Without the code on the end that hop reads as a lame server — one with no
business serving the zone, which is a fault to take to whoever runs it. With it,
the server is working exactly as somebody configured it, and the fault, if there
is one, is not the zone's. The same goes for an NXDOMAIN carrying `Blocked (15)`: the
name is not missing, it is being denied, and a walk that ends that way reports
`filtered` rather than `no answer`.

A code that claims nothing of the sort — a stale answer served from a cache,
say — is carried on the hop and changes nothing else. Every code reaches
`--format json` as `extended`, with a `withheld` flag on the ones that mean
somebody decided the answer, so a script need not carry the list itself.

Exit code 2 covers a filtered walk, as it does any other walk that ends without
an answer.

## Which machine answered

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

## Which servers support DNS cookies

Most DNS travels over UDP, where anyone can send a packet claiming to be from
anywhere. A DNS cookie (RFC 7873) is the cheap fix: the client sends a random
value, the server answers with it and a value of its own, and an answer that
does not carry the client's value is not an answer to that client. `--cookie`
sends one to every server and says on each hop how it answered:

```
$ dnstree --cookie --no-asn --no-compare --explain www.isc.org A
. (root)
├── a.root-servers.net. 198.41.0.4  247ms  NOERROR  referral → org.  no cookie
│   ├── a2.org.afilias-nst.info. 199.249.112.1  233ms  NOERROR  referral → isc.org.  no cookie
│   │   ├── ns1.isc.org. 149.20.2.26  366ms  NOERROR  AA  cookie
│   │   │   ├── www.isc.org. 300 A 151.101.3.42
...
✔ answered in 849ms · 3 queries · 3 servers

· www.isc.org. A is 151.101.131.42, 151.101.195.42, 151.101.3.42 and 1 more, answered by ns1.isc.org. for isc.org.
· a cache may hold this answer for 5 minutes, and the delegation to isc.org. for 1 hour
· 2 servers answered without a dns cookie, which is allowed and leaves nothing to tell a forged answer from a real one: a.root-servers.net. and a2.org.afilias-nst.info.
```

| On the hop | What the server did |
| --- | --- |
| `cookie` | sent our client cookie back with one of its own |
| `no cookie` | sent none back, which is allowed |
| `cookie not ours` | sent back a client cookie other than the one sent: broken, or the answer is not the server's, and the walk warns |
| `cookie malformed` | sent a cookie of a length no cookie has |
| `cookie rejected` | answered `BADCOOKIE` even to the cookie it handed out itself |

The walk behaves as a client that supports cookies: a server is sent back the
cookie it handed out, and one that answers `BADCOOKIE` is asked again with the
cookie that came with it, once. Each server gets a client cookie of its own,
made fresh for the run, so no two of them can follow the walk between them
(RFC 9018). Cookies go on queries over UDP and TCP; over DoT and DoH the
handshake already proves the address, so nothing is sent and nothing is said.
A cookie never changes the exit code.

## Asking only what each zone needs

A walk asks every server the whole name, the way `dig +trace` does. Resolvers
stopped doing that years ago: they ask each zone for one label more than it
already has, so the root hears about `com.` and never about `www.example.com.`
(RFC 9156). `--qmin` walks that way, and every hop that asked less than the
whole name says what it asked instead:

```
$ dnstree --qmin --no-asn www.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  164ms  NOERROR  referral → com.  (minimised to com.)
│   ├── l.gtld-servers.net. 192.41.162.30  221ms  NOERROR  referral → example.com.  (minimised to example.com.)
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  13ms  NOERROR  AA
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
✔ answered in 401ms · resolver in 12ms · 3 queries · 3 servers
```

Below a zone cut it goes on a label at a time — an empty name on the way answers
NODATA, and the walk asks one label further — so a name deep under its zone
costs a query for each label. The point of asking this way is what it finds: a
server that answers NXDOMAIN for a name only because nothing is at it yet, which
RFC 8020 reads as nothing being below it either. A resolver that minimises
stops there; one that does not never asks the question. `--qmin` asks the whole
name again when it meets one, the way resolvers fall back, and says under the
tree which server did it and for which name.

## Whether it still answers with a server down

Every zone has more than one nameserver so that it keeps answering when one of
them stops, but the only way to find out whether it does is to wait for that to
happen. `--without` walks as though it already had. It takes a nameserver's
name, an address or a prefix, as many times as needed. Every server inside it is
drawn and never asked, and the walk goes wherever it would have gone next:

```
$ dnstree --no-asn --without hera.ns.cloudflare.com www.example.com A
. (root)
├── a.root-servers.net. 198.41.0.4  247ms  NOERROR  referral → com.
│   ├── l.gtld-servers.net. 192.41.162.30  245ms  NOERROR  referral → example.com.
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  (not queried)  (left out by --without hera.ns.cloudflare.com.)
│   │   ├── hera.ns.cloudflare.com. 172.64.32.162  (not queried)  (left out by --without hera.ns.cloudflare.com.)
│   │   ├── hera.ns.cloudflare.com. 173.245.58.162  (not queried)  (left out by --without hera.ns.cloudflare.com.)
│   │   ├── hera.ns.cloudflare.com. 2606:4700:50::adf5:3aa2  (not queried)  (left out by --without hera.ns.cloudflare.com.)
│   │   ├── hera.ns.cloudflare.com. 2803:f800:50::6ca2:c0a2  (not queried)  (left out by --without hera.ns.cloudflare.com.)
│   │   ├── hera.ns.cloudflare.com. 2a06:98c1:50::ac40:20a2  (not queried)  (left out by --without hera.ns.cloudflare.com.)
│   │   ├── elliott.ns.cloudflare.com. 108.162.195.228  235ms  NOERROR  AA
│   │   │   ├── www.example.com. 300 A 104.20.23.154
│   │   │   └── www.example.com. 300 A 172.66.147.243
│   │   ├── elliott.ns.cloudflare.com. 162.159.44.228  (not queried)
│   │   ├── elliott.ns.cloudflare.com. 172.64.35.228  (not queried)
│   │   ├── elliott.ns.cloudflare.com. 2606:4700:58::a29f:2ce4  (not queried)
│   │   └── (and 2 more not queried)
│   ├── l.gtld-servers.net. 2001:500:d937::30  (not queried)
│   ├── j.gtld-servers.net. 192.48.79.30  (not queried)
│   ├── j.gtld-servers.net. 2001:502:7094::30  (not queried)
│   └── (and 22 more not queried)
├── a.root-servers.net. 2001:503:ba3e::2:30  (not queried)
├── b.root-servers.net. 170.247.170.2  (not queried)
├── b.root-servers.net. 2801:1b8:10::b  (not queried)
└── (and 22 more not queried)
✔ answered in 728ms · without hera.ns.cloudflare.com. · resolver in 243ms · 3 queries · 3 servers
```

Take the other one away as well and the line under the tree says so, and the
run exits 2:

```
✘ no answer in 494ms · without hera.ns.cloudflare.com., elliott.ns.cloudflare.com. · resolver in 235ms · 2 queries · 2 servers
```

The backup that is not one is what this finds. A second nameserver with
another provider is no help if the zone its own name lives in is served by the
first, and taking the first one's address away shows that. A prefix takes a
whole network away at once: `--without 192.0.2.0/24`.

The servers are left out of everything the walk asks, the `--serial` and
exposure checks included, and nothing else is asked any differently, so it is
safe to point at anybody's zone. The comparison with a resolver and the AS
lookups are not part of the walk and are left alone. A `--without` that matched
no server the walk came to is said under the tree, since a misspelled name
otherwise reads as a zone that survived the outage. `--diff` is refused beside
it, because the walk it remembers would be one with part of the DNS missing.
With `--expect answer` it is a check for CI.

It shows the path dnstree would take, which is not every path. A resolver that
has already learned which servers are slow keeps away from them, and dnstree
starts afresh every time. Leaving out a network by its AS is not there yet.

## How much room an answer had

Every hop records how big the answer was and how big it was allowed to be: the
bytes that arrived, against the EDNS0 buffer the query advertised — 512 for a
query that carried none, and nothing at all over TCP, DoT and DoH, where a
single answer is not bounded that way.

Nearly always that is worth no room on the line and gets none. A hop that has
all but filled its datagram is drawn, because it is the one thing in a walk
that is about to break and has not broken yet:

```
$ dnstree --dnssec --no-asn www.example.com A
. (root)  [secure RSASHA256/SHA256]
├── a.root-servers.net. 198.41.0.4  244ms  1175 of 1232 bytes  NOERROR  DO  referral → com.  [secure ECDSAP256SHA256/SHA256]
│   ├── a.root-servers.net. 198.41.0.4  718ms  NOERROR  AA DO  (truncated over udp; DNSKEY of .)
│   ├── l.gtld-servers.net. 192.41.162.30  242ms  NOERROR  DO  referral → example.com.  [secure ECDSAP256SHA256/SHA256]
...
```

That is the real root, answering a signed referral with 57 bytes to spare. One
more record in it — an address added, a key rolled — and the answer stops
fitting. Every resolver that asks then pays a second round trip to fetch it over
TCP, and the ones that cannot reach the server over TCP get no answer at all.
Nothing is wrong with it today, which is why nothing else reports it.

The hop below it is the same thing after it has happened: the keys of the root
did not fit, and `(truncated over udp)` is the second round trip being paid.

> [!NOTE]
> `--dnssec` is what makes the figure the one that matters. The same referral
> asked for without it comes back 335 bytes lighter, with room to spare, because
> none of the signatures are in it — and a resolver that validates does ask for
> them. `--explain` on a walk that did not says so, rather than leave the reader
> a margin that is not theirs.

Both sizes reach `--format json` as `size_bytes` and `limit_bytes`, with a
`tight` flag on the hops that have no room left, so a script need not carry the
margin itself.
