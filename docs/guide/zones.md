# Checking a zone

The questions a walk can put to a zone beyond the one it was given, and what a
server says about its own answer.

- [All of it at once](#all-of-it-at-once)
- [Whether the parent and the child agree](#whether-the-parent-and-the-child-agree)
- [Records that point where they may not](#records-that-point-where-they-may-not)
- [Whether they all have the same zone](#whether-they-all-have-the-same-zone)
- [What they give a stranger](#what-they-give-a-stranger)
- [How they handle EDNS](#how-they-handle-edns)
- [Who may issue certificates for it](#who-may-issue-certificates-for-it)
- [What a check of its mail costs](#what-a-check-of-its-mail-costs)
- [Whether its mail can be sent verified](#whether-its-mail-can-be-sent-verified)
- [Where a browser connects](#where-a-browser-connects)
- [Whether its registration is about to run out](#whether-its-registration-is-about-to-run-out)
- [How long a change takes to reach everyone](#how-long-a-change-takes-to-reach-everyone)
- [What a server said about its answer](#what-a-server-said-about-its-answer)
- [Which machine answered](#which-machine-answered)
- [Which servers support DNS cookies](#which-servers-support-dns-cookies)
- [Asking only what each zone needs](#asking-only-what-each-zone-needs)
- [Whether it still answers with a server down](#whether-it-still-answers-with-a-server-down)
- [Whether it will answer on new nameservers](#whether-it-will-answer-on-new-nameservers)
- [How much room an answer had](#how-much-room-an-answer-had)

## All of it at once

Most checks below have a flag of their own. `--check` turns on the ones that
grade a zone and ends the walk with one verdict on the zone it reached, a line
for each area:

```
$ dnstree --check --no-compare --expect check:clean example.com
...
check example.com.
  ✔ answer        example.com. A is 104.20.23.154 and 172.66.147.243, answered by elliott.ns.cloudflare.com. for example.com.
  ✔ delegation    the parent and example.com. agree on 2 nameservers
  ✔ consistency   every nameserver asked serves one copy of example.com., serial 2416374680 (2 nameservers, 12 addresses)
  ✔ dnssec        the chain of trust holds from the root to example.com., signed with ECDSAP256SHA256
  ⚠ servers       all 2 nameservers of example.com. are in AS13335, so one operator's outage takes the whole zone with it
  ✔ edns          every nameserver of example.com. that was asked passed the RFC 8906 edns tests
  · strangers     not asked; --check-axfr and --check-recursion probe the nameservers, which is for your own zone
  ✔ caa           no name from example.com. up has a CAA set, so any certificate authority may issue for it
  ✔ mail          the SPF policy of example.com. takes 0 of the 10 lookups a check is allowed
  ✔ registration  the registration of example.com. runs until 2027-08-13
1 to look at · 8 passed · 1 skipped
✔ answered in 9.2s · 161 queries · 64 servers
expected check:clean, got servers look
```

It is `--dnssec`, `--all`, `--check-ns`, `--check-ds`, `--serial`,
`--check-edns`, `--cookie`, `--caa`, `--spf`, `--mail` and `--rdap` in one,
with a budget of 512 queries unless `--max-queries` says otherwise. An area is
broken where the walk has no answer, or none to trust; worth a look where a
check warned, or where the zone is not signed; passed where it was checked and
nothing came up; and skipped where nothing checked it. Each line says the
worst of what the area found, with a count of the rest, which the warnings
above it and `--explain` spell out. The grades are read off what the flags
themselves say, so an area cannot pass while its flag warns.

The servers area is about the zone's own nameservers: a root or TLD server
short of room is somebody else's to fix. Zone transfers and recursion are
asked of the servers as a stranger would, which is for the zone's owner to
choose, so `strangers` is graded only when `--check-axfr` or
`--check-recursion` is named as well. A name that is an alias is graded at the
zone its target is in, which is where the checks run: `--check` on a name
pointed at a CDN grades the CDN's zone, so point it at the zone's own apex.

The exit code is the walk's own: a broken chain of trust is still 3.
`--expect check:ok` fails on anything broken, and `--expect check:clean` on
anything to look at as well, which is how a zone is held to its health in CI
([Asking rather than reading](scripting.md#asking-rather-than-reading)).
Tree, ascii, emoji, markdown and json draw the grades; `--format json` carries
them as `check`, and `--from` draws a saved one again without being asked.

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
│   │   ├── hera.ns.cloudflare.com. 108.162.192.162  214ms  NOERROR  AA
│   │   │   ├── www.example.com. 300 A 172.66.147.243
│   │   │   ├── www.example.com. 300 A 104.20.23.154
│   │   │   └── hera.ns.cloudflare.com. 108.162.192.162  217ms  NOERROR  AA  (parent/child NS check)
│   │   │       └── hera.ns.cloudflare.com. 108.162.192.162  212ms  NOERROR  AA  no data  (CSYNC of example.com.)
...
✔ answered in 1.1s · resolver in 229ms · 5 queries · 3 servers
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

It costs two queries, the NS set and the CSYNC below, asked of the server that
answered the question, and it is off unless asked for.

A nameserver named inside the zone it serves can only be reached through the
addresses its parent hands out with the referral, the glue. Glue is a copy of
what the zone says, made when the nameserver was registered, and nothing keeps
the two in step: a nameserver renumbered in the zone goes on being handed out at
its old address, and every resolver tries that first. `--check-ns` asks the zone
for the A and AAAA of each such nameserver too, together, under the NS check:

```
$ dnstree --check-ns --no-asn www.isc.org A
...
│   │   │   └── ns1.isc.org. 149.20.2.26  358ms  NOERROR  AA  (parent/child NS check)
│   │   │       ├── ns1.isc.org. 149.20.2.26  372ms  NOERROR  AA  (glue check: A of ns1.isc.org.)
│   │   │       ├── ns1.isc.org. 149.20.2.26  366ms  NOERROR  AA  (glue check: AAAA of ns1.isc.org.)
│   │   │       ├── ns1.isc.org. 149.20.2.26  366ms  NOERROR  AA  (glue check: A of ns2.isc.org.)
│   │   │       ├── ns1.isc.org. 149.20.2.26  360ms  NOERROR  AA  (glue check: AAAA of ns2.isc.org.)
│   │   │       ├── ns1.isc.org. 149.20.2.26  360ms  NOERROR  AA  (glue check: A of ns3.isc.org.)
│   │   │       ├── ns1.isc.org. 149.20.2.26  374ms  NOERROR  AA  (glue check: AAAA of ns3.isc.org.)
│   │   │       └── ns1.isc.org. 149.20.2.26  350ms  NOERROR  AA  no data  (CSYNC of isc.org.)
...
✔ answered in 2.2s · resolver in 237ms · 11 queries · 3 servers
```

The addresses are compared a family at a time, as sets, and agreeing costs no
room. Where they differ the walk says which way:

> test. hands out 192.0.2.53 for ns1.example.test., which example.test. itself gives as 198.51.100.53; have the registrar update the glue

> test. hands out no IPv6 address for ns1.example.test., which example.test. gives as 2001:db8::53; have the registrar add it to the glue

> test. hands out 2001:db8::53 for ns1.example.test., which example.test. itself does not give; have the registrar remove it from the glue

A nameserver named in some other zone gets no glue and is not the zone's to
give an address for, so it is left alone; one named inside with no glue at all
breaks the delegation, and is warned about where the referral is followed. What
the zone gave is in `--format json` as the delegation's `zone_addrs`. It costs
two queries for each nameserver named inside the zone.

The zone's own NS set carries a TTL of its own, too, and it is rarely the
parent's: the parent's is often the registry's to choose. Resolvers differ over
whose copy they keep once they have seen both, so a change of nameservers takes
the longer of the two to reach everybody. `--explain` says so where they differ:

```
$ dnstree --check-ns --explain --no-asn www.example.com A
...
✔ answered in 1.1s · resolver in 228ms · 5 queries · 3 servers

...
· the parent hands out the nameservers of example.com. for 2 days and the zone gives its own for 1 day, so a change of nameservers takes up to 2 days to reach every resolver
```

### What the zone asks its parent to copy

The zone can ask for the change itself. A CSYNC record at its apex (RFC 7477)
names what its parent should copy from it, the NS set, the A and AAAA of the
nameservers named inside it, or both, and registries that support it poll for
one. `--check-ns` asks for it beside the NS set, the line `(CSYNC of …)` under
the NS check above, and where the zone has one it says what a parent acting
on it would change in the delegation the walk was handed: a `csync:` line
with the record and whether a parent would act on it, then one line for each
nameserver or address it would add or remove. Few zones publish one yet, and
the example.com. above does not, so it draws nothing more than its `no data`.

A parent copies only a CSYNC the zone's keys signed, so it reads as unproven
unless the chain of trust reached the zone secure, and as unchecked without
`--dnssec`, with what it would change still listed. One that leaves the
`immediate` flag clear waits for whoever runs the parent to approve it; one
with `soaminimum` waits until the zone's serial reaches its own, which costs
one more query to compare. A warning says when a signed CSYNC cannot do its
job: its serial is ahead of the zone's, it asks for the addresses of a
nameserver the zone gives none for, or it names a type other than NS, A and
AAAA, which no parent copies. Whether this parent polls for a CSYNC at all is
not something a walk can see, and `--explain` says so. `--format json` carries
it as the delegation's `csync`, and `--format openmetrics` as `dnstree_csync`
and `dnstree_csync_changes`.

## Records that point where they may not

An alias stands in for another name almost anywhere, and the few places it may
not are the ones a forgiving resolver papers over and a strict one does not. A
walk is strict, so it runs into them as it goes, and says so above the summary
without asking anything more:

> test. delegates to ns1.example.test., which is an alias for host.example.test.; name the nameserver by its own name, since resolvers need not follow an alias to find one (RFC 2181 section 10.3)

> example.test. is an alias at the top of its zone, which hides the zone's SOA and NS from every resolver that asks (RFC 1034 section 3.6.2); serve the records there rather than an alias

> test. delegates to 192.0.2.53., which is an address written as a name, and nothing resolves it; name the nameserver instead (RFC 1035 section 3.3.11)

A nameserver named by an alias is found where the walk looks the name up, which
is only for one named outside the zone it serves; `--check-ns` asks the zone
about the ones named inside it. An alias at the top of a zone is only said of
the CNAME itself: a provider that lets one be written there and answers with
the addresses instead is answering correctly, and nothing on the wire shows it
was ever an alias. None of them is a failure, so none of them changes the
result or the exit code.

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

It costs a query per nameserver and is off unless asked for. A walk looks up
only as many of the nameservers named outside the zone as it needs to get an
answer, so the sweep looks up the rest itself, at a few queries each. It does
not need `--all`: the sweep is one cheap question to each of them, rather than
the whole resolution done over again.

`--all` sees the other half of the same thing, and needs no flag of its own to
say it. Where it has put the question itself to every nameserver of a zone, two
of them answering differently is worth a line:

> the nameservers of test. do not answer www.test. A alike: 192.0.2.10 at ns1.test., 192.0.2.99 at ns2.test.

Answers are held against each other as sets, so a nameserver rotating an RRset
between one question and the next is not a nameserver that disagrees. A real
difference is not by itself a fault — a zone served by something that answers by
where the question came from will do this honestly, and so will an RRset caught
halfway through a change — but nothing else in a trace says it at all. Where
one nameserver has several addresses, each is named with its address, since
the sites behind one name can disagree among themselves. The same goes for
`--serial`.

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
root zone on purpose (RFC 8806). Like `--serial`, they look up the nameservers
the walk did not need, and ask every one an address was found for. `--format json` carries each check as a `probe`
on its hop, and `--format openmetrics` as `dnstree_open`.

## How they handle EDNS

EDNS (RFC 6891) is the record in every query that carries the bigger buffer, the
DNSSEC flag, cookies and the rest. It was made to grow: a server has to answer
a version it does not know with BADVERS, and ignore an option or a flag it does
not know. Some servers, and many firewalls in front of them, drop those queries
or answer them wrongly instead, and since DNS Flag Day 2019 resolvers no longer
work around them. `--check-edns` asks every nameserver of the zone the walk ends
in for its SOA in the four shapes RFC 8906 tests: EDNS0 alone, version 1, option
100 and flag 0x40, the last two defined by nobody:

```
$ dnstree --check-edns --max-queries 120 --explain --no-asn --no-compare qq.com
...
│   │   │   ├── ns1.qq.com. 203.205.220.251  435ms  NOERROR  AA  edns0 ok
│   │   │   ├── ns1.qq.com. 203.205.220.251  444ms  BADVERS  AA  edns version 1 broken: answered anyway
│   │   │   ├── ns1.qq.com. 203.205.220.251  534ms  NOERROR  AA  edns option 100 ok
│   │   │   ├── ns1.qq.com. 203.205.220.251  455ms  NOERROR  AA  edns flag 0x40 ok
...
· ns1.qq.com. (203.205.220.251) did not answer EDNS version 1 with BADVERS and nothing else, which leaves a resolver that tries a newer version no way back; fix the server, or the firewall in front of it (RFC 8906)
```

A name's addresses are often different machines, and only some of them may be
at fault, so a finding names the address as well as the server. A zone whose
servers all pass says so once:

```
$ dnstree --check-edns --explain --no-asn --no-compare www.isc.org
...
│   │   │   ├── ns1.isc.org. 149.20.2.26  414ms  NOERROR  AA  edns0 ok
│   │   │   ├── ns1.isc.org. 149.20.2.26  391ms  BADVERS  edns version 1 ok
│   │   │   ├── ns1.isc.org. 149.20.2.26  386ms  NOERROR  AA  edns option 100 ok
│   │   │   ├── ns1.isc.org. 149.20.2.26  378ms  NOERROR  AA  edns flag 0x40 ok
...
· every nameserver of isc.org. that was asked passed the RFC 8906 edns tests
```

A broken test says what it got wrong: `no answer`, the wrong rcode
(`not BADVERS`, `not NOERROR`), `no opt record`, `opt not version 0`, `no soa`,
the option or flag `copied back`, or BADVERS `answered anyway`. Only a server
that passed EDNS0 alone is asked the other three. One that failed it would fail
them all for the same reason, and one that cannot be reached, refuses the zone
or answers without its SOA is `unchecked`, since that says nothing about EDNS. A
`no answer` comes only after the retries every query gets, but a lossy path can
still cost a test its reply. None of the queries is asked again without EDNS0, which is how
the walk itself gets past a server like that.

It costs up to four queries per nameserver address, so a zone with many
addresses needs a bigger `--max-queries`; a warning says when the budget ran
out. Like `--serial`, it looks up the nameservers the walk did not need. It is
off unless asked for and leaves the exit code alone. `--format json` carries
each test as `edns` on its hop, and `--format openmetrics` as `dnstree_edns_ok`.

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

## What a check of its mail costs

An SPF record (RFC 7208) says which servers may send mail as a domain, and a
receiving mail server checks it on every message. It rarely names servers
outright: most of it is `include`s of other domains' policies, which include
more in turn. To keep one check from turning into hundreds of queries, the RFC
allows it ten lookups over the whole tree, and two that find nothing; past
either, the check is a permerror, which many receivers treat as a failure. The
count usually creeps up in a provider's record, which the domain's owner never
touches. `--spf` draws the policy as the tree it really is, with the running
count on every term that costs a lookup:

```
$ dnstree --spf --explain --no-asn --no-compare github.com
...
spf: github.com. takes 10 of 10 lookups, asked of 8.8.8.8
├── 5 address ranges
├── include:spf.protection.outlook.com (lookup 1)
│   ├── 11 address ranges
│   └── -all
├── include:_netblocks.google.com (lookup 2)
...
├── include:_spf.salesforce.com (lookup 5)
│   ├── exists:%{i}._spf.mta.salesforce.com (lookup 6, depends on the sender)
│   └── -all
...
├── include:sendgrid.net (lookup 9)
│   ├── 11 address ranges
│   ├── include:ab.sendgrid.net (lookup 10)
│   │   ├── 4 address ranges
│   │   └── ~all
│   └── ~all
└── ~all
spf: ok, at the limit: one more lookup in any policy it includes is a permerror
...
· the SPF policy of github.com. takes all 10 lookups a check is allowed, so one more in any policy it includes makes every check a permerror
```

The lookups go to the first `--resolver`, or the host's own, which is where a
mail server asks them, and they are not in the tree of the walk. Which term a
check stops at depends on who is sending, so every term up to `all` is
followed, the way a sender that matches none of them is checked; what comes
after `all`, and a `redirect` beside one, is drawn as never reached. A term with
a macro in it, such as `%{i}`, and `ptr`, depend on the sender too: they are
counted and not looked up. The `ip4` and `ip6` ranges cost nothing and are
drawn as a count.

What fails a check is said on the term it fails at: the eleventh lookup, the
third that finds nothing, an `include` that loops back or names a domain with
no policy, two policies on one name, a term that does not parse, and a lookup
that fails, which is a temperror. `+all`, a final `?all`, and `ptr` are said
too, though a check survives them. The check spends a budget of
`--max-queries` apart from the walk's, and one cut short says its counts are a
floor. A policy of more than 512 terms is not read, and leaves the check
undecided. The exit code is left alone,
unless `--expect spf:ok` asks for a policy no check fails on
([Asking rather than reading](scripting.md#asking-rather-than-reading)).
`--format json` carries it as `spf`, and `--format openmetrics` as
`dnstree_spf_lookups` and `dnstree_spf`.

## Whether its mail can be sent verified

When a server sends mail to a domain, it looks up the domain's MX hosts and
switches to TLS with whichever it reaches, but by default that encryption is
optional and nobody checks the certificate: anyone in the way can strip it off.
DANE (RFC 7672) closes the gap with a TLSA record under `_25._tcp` of each MX
host, which a sender honours only where DNSSEC proves it. `--mail` looks the
path up the way such a sender does: the MX hosts by preference, the addresses of
each, and the TLSA set of each whose addresses are signed, then the MTA-STS,
TLS-RPT and DMARC records beside them:

```
$ dnstree --mail --dnssec --explain --no-asn --no-compare freebsd.org
...
│   │   │   ├── freebsd.org.  (TLSA of _25._tcp.mx1.freebsd.org. for mail)
│   │   │   │   ├── ns1.freebsd.org. 163.237.210.11  547ms  NOERROR  AA DO  [secure RSASHA256]
│   │   │   │   │   └── _25._tcp.mx1.freebsd.org. 3600 TLSA 3 1 1 0a7e2f469913ea64ca98af1f31bbbcaf51920d8df90d2972a9dc02bf7c37f404
...
│   │   │   ├── freebsd.org.  (TLSA of _25._tcp.mx66.freebsd.org. for mail)
│   │   │   │   ├── ns1.freebsd.org. 163.237.210.11  1.65s  NXDOMAIN  AA DO  [secure]  (truncated over udp)
...
mail: 2 MX hosts for freebsd.org. [secure RSASHA256]
mail:   10 mx1.freebsd.org. dane (1 TLSA record): a sender has to see a certificate that matches
mail:   30 mx66.freebsd.org. none: its zone proves there is no TLSA set
mail: no mta-sts; no tls-rpt; dmarc p=none
mail: dane covers 1 of 2 MX hosts
warning: DANE covers 1 of the 2 MX hosts of freebsd.org., so a sender may deliver to mx66.freebsd.org. unverified; publish TLSA for it
✔ answered in 10.6s · 14 queries · 3 servers
...
· DANE covers 1 of the 2 MX hosts of freebsd.org., so a sender may deliver to the others unverified
· the DMARC policy at _dmarc.freebsd.org. asks receivers to do nothing different with mail sent as freebsd.org. that neither SPF nor DKIM vouches for
```

Every lookup is a walk of its own, drawn in the tree as an aside, starting
from the deepest zone the run has already entered, so a provider's zone is
walked down to once. A host is `dane` where the zone signs a TLSA set with a
record a mail sender may use, a trust anchor or end entity one; `unusable`
where it signs only PKIX ones, which still makes a sender insist on TLS;
`none` where the zone proves there is no set; and `insecure` where its
addresses or its set are not signed, which DANE ignores. A host whose
addresses do not validate, or whose TLSA set fails to look up or validate, is
`failed`: every sender
that checks DANE treats the host as unreachable and holds the mail, which is an
outage rather than a weakness, and is said in a warning. So is an MX host left
uncovered while others are covered, and a TLSA set nothing signed. A host with
no address is `unreachable`, and is left out of the count; one written as an
address is `literal`. One whose addresses or set this build cannot check, for
an algorithm or a denial it does not know, is `indeterminate`, and so is one
the budget ran out before, which leaves the coverage line undecided; nothing is
claimed of either. Without `--dnssec` every set is listed as `unchecked`, and
nothing is claimed of it. An MX set that does not validate stops the check with
a warning, since a sender that validates holds all the mail.

A null MX (RFC 7505) says the domain takes no mail, and a domain with no MX set
is its own only host. An MX set that is not signed leaves DANE protecting each
host and not which hosts get the mail, and the coverage line says so. The
MTA-STS and TLS-RPT records count only where exactly one begins with their
version, as the RFCs say. A name with no DMARC record of its own goes by one
found above it, walking up the tree the way RFC 9989 says: every name up to the
top-level domain is asked, eight lookups at most, and the record nearest the
root applies, unless one on the way says `psd=n`, which makes it the name's
own, or `psd=y`, which makes it a public suffix whose record applies only where
the domain one label below publishes none. A record found above the name
applies its `np` where the name does not exist and its `sp` where it does,
each where it has one, and its `p` otherwise. A lookup that fails on the way
stops the walk, and the line says so rather than guess which record applies.
Nothing connects to a mail server unless `--tlsa`
asks, and the MTA-STS policy file is not fetched. The lookups spend the walk's
budget, and a check cut short says so. The exit code is left alone.
`--format json` carries it as `mail`, and `--format openmetrics` as
`dnstree_mail_hosts`, `dnstree_mail_dane_hosts` and `dnstree_mail_policy`.

### Whether the certificates match

A signed TLSA set says which certificate a sender should see; it does not say
the server shows it. The usual way DANE breaks is a certificate renewed with a
new key while the TLSA record still names the old one: the record is there and
signed, `--mail` calls the host covered, and every sender that checks DANE
stops delivering to it. `--tlsa` connects to each address `--mail` proved for a
covered host, on port 25, starts TLS with STARTTLS, and holds the chain the
server presents against the host's TLSA set the way a sender does:

```
$ dnstree --mail --tlsa --dnssec --explain --no-asn --no-compare freebsd.org
...
mail: 2 MX hosts for freebsd.org. [secure RSASHA256]
mail:   10 mx1.freebsd.org. dane (1 TLSA record): a sender has to see a certificate that matches
mail:     96.47.72.80 match: 3 1 1 0a7e2f46... matches CN=mx1.freebsd.org, issued 2026-08-15
mail:   30 mx66.freebsd.org. none: its zone proves there is no TLSA set
mail: no mta-sts; no tls-rpt; dmarc p=none
mail: dane covers 1 of 2 MX hosts
...
```

A DANE-EE record (usage 3) has to match the leaf certificate, and its names and
dates are ignored (RFC 7672 3.1.1). A DANE-TA record (usage 2) has to match a
certificate of the chain the server presents, the leaf has to chain to it and
be valid when the walk was made, and it has to name the TLSA base domain, the
MX host or the domain the mail is for (RFC 7672 3.2.2). PKIX records are not
used, as no mail sender uses them.

Each address is a line of its own under its host, since a host behind several
addresses may present a new certificate on one and an old one on another.
`match` names the records that matched; `mismatch` is a chain none matches, or
a server that does not offer STARTTLS, and is said in a warning with when the
certificate presented was issued, which is most likely when its key changed.
The coverage line and `--explain` both say which hosts a sender refuses. An
address that cannot be reached is `unreached`: many networks and cloud
providers block outgoing connections on port 25, so it could not be checked
from here, and one line says so; it is never taken for a mismatch.

It needs `--mail` and `--dnssec`, since only an address DNSSEC proved is worth
connecting to; from the file of defaults it waits for a run with both, such as
one with `--check`, which does not turn it on by itself. It connects only to
the hosts DANE covers, at most four addresses each and sixteen in all, and a
warning says how many it left; each is held to ten seconds and to what it may
send. It never asks of a walk drawn again with `--from`, and dnstree-web never
does it. The exit code is left alone.
`--format json` carries it as `addresses` and `presented` on each host, and
`--format openmetrics` as `dnstree_mail_tlsa_addresses`.

## Where a browser connects

An HTTPS record (RFC 9460) tells a browser how to reach a site before it
connects: which protocols it speaks, on which port, at which server, and the
key for encrypted client hello. The record often points somewhere else: one in
alias mode, priority 0, says to look at another name instead, and one in
service mode can name another server and carry `ipv4hint` and `ipv6hint`
addresses a browser may connect to before it has looked that server up.
`--svcb` follows the records the way a client does, down the aliases and on to
the addresses of every server the last set names:

```
$ dnstree --svcb --dnssec --explain --no-asn --no-compare facebook.com HTTPS
...
│   │   ├── a.ns.facebook.com. 129.134.30.12  238ms  NOERROR  AA DO  [insecure]
│   │   │   ├── facebook.com. 7200 HTTPS 2 star-mini.fallback.c10r.facebook.com. alpn="h2,h3"
│   │   │   ├── facebook.com. 7200 HTTPS 1 . alpn="h2,h3"
...
│   │   │   ├── facebook.com.  (A of star-mini.fallback.c10r.facebook.com. for svcb)
│   │   │   │   ├── a.ns.facebook.com. 129.134.30.12  241ms  NOERROR  AA DO  [insecure]
│   │   │   │   │   └── star-mini.fallback.c10r.facebook.com. 60 A 57.144.222.1
...
svcb: facebook.com. HTTPS 1 . alpn="h2,h3"  [insecure]
svcb: facebook.com. HTTPS 2 star-mini.fallback.c10r.facebook.com. alpn="h2,h3"
svcb:   facebook.com. 163.70.151.35, 2a03:2880:f189:184:face:b00c:0:25de
svcb:   star-mini.fallback.c10r.facebook.com. 57.144.222.1, 2a03:2880:f36f:1:face:b00c:0:25de
✔ answered in 2.8s · 10 queries · 3 servers
...
· a client that reads the HTTPS records of facebook.com. connects to facebook.com., then star-mini.fallback.c10r.facebook.com.
```

Each set of the chain is drawn with its verdict, the first on the way that is
not secure, so an alias that leaves a signed zone for one that is not reads as
the unsigned one it lands in. Every record is followed, best priority first,
rather than the one a client would pick, and a target of `.` is the record's
own name. Each server's line lists the addresses its A and AAAA sets came to,
as far as `-4` or `-6` allows. A hint that is none of them is said on that
line and in a warning: a client may connect on the hint before it looks, and
reach a server that no longer serves the site. A family whose lookup failed is
not judged, so a hint is never called stray for want of an answer.

An alias to `.` says the service does not exist. A chain that ends on a name
with no records leaves a client connecting to that name by its addresses
alone, and a name with no records at all leaves it connecting as it would
without them. A warning says when the aliases loop, go on past `--max-cname`,
or share a set with records in service mode, which a client ignores; when a
set has more than one alias, which a client picks among at random, and the
walk follows the first by name; when a target has no address, or its addresses
cannot be looked up; when a set fails to look up or does not validate; and when
a set with an ECH key is not signed all the way down, the aliases that led to
it included. A TYPE of HTTPS or SVCB makes the walk's own answer the first
set; any other TYPE looks up the HTTPS set as an aside, and SVCB records are
followed only where SVCB is the TYPE. A name with a port, such as
`_8443._https.example.com`, is asked as written, and the aliases it leads to
are asked without the port, as RFC 9460 says. Nothing connects to the servers. The lookups
spend the walk's budget, and a check cut short says so and leaves the hints of
the targets it did not reach unjudged. The exit code is left alone. `--format json` carries it as
`service_path`, and `--format openmetrics` as `dnstree_svcb_targets` and
`dnstree_svcb_stray_hints`.

## What it depends on

To reach a name, a resolver asks the servers of every zone above it. But those
servers have names too, often in other zones, and finding their addresses
means walking to those zones first, whose own servers may sit somewhere else
again. Whoever controls any zone on the way can make the name resolve
somewhere else, and most of them nobody chose. `--deps` follows every
nameserver of every zone the walk went through, and then every nameserver of
every zone those lookups went through, until none is left:

```
$ dnstree --deps --dnssec --explain --no-asn --no-compare www.example.com
...
│   │   │   ├── com.  (A of hera.ns.cloudflare.com. for deps)
│   │   │   │   ├── l.gtld-servers.net. 192.41.162.30  248ms  NOERROR  DO  referral → cloudflare.com.  [secure ECDSAP256SHA256/SHA256]
│   │   │   │   │   ├── ns3.cloudflare.com. 162.159.0.33  229ms  NOERROR  AA DO  [secure ECDSAP256SHA256]
│   │   │   │   │   │   ├── hera.ns.cloudflare.com. 86353 A 173.245.58.162
...
deps: www.example.com. depends on 6 zones besides the root, 2 of them unsigned
deps:   com., example.com.  the walk
deps:   net., gtld-servers.net. (unsigned)  by l.gtld-servers.net., a nameserver of com.
deps:   cloudflare.com.  by hera.ns.cloudflare.com., a nameserver of example.com.
deps:   nstld.com. (unsigned)  by av1.nstld.com., a nameserver of gtld-servers.net.
✔ answered in 11s · 39 queries · 6 servers
```

Each line names the zones one nameserver's lookup came to that no lookup
before it had, and the zone that nameserver serves. With `--dnssec`, a
delegation that is unsigned, or bogus, is said beside its zone: a zone like
that is easier to forge. The walk itself stops at the first nameserver it
reaches, but any of them may be the one a resolver asks, so every one is
followed here, glued or not: glue is a copy, and whoever can change the zone
the name lives in can change what it says. A nameserver named inside the zone
it serves adds nothing the list does not have, and the root is left out, since
every name depends on it.

Each zone and each nameserver is visited once, so zones that serve each other
end the lookups rather than feed them. A nameserver whose lookup fails is said
on a line of its own, and one that does not exist is marked in the tree the way
one the walk finds is: whoever registers the domain it would be in can answer
for the zone. Every lookup is a walk of its own, drawn in the tree as an aside,
and starts from the deepest zone the run has already entered. A name served
from other TLDs costs dozens of queries, so the budget is 512 unless
`--max-queries` says otherwise, and a budget that runs out says the list is
short, in a line and a warning. The exit code is left alone. `--format json`
carries it as `dependencies`.

## Whether its registration is about to run out

A domain is rented, not owned. When the registration lapses, or the registry
puts the domain on hold, the TLD stops delegating it and the name stops
resolving everywhere at once — and the registry knew for weeks. `--rdap` asks
the registry over RDAP (RFC 9083), the JSON successor to WHOIS, when the
registration runs out, which statuses it carries, and which nameservers and DS
it holds, and holds those against the referral the TLD handed the walk:

```
$ dnstree --rdap --dnssec --explain --no-asn --no-compare example.com
...
rdap: example.com. is registered until 2027-08-13, with 310 days left
rdap: status: client delete prohibited, client transfer prohibited, client update prohibited
rdap: nameservers and DS match what com. hands out
✔ answered in 2.1s · 6 queries · 3 servers
...
· the registration of example.com. runs until 2027-08-13
```

Less than 30 days left is drawn as a warning, and a registration that has run
out, or a status that takes the domain out of its zone — `client hold`,
`server hold`, `pending delete`, `redemption period`, `pending restore`,
`inactive` — as a fault. Nameservers or DS that the registry and the TLD do not
agree on mean a change is stuck between the two, or the registry's copy is
stale. The DS are compared only with `--dnssec`, since a referral carries them
only then.

The domain asked about is the zone the walk was delegated to below the TLD,
which is where a registration is, `example.co.uk` and `example.com.br`
included. Where the TLD said the name does not exist — which is what a lapsed
domain looks like from the outside — it is the TLD and one label of the name,
and the registry says whether it holds it:

```
$ dnstree --rdap --explain --no-asn --no-compare zzzz-not-registered-4711.com
...
rdap: the registry holds no registration for zzzz-not-registered-4711.com.
...
· the registry holds no registration for zzzz-not-registered-4711.com.: it has lapsed, or was never registered
```

The registry is found in [IANA's bootstrap file](https://data.iana.org/rdap/dns.json)
(RFC 9224), over HTTPS: these are the only requests dnstree makes that are not
DNS, which is why it is off unless asked for. A TLD whose registry runs no RDAP
service says so, and so does a registry that could not be reached or did not
answer in time; either costs the check and never the walk. Each domain is
asked about once an hour at most, so `--watch` does not hammer the registry.
The exit code is left alone unless `--expect registered:30d` asks for that long
left ([Asking rather than reading](scripting.md#asking-rather-than-reading)).
`--format json` carries it as `registration`, and `--format openmetrics` as
`dnstree_registration_left_seconds` and its neighbours.

## How long a change takes to reach everyone

Nothing is pushed out when a zone changes: every cache holding the old copy
keeps it until its TTL runs out, and most changes wait on more than one TTL,
kept in more than one zone. `--propagation` reads the ones the walk saw and
says how long each kind of change to the zone it ended in takes to reach every
cache:

```
$ dnstree --propagation --dnssec --check-ns --serial --no-asn --no-compare example.com
...
propagation: how long a change to example.com. takes to reach every cache, at worst
propagation:   change the answer        5m   A 300 at example.com.
propagation:   create a missing record  30m  SOA 1800, minimum 1800 at example.com.
propagation:   move the nameservers     2d   NS 172800 at com., 86400 at example.com.
propagation:   change the DS            1d   DS 86400 at com.
propagation:   change the keys          1h   DNSKEY 3600 at example.com.
✔ answered in 2.7s · 20 queries · 14 servers
```

Each line is the worst case, for a cache filled just before the change; most
caches let go sooner, and a resolver that caps TTLs, as many do at a day or a
week, sooner still. A record that did not exist is kept missing for the shorter
of the SOA's TTL and its minimum (RFC 2308), which is why a name created after
somebody asked for it can take a while to appear. The nameservers take the
longer of the two NS TTLs: the parent's, which is often the registry's to
choose, and the zone's own, since resolvers differ over which they keep. A key
rollover is steps that each wait on the DS or the DNSKEY TTL; removing an old
DS before the longer one has passed leaves the caches still holding it with a
chain that breaks.

A TTL lowered ahead of a move counts only once the old, longer one has run out
of the caches, so lower it at least that long before.

It asks nothing more than the walk: the parent's NS TTL comes with the
referral, the zone's own only with `--check-ns`, the SOA with a denial or
`--serial`, and the DS and DNSKEY TTLs only with `--dnssec`. A line the walk
had no TTL for is left out, and the flag that reads it is named under the
others. It is worked out again for a walk read back with `--from`, and
`--format json` carries it as `propagation`.

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

## Whether it will answer on new nameservers

Moving a zone to another provider comes down to changing the nameservers its
parent delegates it to, and the mistakes are the ones nobody checks before the
change: a record the new provider was never given, a zone it was never told to
serve, and, for a signed zone, a DS at the parent that still vouches for the old
provider's keys. Once the change is made, resolvers keep the old delegation for
as long as the parent allows — two days, often — so undoing it is slow.

`--try-ns ZONE=SERVER` walks as though the parent already delegated the zone to
the servers named, as many times as there are of them. A server is a name, an
address, or both as `--root` writes them, `NAME@ADDR`; a name with no address
is looked up the way a nameserver named outside its zone is, so one inside the
zone it serves has to be given its address, as glue would. The referral is
drawn as the parent really gave it, marked `replaced by --try-ns`, its DS and all,
and the walk goes on to the new servers:

```
$ dnstree --dnssec --no-asn --explain --try-ns example.com=a.iana-servers.net --try-ns example.com=b.iana-servers.net www.example.com A
. (root)  [secure RSASHA256/SHA256]
├── a.root-servers.net. 198.41.0.4  133ms  1175 of 1232 bytes  NOERROR  DO  referral → com.  [secure ECDSAP256SHA256/SHA256]
│   ├── a.root-servers.net. 198.41.0.4  397ms  NOERROR  AA DO  (truncated over udp; DNSKEY of .)
│   ├── l.gtld-servers.net. 192.41.162.30  177ms  NOERROR  DO  referral → example.com.  [bogus ECDSAP256SHA256/SHA256: no DNSKEY of the zone matches the DS its parent published]  (replaced by --try-ns)
│   │   ├── l.gtld-servers.net. 192.41.162.30  184ms  NOERROR  AA DO  (DNSKEY of com.)
│   │   ├── . (root)  [secure RSASHA256/SHA256]  (resolving a.iana-servers.net.)
...
│   │   └── a.iana-servers.net. 199.43.135.53  151ms  NOERROR  AA DO  [bogus: no DNSKEY of the zone matches the DS its parent published]
│   │       ├── www.example.com. 300 CNAME www.example.com.cdn.cloudflare.net.
...
✘ bogus in 3.7s · as though delegated to a.iana-servers.net., b.iana-servers.net. · resolver in 20ms · 18 queries · 5 servers

· www.example.com. A is 104.20.23.154 and 172.66.147.243, answered by ns1.cloudflare.net. for cloudflare.net., after 1 alias
· a cache may hold this answer for 5 minutes, and the delegation to cloudflare.net. for 2 days
· the chain of trust breaks at example.com.: no DNSKEY of the zone matches the DS its parent published, so a resolver that validates answers SERVFAIL for this name
· this walk went to the nameservers --try-ns named, so moving example.com. to them as it stands breaks it for every resolver that validates; have the parent publish a DS for their keys first, or move it unsigned
...
```

IANA's servers still serve `example.com`, with keys of their own; the parent's
DS is for the ones Cloudflare signs with, so moving the zone back today would
break it for every resolver that validates. The exit code is the walk's, so a
script can hold a move to `--expect` before making it. To see what the new
servers say differently, save a walk of the zone as it is with `--format json`
and hold the trial against it with `--against`; `--names` tries a whole list
of names in one run.

The summary says the walk was a simulation, and so does `--format json`, as
`trial`. A walk that never comes to a referral for the zone named changes
nothing and says so. One zone is tried at a time, the root cannot be, since it
has no parent to delegate it; `--diff`, which remembers the DNS as it is, will
not take it, and nor will the file of defaults.

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
