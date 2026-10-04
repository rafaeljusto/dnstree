# DNSSEC

Following the chain of trust, the requests a zone makes of its parent, and what
DNSSEC is worth to ECH.

- [Following the chain of trust](#following-the-chain-of-trust)
- [What the zone asks its parent](#what-the-zone-asks-its-parent)
- [Telling the zone it is broken](#telling-the-zone-it-is-broken)
- [ECH, and what makes it worth anything](#ech-and-what-makes-it-worth-anything)

## Following the chain of trust

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
stretched over has to show there was nothing closer to answer with. A denial
that rests on an opt-out range reads `[insecure]`: the range may be hiding an
unsigned delegation, so it proves only that the name is not signed.

A zone that signs as it answers cannot sign the gap a name falls in, so it says
every name it has nothing for is there, with a record of its own — and where the
name is not there after all, that record lists NXNAME (RFC 9824). Cloudflare
answers this way. The answer comes back NOERROR, and read as it came it is a
name that exists; once the record at the name has been checked against the
zone's keys, it is the NXDOMAIN it is, and the hop says why:

```
$ dnstree --dnssec --no-asn --explain nothing-here-dnstree.cloudflare.com A
...
│   │   ├── ns3.cloudflare.com. 162.159.0.33  20ms  NOERROR  AA DO  [secure]  (compact denial, RFC 9824)
...
· nothing-here-dnstree.cloudflare.com. does not exist, and cloudflare.com. is the zone that says so, answering NOERROR with a signed record that says it, the way a zone that signs as it answers does (RFC 9824)
```

The rcode stays what the server sent, and `--format json` marks the hop
`compact`. A record nobody signed is anybody's to add, so one that did not check
out leaves the hop a NODATA, noted `NXNAME, unproved`. Without `--dnssec` the
question asks for no signatures, and the zone owes it the NXDOMAIN outright.

A registry that serves its own domains from the machines of its ccTLD answers
for a child zone with no referral to it, so the cut is invisible from the walk.
The signatures name the zone that made them, and the same server holds the
parent side of the cut, so it is asked for the child's DS — an aside reading
`(DS of registro.br.)` — and the chain crosses the cut before the answer, or a
referral the same server hands out from below it, is checked.

A chain that holds today can stop holding on a schedule. Every signature is
made to last a while, and a zone whose signer has stopped goes on validating
until the first of them runs out, and then fails all at once. A signer re-signs
with a quarter or more of a signature's life still ahead of it, so a verdict
resting on one with less than a fifth of its life left says when it runs out —
`[secure ECDSAP256SHA256, expires in 2d3h]` — and `--explain` says what happens
then. The time left is read against when the walk was made, which is also what
a walk drawn again with `--from` reads it against. `--expect fresh` holds a
script to the same thing; see [Asking rather than reading](scripting.md#asking-rather-than-reading).

A validating resolver fetches a zone's keys from one of its nameservers, keeps
them, and checks what the others say against them. A zone signed by two
providers at once (RFC 8901) works only while each publishes the other's keys
as well as its own; one that forgets fails for the resolvers that happened to
take the keys from it, and only for answers the other provider signed — some of
the time, for some people, which is the hardest outage there is to report. A
walk asks one server and sees nothing wrong, so `--all --dnssec` asks every
nameserver of the zone it ends in for the keys it publishes and the key it signs
its SOA with:

```
$ dnstree --all --dnssec --no-asn isc.org SOA
...
│   │   ├── ns2.isc.org. 199.6.1.52  220ms  NOERROR  AA DO  [secure ECDSAP256SHA256]
│   │   │   ├── isc.org. 7200 SOA ns-int.isc.org. hostmaster.isc.org. 2026100209 7200 3600 24796800 3600
│   │   │   ├── ns2.isc.org. 199.6.1.52  277ms  NOERROR  AA DO  (DNSKEY of isc.org.)
│   │   │   ├── ns2.isc.org. 199.6.1.52  228ms  NOERROR  AA DO  (keys check: publishes 7250 27566)
│   │   │   ├── ns2.isc.org. 199.6.1.52  218ms  NOERROR  AA DO  (keys check: signs with 27566)
...
✔ answered in 6s · resolver in 207ms · 77 queries · 50 servers
```

Where one signs with a key another does not publish, the walk names both, once
for each key:

> the nameservers of example.test. do not publish the same keys: ns2.example.test. lacks key 2192, which ns1.example.test. signs with, so a resolver that took the keys from ns2.example.test. rejects what ns1.example.test. answers; publish every signer's keys from every nameserver (RFC 8901)

A key one server publishes and nobody signs with breaks nothing, and is left
alone. The verdict is the one the walk reached: this is about the paths it did
not take. Servers are told apart by address, since an anycast site left behind
is one address of a name. It costs two queries for each address, which is
part of why `--all` walks on a budget of 256 queries rather than 64; a walk
whose budget ran out before it entered the zone has no keys to compare, and
says nothing.

A chain that holds can still be set up the way the advice has moved on from, and
`--explain` says so under the verdict, which it never changes: a zone signing
with RSASHA1, which RFC 8624 says zones should no longer sign with and some
validators already read as unsigned; RSA keys under 2048 bits; a SHA-1 DS at the
parent; a DS that matches none of the zone's keys; and a key signing key that no
DS points at and that signs nothing. The last two are how a planned rollover
looks halfway through, so they are said as what the walk saw, not as mistakes.
Every zone on the way down is read, since a weak link above a zone weakens it
too:

```
$ dnstree --dnssec --explain isc.org SOA
...
✔ answered in 2.8s · resolver in 254ms · 6 queries · 3 servers

· isc.org. SOA is ns-int.isc.org. hostmaster.isc.org. 2026092822 7200 3600 24796800 3600, answered by ns1.isc.org. for isc.org.
· a cache may hold this answer for 2 hours, and the delegation to isc.org. for 1 hour
· the chain of trust holds from the root to isc.org., signed with ECDSAP256SHA256
· org. signs with RSA keys of 1024 bits (tags 11859, 24060 and 25488), shorter than the 2048 bits NIST has asked of a signing key since 2013; the next rollover can make them longer
· org. publishes a key signing key that no DS points at and that signs none of its keys (tag 725): one waiting to be rolled in, or left by a rollover that never finished
```

## What the zone asks its parent

A zone changes the DS that vouches for it by asking: it publishes the DS it
wants in a CDS record, or the key in a CDNSKEY (RFC 7344), and its parent picks
the request up when it next looks. A key rollover is exactly that, which makes a
request the parent has not acted on a rollover stuck halfway — and the chain is
secure all the while, so nothing else says so. `--check-ds` asks the zone the
walk ends in for both, and holds them against the DS its parent handed out:

```
$ dnstree --dnssec --check-ds --no-asn cloudflare.com A
. (root)  [secure RSASHA256/SHA256]
├── a.root-servers.net. 198.41.0.4  151ms  1174 of 1232 bytes  NOERROR  DO  referral → com.  [secure ECDSAP256SHA256/SHA256]
│   ├── a.root-servers.net. 198.41.0.4  491ms  NOERROR  AA DO  (truncated over udp; DNSKEY of .)
│   ├── l.gtld-servers.net. 192.41.162.30  186ms  NOERROR  DO  referral → cloudflare.com.  [secure ECDSAP256SHA256/SHA256]  cds matches the ds
│   │   ├── l.gtld-servers.net. 192.41.162.30  214ms  NOERROR  AA DO  (DNSKEY of com.)
│   │   ├── ns3.cloudflare.com. 162.159.0.33  8.2ms  NOERROR  AA DO  [secure ECDSAP256SHA256]
│   │   │   ├── cloudflare.com. 300 A 104.16.133.229
│   │   │   ├── cloudflare.com. 300 A 104.16.132.229
│   │   │   ├── ns3.cloudflare.com. 162.159.0.33  12ms  NOERROR  AA DO  (DNSKEY of cloudflare.com.)
...
✔ answered in 1.1s · resolver in 14ms · 8 queries · 3 servers
```

Beside the verdict of the cut it reads `cds matches the ds`, `no cds`, or one of
the three things worth a warning: a zone asking for a key the parent does not
publish, a zone asking for no DS at all (RFC 8078), which leaves it unsigned
once the parent acts, and a CDS and a CDNSKEY describing different keys, which a
parent acts on neither of. A parent holding a SHA-1 digest beside the SHA-256
one asked for holds the same key, and is not a rollover.

The request counts only once the zone's own keys have signed it, the way a
parent checks it, so `--check-ds` needs `--dnssec` — a file of defaults that sets
it is heeded by the runs that check signatures, and left alone by the rest — and
a zone the chain did not reach secure reads `cds unchecked`. A zone that crosses into a child served by
the same machines, with no referral, is checked against the DS fetched to cross
it. It costs two queries, asked of the server that answered.

## Telling the zone it is broken

When a zone's chain of trust breaks, the first to know are the resolvers that
check it: they answer SERVFAIL, and nobody tells the zone's owner. RFC 9567
gives a zone a way to ask: its servers add the name of a reporting agent to
their answers, unasked, and a resolver that hits a failure reports it by looking
up a name built from the question and the error. Every hop that names an agent
draws it, so where a report would go is in the tree before anything is sent:

```
│   │   ├── ns1.example.test. 192.0.2.53  18ms  NOERROR  AA DO  report → agent.example.net.  [bogus: the answer carries no signature]
```

`--report` sends it, when the chain the walk followed is bogus and the broken
zone named an agent: a TXT lookup of the name RFC 9567 builds, through the
recursive server the walk is compared against, which the first `--resolver`
names:

```
report: told agent.example.net. the chain of trust is bogus, as _er.1.www.example.test.6._er.agent.example.net. (NOERROR)
```

The error reported is 6, DNSSEC Bogus. A chain that could not be checked is
never reported, since that is this build's limit and not the zone's fault; nor
is one with no agent, one whose agent sits at or below the name it would be told
about, which RFC 9567 rules out, or one whose report would be longer than a name
can be. Without `--report`, `--explain` says when a broken zone asked for one.

A report tells a third party that this machine looked up this name, so it is
only ever sent when asked for. It needs `--dnssec`, it is not sent from
`--watch`, which would send the same report every walk, and the file of
defaults cannot set it. The agent is only what the server said, and nothing
vouches for it, which is why it is drawn. What came of the report is in
`--format json` as `report`, and the agent of each hop as `report_to`.

## ECH, and what makes it worth anything

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
