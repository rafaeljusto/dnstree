---
name: dnstree-dig
description: Hold dnstree against dig across many real domains — the curated questions in domains.txt plus a sample of the Tranco top million — and investigate every question where they disagree, down to whether dnstree, dig or the zone is wrong. Compares the answer with the server the walk ended at, the rcode, and the DNSSEC verdict with two validating resolvers. Use when asked to compare with dig, cross-check answers, run a differential test, or check dnstree against real domains at scale. Takes an optional sample size (default 300) or `curated` for domains.txt alone. Edits nothing and commits nothing unless asked.
---

# dnstree against dig

`make live` checks a few names and `dnstree-e2e` checks the flags. Neither asks
whether the answer is *right* for the long tail of real zones. This does: every
question is walked by dnstree and asked again with dig, and the ones that
disagree are investigated until it is clear who is wrong.

## What is compared

[compare.sh](compare.sh) runs one walk per question with `--format json` and
reads it the way `Trace.Result` and `Trace.Trust` do. Then it asks dig:

- **the server the walk ended at**, `+norec`, for the name the last hop asked
  (the end of a CNAME chain). This is the strong signal: same server, same
  question, so the answer should be the same set. Rotating servers are asked up
  to five times, a second apart, before a difference counts.
- **1.1.1.1 and 8.8.8.8**, validating, for the rcode, the AD bit and, on a
  SERVFAIL, again with `+cd` to tell a failed validation from a broken zone.

Each question gets one class in `results.tsv`, worst first:

| class | means | weight |
| --- | --- | --- |
| `crash` | panic, race, hang, or exit 1 on a question the list meant to be valid | bug unless the question is bad |
| `auth-rcode` | the walk's rcode differs from the same server's | likely bug |
| `auth-answer` | the rdata differs from the same server's, five times | likely bug, or presentation |
| `auth-case` | differs only in letter case | presentation; check which is right |
| `auth-varies` | the server gave more than one answer across five asks | the zone rotates; ignore unless the walk's answer is not one it could give |
| `no-answer` | exit 2 where both resolvers answered | likely bug, or a lame/partial zone |
| `bogus-only-here` | exit 3, neither resolver fails validation | bug until shown otherwise |
| `bogus-missed` | both resolvers fail validation, the walk did not say bogus | bug until shown otherwise |
| `rec-rcode` | NXDOMAIN on one side, NOERROR on the other, resolvers agreeing | investigate |
| `secure-unproven` / `secure-missed` | secure where neither resolver sets AD, or insecure where both do | investigate |
| `auth-unreachable` | dig could not reach the server the walk ended at | environment |
| `rec-answer` | answer differs from both resolvers but not from the server | usually a CDN or geo answer |
| `ok` | agrees | — |

## Set up

Use bash. Everything goes in a run directory in the scratchpad.

```bash
R=$PWD; W=<scratchpad>/dig-$(date +%Y%m%dT%H%M%S); mkdir -p $W/tranco
go -C $R build -race -o $W/dnstree ./cmd/dnstree
dig -v; jq --version; timeout --version | head -1
```

`dig` must be BIND 9.18 or later, or HTTPS, SVCB and other newer types come
back as `TYPE65` and every one of them reads as `auth-answer`. macOS ships 9.10:
use `DIG=$(brew --prefix bind)/bin/dig` if it is installed, otherwise say so in
the report and treat those types as untested. Note whether IPv6 works
(`dig -6 @2001:500:2::c . SOA`): a walk can end at a v6 address dig cannot reach.

## The questions

1. Always [domains.txt](domains.txt): chosen for what they exercise.
2. Unless the scope is `curated`, a sample of the Tranco list, downloaded into
   its own directory and read as data:

   ```bash
   curl -sSL https://tranco-list.eu/top-1m.csv.zip -o $W/tranco/list.zip
   unzip -p $W/tranco/list.zip | tr -d '\r' | cut -d, -f2 > $W/tranco/names
   N=${N:-300}
   { head -n $((N / 3)) $W/tranco/names; tail -n +1001 $W/tranco/names | sort -R | head -n $((N - N / 3)); } > $W/sample
   ```

   A third from the head, where zones are big and well run, the rest from the
   tail, where the odd ones are. Spread the types: every name gets `A`, and
   every name also gets one of `AAAA MX NS TXT SOA DNSKEY CAA HTTPS`, in turn:

   ```bash
   awk 'BEGIN{split("AAAA MX NS TXT SOA DNSKEY CAA HTTPS",t," ")} {print $1; print $1, t[NR % 8 + 1]}' $W/sample > $W/tranco.txt
   ```

If Tranco cannot be reached, say so and go on with the curated list.

## Run

```bash
cat $R/.agents/skills/dnstree-dig/domains.txt $W/tranco.txt > $W/questions.txt
JOBS=4 $R/.agents/skills/dnstree-dig/compare.sh $W/dnstree $W/questions.txt $W/out
```

Keep `JOBS` at 4 or so: each question is several walks' worth of queries on
other people's servers, and a burst gets rate limited, which then reads as
`no-answer`. Six hundred questions take about fifteen minutes. Each question's
directory under `$W/out/q/` keeps the trace, the walk's reading of it
(`walk.json`, `walk.answers`) and every dig, raw and parsed.

## Investigate

Run every question that is not `ok` or `rec-answer` once more through
`compare.sh` on a list of just those: a server that timed out once is not a
finding. What still disagrees, take one at a time, worst class first, and decide
which of these it is:

- **dnstree**: it recorded something the server did not send, missed something
  it did, judged a chain the resolvers judge otherwise and the RFCs side with
  them, or crashed. That is a finding.
- **dig or this harness**: dig's presentation differs (an old dig's `TYPE65`,
  escapes in TXT, upper-case hex in TLSA, which is `auth-case`, or `107.00m`
  against `107m` in LOC, both valid under RFC 1876), or the script misread the
  trace. Fix the script or the setup, not dnstree, and say so.
- **the zone**: servers of the zone disagree with each other, a load balancer
  hands out one address that moves every few minutes (`auth-answer` that
  clears on a second run), the zone is lame
  at some servers, a CDN answers by location, or the resolvers carry a negative
  trust anchor or stale cache. Not a finding against dnstree, unless dnstree
  failed to *say* so — a walk that hit a lame server and drew nothing about it
  is.
- **the resolvers**: 1.1.1.1 and 8.8.8.8 are not the standard. An algorithm
  they do not support makes them treat a zone as insecure, where dnstree says
  `indeterminate`; that is the invariant working, not a finding.

To decide, read the trace (`$W/dnstree --from trace.json` draws it again with
no network), walk the same question with `--all` to see every server's answer,
`dig +trace +dnssec` for the path dig takes, and `delv` for an
independent validator. Name the RFC section when one decides it.

A crash, a hang, or anything a server could set off on purpose goes to
`dnstree-audit` as a hand-off with the question and the trace, to be reproduced
against `fakens`. A real server is not a reproduction there.

A curated question whose zone changed is **target drift**: propose a new target
for `domains.txt` that exercises the same thing.

## Report

One line first: questions asked, how many per class, the commit built, the dig
version, and how long it took.

Then the findings, dnstree first, each as:

- **[bug | ux | harness | zone]** one-line claim
- question: `NAME TYPE`, its class, and the lines of the trace and the dig
  output that show it
- why: the RFC or invariant that decides it
- where, if found: [file.go:L42](path/file.go#L42)

Then one line per question explained away as the zone or the resolvers, grouped
by reason. Leave the `ok` rows out.

If the user wants a finding fixed, fix it as normal work with a `fakens`
scenario that reproduces it, and hand the commit message to `dnstree-commit`.
Never commit, push or tag.
