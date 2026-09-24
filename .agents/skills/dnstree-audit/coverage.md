# Audit coverage

The ledger the `dnstree-audit` skill reads first and rewrites last.

- **Commit**: `ccfb897`
- **Date**: 2026-09-24
- **Scope**: full, areas 1–7 plus asn, recursive, cli and cmd

## Open findings

- **Critical**: a DS with an unknown algorithm and no signature reads
  `indeterminate`, not `bogus`, because the algorithm filter runs before the
  parent's signature is checked. `internal/dnssec/dnssec.go:95`
- **Critical**: an opt-out NSEC3 covering the delegation proves it insecure
  without the closest encloser proof (RFC 5155 8.9), so a referral that names a
  cut below a signed zone escapes it. `internal/dnssec/denial.go:88`. fakens
  sends no closest encloser NSEC3 in its referral denials (`fakens.go:426`), so
  `TestProvenInsecureDelegation` and `TestNoDSProvenByOptOut` pass on a proof
  that is too weak.
- **High**: names reach the renderers as raw octets, `--format ascii`
  included. `internal/resolver/resolver.go:1086`,
  `internal/transport/recursive.go:94`, the sinks in `internal/render/tree`,
  `internal/explain` and `warnf`.
- **Medium**: `wide` misses CJK Ext B+ and U+1F0xx–1F2xx, so the live cut lets
  a line wrap. `internal/render/tree/live.go:545`
- **Low**: history refuses the file its own walk wrote and says "first walk".
  `internal/history/history.go:174`
- **Low**: A/AAAA glue with empty rdata becomes an invalid address.
  `internal/resolver/classify.go:137`
- **Low**: raw bytes in JSON-only fields: `service.alpn` (reproduced), the ASN
  fields and `Resolver.Err` (unverified). `internal/resolver/resolver.go:1112`,
  `internal/asn/asn.go:293`, `internal/transport/recursive.go:74`

## Checked and sound

- Referrals only go strictly down (`IsBelow` and not equal), with `MaxDepth`
  behind them.
- Bailiwick is judged against the answering server's zone and not narrowed.
- CNAME cycles are caught by `chased` and `MaxCNAME`. DNAME synthesis is checked
  against the signed DNAME.
- Side walks are capped at 2 and spend from the run budget. `--all` and
  `--serial` spend before fanning out.
- The FORMERR/NOTIMP retry, TC to TCP and the fallback stay in one hop. A
  truncated reply is never NODATA.
- Every failure becomes a step: budget exhaustion, timeouts, lame servers.
- UDP replies are matched by ID, QR and question. Non-IN classes are dropped.
- An NS with empty rdata unpacks as `.` and is harmless. The `rr.(*dns.NS)`
  type assertions are safe.
- RRSIG window, TypeCovered and RRset shape are checked. SignerName is tied to
  the key owner.
- Key tag collisions: every matching key and signature is tried in `matchDS`
  and `verify`.
- A signed DS with an unknown digest type is `indeterminate`. Wildcard answers
  need a denial of the next closer name.
- NSEC/NSEC3 canonical order and apex wrap-around are right, including a single
  record.
- NSEC3: iterations capped at 100, 16 records per section, unknown hash
  algorithms `indeterminate`.
- A delegation cut or DNAME is never the closest encloser. `crossCut` only
  enters cuts above the qname.
- `step.Err` and extended error text are escaped (`ccfb897`). DoT and UDP/TCP
  close on cancel (`4f25f13`).
- TCP and DoT honour the length prefix and ID. DoT's `ServerName` is the
  delegation's name.
- DoH: 64 KiB body cap, status and content type checked, redirects refused,
  dial pinned.
- Deadlines are the minimum of the query timeout and ctx, on the dial, conn and
  HTTP client.
- Web: `textContent` only, data by JSON fetch. The server has a Host allowlist,
  binds 127.0.0.1 by default and sets `nosniff` and `no-store`.
- DOT: `quote()` escapes quotes, backslashes and newlines.
- History: names limited to `[a-z0-9.-]`, 0700/0600, temp file and rename,
  version and question checked on read.
- Concurrency: `attach` only after `wait.Wait()`, `warnf` under a mutex, the
  live tail reads its own counters, `Asking` guarded. `go test -race -count=2`
  is clean.
- AS lookups: each address started once, `Annotate` waits at most `asnGrace`,
  failure is one warning.
- Config file: unknown flags refused, `config`/`no-config`/`version`/`schema`
  not settable, groups replace.
- Layering: `internal/layering` passes.
