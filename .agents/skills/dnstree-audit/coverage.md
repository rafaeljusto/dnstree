# Audit coverage

The ledger the `dnstree-audit` skill reads first and rewrites last.

- **Commit**: `f556f8c`
- **Date**: 2026-09-24
- **Scope**: the seven commits since `ccfb897`, and the open findings

## Open findings

None.

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
- `step.Err` and extended error text in the tree and DOT are escaped
  (`ccfb897`). DoT and UDP/TCP close on cancel (`4f25f13`).
- Names are escaped by `Trace.Shown` in tree, live, summary, DOT, JSON, web,
  explain, expect and history. SOA holds only numbers. `twin` keeps the
  highlight on the copy.
- An unsigned DS is bogus whatever its algorithm. Unsupported is read only
  after the parent's signature (`bbd0238`).
- An opt-out no-DS proof needs a signed closest encloser, and a cut is never
  one. A forged covering record only makes it bogus (`3229088`).
- `wide` covers U+1F000–1F2FF and CJK Ext B+. Overcounting is the safe side,
  and `Shown` keeps attacker text ASCII before the cut.
- Glue with empty rdata is dropped. Addresses from answers go through
  `netip.ParseAddr`, which refuses them too.
- History: `Of` writes the escaped copy, so its own file loads back.
- EXTRA-TEXT in JSON is escaped whole by `convertExtended`
  (`TestRenderEscapesNames`, `TestRenderKeepsExtraTextWhole`).
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
