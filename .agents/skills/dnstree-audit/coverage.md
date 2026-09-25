# Audit coverage

The ledger the `dnstree-audit` skill reads first and rewrites last.

- **Commit**: `f57b93b`
- **Date**: 2026-09-25
- **Scope**: the thirteen commits since `f556f8c` (`--qmin`, `--from`,
  `--format mermaid`, signature expiry, `-x`, `--check-ds`, `--cookie`)

## Open findings

None. The eight found at `f57b93b` are fixed in the working tree, each with
the test that reproduced it kept: `TestDeniedEmptyNonTerminal`,
`TestWildcardOverAnEmptyNonTerminal`, `TestTraceShownEveryField`,
`TestRunFromHostile`, `TestExpiringLongLife`, `TestReadRefuses` (depth,
trailing data, version 3), `TestReadRefusesTheEndless`, `TestNSECBitmapWithCDS`
and `TestBuildDatesTheWalk`. Until they are committed, the next run starts from
this commit and those tests.

## Checked and sound

- Referrals only go strictly down (`IsBelow` and not equal), with `MaxDepth`
  behind them.
- Bailiwick is judged against the answering server's zone and not narrowed,
  under `--qmin` too.
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
- An NSEC gap ending below a name never denies it (`nsecDenies`): NXDOMAIN,
  the wildcard's next closer and the wildcard itself. The empty non-terminal
  NODATA proof keeps `nsecCovers`.
- NSEC3: iterations capped at 100, 16 records per section, unknown hash
  algorithms `indeterminate`.
- A delegation cut or DNAME is never the closest encloser. `crossCut` only
  enters cuts above the qname, and only on the full-name hop under `--qmin`.
- An unsigned DS is bogus whatever its algorithm. Unsupported is read only
  after the parent's signature.
- An opt-out no-DS proof needs a signed closest encloser, and a cut is never
  one.
- qmin: `Result()` skips minimised hops, so exit code, `--expect` and `--diff`
  never read one. A minimised NXDOMAIN is re-asked in full. `reach` only grows
  and every hop spends `counters.query()`.
- A minimised referral goes through the same `enterZone` DS/NSEC proof.
- `--check-ds`: both fetches budgeted, a bogus CDS/CDNSKEY is `unchecked`,
  `chain.Verify` never settles the chain state, no signal state reaches an exit
  code. `Signal` survives bad base64, empty keys and digests, unknown types.
- `moment()` mirrors the library's serial arithmetic. `Left`, `Expiring`,
  `Soonest` and `Stale` read `Trace.Started`, never the clock.
- Cookies: `EchoedCookie` checks lengths (8 + 8..32) before slicing, a
  mismatched client cookie is flagged, one BADCOOKIE retry per hop, the map is
  under `r.mu`.
- `-x` builds the name from `netip.ParseAddr` bytes only.
- Names are escaped by `Trace.Shown` in tree, live, summary, DOT, JSON, web,
  explain, expect, history and Mermaid. SOA holds only numbers. `Shown` reaches
  every plain string of the trace but EDE text, which is escaped where drawn;
  a reflection test fails on a field added without it.
- Staleness divides the lifetime, so no RRSIG time overflows it.
- `--from` input: 64 MiB, 1024 steps deep, nothing after the document, and
  schema 4 only (3 wrote EDE text raw).
- Mermaid: `quote()` escapes `"`, `#`, `<`, `>`, `&`, backtick and newline,
  labels always quoted, ids are `n<N>`/`z<N>`, edge labels are durations.
- `wide` covers U+1F000–1F2FF and CJK Ext B+. Overcounting is the safe side.
- Glue with empty rdata is dropped. Addresses from answers go through
  `netip.ParseAddr`.
- EXTRA-TEXT in JSON is escaped whole by `convertExtended`.
- `read.go` validates `kind`, `cookie`, `dnssec.state`, `signal.state`,
  `match`, IPs and subnets; a fuzz of Read plus every renderer found no panic.
- `--from` skips ASN lookups and the resolver comparison, and refuses `--diff`.
- TCP and DoT honour the length prefix and ID. DoT's `ServerName` is the
  delegation's name. UDP/TCP/DoT close on cancel.
- DoH: 64 KiB body cap, status and content type checked, redirects refused,
  dial pinned.
- Deadlines are the minimum of the query timeout and ctx, on the dial, conn and
  HTTP client.
- Web: `textContent` only (new chips too), data by JSON fetch. Host allowlist,
  127.0.0.1 by default, `nosniff` and `no-store`.
- DOT: `quote()` escapes quotes, backslashes and newlines; new lines are enums.
- History: names limited to `[a-z0-9.-]`, 0700/0600, temp file and rename,
  version and question checked on read. `Of` writes the escaped copy.
- Concurrency: `attach` only after `wait.Wait()`, `warnf` under a mutex, the
  live tail reads its own counters, `Asking` guarded. fakens builds CDS before
  the `atomic.Pointer` store and signs clones. `go test -race -count=2` is
  clean.
- AS lookups: each address started once, `Annotate` waits at most `asnGrace`,
  failure is one warning.
- Config file: unknown flags refused; `config`, `no-config`, `version`,
  `schema`, `from` and `x` not settable; groups replace; `--from` drops the
  file's `live`/`watch`/`diff`.
- Layering: `internal/layering` passes.
