# Audit coverage

The ledger the `dnstree-audit` skill reads first and rewrites last.

- **Commit**: `cc0837f`
- **Date**: 2026-09-29
- **Scope**: the eighteen commits since `499eefc` (dnstree-web and
  `internal/server`, `transport.Guard`, `--against`, IDN names, dangling names,
  DDR, open transfer and recursion probes, the hidden zone cut referral)

## Open findings

None.

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
- `--from` input: 64 MiB, 1024 steps deep, nothing after the document,
  schema 4 only (3 wrote EDE text raw), and durations between 0 and a year.
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
- NSEC3 hashing is recorded only off a record whose signature held, and its
  zone and salt go through `Shown`.
- `Trace.Chain` reads the chain the way the exit code does: bogus anywhere,
  then indeterminate, then the answer's verdict. `verdict`, the live summary,
  explain and openmetrics all read it.
- Waterfall and gantt: every float-to-int conversion is bounded, the axis
  counts its marks, gantt names swap `:`, `#`, `%`, `;` and newline.
- OpenMetrics: label values escape `\`, `"` and newline over the shown trace.
- web-3d: text only through `textContent` or text nodes, styles only from the
  page's own tones, same `local()` host check. The icons are static assets.
- The served address is announced with the question shown, never raw.
- ANY, AXFR, IXFR and the meta types are refused; `TYPE255` is not in the
  codec's type map either.
- dnstree-web: both transports guarded by `Public`; exposure probes, DDR, AS
  lookups and the comparison are off; nothing but the question reaches the
  resolver.
- dnstree-web: `asked` and `drawn` redirect through `path()` (literal view,
  `PathEscape`); `canonical` refuses `/`, `\`, whitespace and over 253 bytes;
  CR/LF never reaches a header.
- dnstree-web: assets are a fixed embedded map, `failed.html` gets fixed text
  through `html/template`, hostile text reaches the page only as JSON.
- dnstree-web: 4 walks at once, 5 s queue, 15 s per walk on `WithoutCancel`;
  kept walks capped at 32 MiB and 1 MiB each; the limiter clears every window.
- Probes (AXFR, recursion): one length-prefixed message read, spent from
  `counters.query()` before fan-out, `Aside` so no verdict or exit code reads
  them, attached after `wait.Wait()`.
- `crossReferral`: the cut is strictly between the answering zone and the
  delegation, budgeted, and its DS goes through `enterZone`/`provesNoDS`.
- Pending nameserver names shrink every pass and stay inside the query budget.
- `unowned` is bounded by `len(Answer)`; dangling and DDR strings go through
  `Shown`; DDR drops AliasMode, `.` targets and unknown mandatory keys.
- `idn.ASCII` runs only on user input; `terse` always goes deeper and terminates.
- `--against`: the saved file goes through `saved()` limits and `history.Of`;
  `Against` indexes nothing; a fuzz of Read, Against, Findings and every
  renderer found no panic and no raw escape.
- The trace reflection test reaches `Dangling`, `DDR` and `Designated`; `Probe`
  holds validated enums only.
- dnstree-web redirects are all rebuilt through `path()`, the bare route too;
  the mux's own cleaning keeps `%5C` escaped (`TestRoutes`).
- `--client-header` reads the last entry, the one the proxy wrote, and falls
  back to the connection when it is no address (`TestPerClientForwarded`).
- `Public` refuses IPv4-compatible, SIIT, Teredo, site-local and the 6to4
  relays (`TestPublic`).
- Every finding's text is checked for ASCII in the explain table tests.
