# Audit coverage

The ledger the `dnstree-audit` skill reads first and rewrites last.

- **Commit**: `8e729b6`
- **Date**: 2026-10-07
- **Scope**: the commits since `05467fe` (`--rdap`, `--mail`, `--propagation`,
  the SERVFAIL diagnosis, `--check`, `--svcb`, CSYNC and the RFC 9615
  bootstrap signals, the resolver split, the history and dnstree-web fixes)
- **Since**: `internal/spf` alone at `9ba8ec7` on 2026-10-08, and its three
  findings fixed in the working tree. The other commits since `8e729b6`,
  `--tlsa` among them, are still to read.

## Open findings

- Low: the SPF check keeps asking after a temperror, so a resolver that times
  out on the policy's names costs a timeout per budgeted query rather than
  one; it now stops when ctx ends
  ([spf.go:71](../../../internal/spf/spf.go#L71)).
- Low: names, CAA issuer values, SPF names and the report agent inside the
  markdown report's finding sentences are open to GitHub's autolinks,
  `@mentions` and `#refs`; fixing it means marking them apart from the prose
  explain writes
  ([markdown.go:55](../../../internal/render/markdown/markdown.go#L55)).
- Low, unverified: `TestMailDANE` once came back with the example.com MX set
  bogus ("the parent published a DS it did not sign") under `-race` while the
  package was building; 260 runs after it were clean.

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
  `match`, IPs and subnets; a fuzz of Read plus every renderer found no panic; a saved CAA with no
  `wildcard` reads as any authority (`TestIssuance`).
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
- Layering: `internal/layering` passes, through every import for the trace,
  the renderers, explain, expect, history and asn (`TestApartFromTheWire`).
- NSEC3 hashing is recorded only off a record whose signature held, and its
  zone and salt go through `Shown`.
- `Trace.Chain` reads the chain the way the exit code does: bogus anywhere,
  then indeterminate, then the answer's verdict. `verdict`, the live summary,
  explain and openmetrics all read it. It, `Soonest` and `Stale` skip the
  steps under an `Apart` root, the lookups of `--mail`, `--svcb` and the
  bootstrap signals, so a third party's zone sets no exit code
  (`TestMailLeavesTheChain`, `TestServiceLeavesTheChain`,
  `TestBootstrapLeavesTheChain`, `TestApartLeavesTheRun`); `read.go` refuses
  `apart` off an aside.
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
- Markdown: names, records and findings go through `Shown` and then `escape`;
  `|`, brackets, `<`, `&` and openers are escaped, the fence outgrows any
  backtick run, the heading is a padded code span. Resolver answers are code
  spans with `|` as `\124` (`TestRenderEscapes`).
- `setupOf` runs only after the chain held, and digests no more pairs than
  `matchDS` already did; `rsaBits` checks lengths before indexing.
- `Keys` and `DS` text goes through `Shown`; `read.go` validates the DS `match`
  and `kept`; `Bits` from a file is only read when above zero.
- `Kept` and `Allowed` skip minimised hops and asides; `stale` needs a TTL of
  at most 30 against a zone TTL above it.
- `--without`: `Down` is checked before a query and again in the transport
  (TCP, fallback, probes); `kept` is under a mutex; never reaches dnstree-web;
  refused with `--diff`. `go test -race -count=2` is clean.
- web and web-3d after the replay rewrite: walk text only through
  `textContent` or text nodes, styles only from `TONES`, the film's file name
  limited to `[A-Za-z0-9.-]`, the new modules in the served file list.
- Compact denial: NXNAME is NXDOMAIN only on a Secure chain with a signature
  that held; unsigned it stays NODATA; only the full-name hop reads it.
- `ordered()`: CAA, URI and NULL sets are checked in RFC 3597 form, the shape
  and `TypeCovered` still against the original set.
- CAA climb: bounded by labels, every lookup and alias spends the budget,
  steps attached on the walking goroutine, a bogus CAA hop reaches exit 3
  through `Trace.Chain`; `dnstree_caa` takes fixed labels only.
- `checkGlue` and `checkKeys`: spend before the fan-out, attach after
  `wait.Wait()`, addresses through `netip.ParseAddr`, keys only on a Secure
  chain.
- `--try-ns`: one zone, never the root, the parent's DS through `enterZone`,
  name-only servers capped by `maxSideResolution`; nil in dnstree-web.
- `--report`: one TXT query, only on bogus, through the user's resolver; an
  agent at or below the question refused; names checked against 255 octets;
  not settable from the file, never on `--from` or in dnstree-web.
- DoT known only by address verifies the certificate's IP SANs; a zoned IPv6
  address fails closed.
- Several questions: every one checked by `Askable` first; `worse` keeps 3
  over 2 over 4 over 0; `several()` refuses the single-document formats,
  `--expect`, `--against` and `--watch`.
- Config file: `names`, `without`, `report` and `try-ns` refused; budgets
  under 1 refused, the file's included.
- `Trace.Shown` reaches `Trial`, `Report`, `CAA`, `ReportTo` and `ZoneAddrs`;
  hostile ESC in them stays out of `--format ascii`.
- `read.go` validates `caa.asked[].found`, the CAA DNSSEC status and every
  glue, `zone_addrs` and trial address.
- The Lambda bootstrap only adds `-client-header X-Forwarded-For`;
  `internal/server` and `cmd/dnstree-web` are unchanged.
- `go test -race -count=2 ./...` is clean at `8e729b6`.
- CAA failures: a referral below the walk is judged by no chain
  (`TestCAAUnenteredZone`); the budget is blamed only when this lookup ran it
  out (`TestCAABudgetSpentBefore`).
- CAA tags: a critical tag the text cannot carry refuses (`TestCAA`); a wire
  tag with `\`, `"`, a space or `;` never reads back as `issue`, since unpack
  escapes `\` and `"` and the rest fail to parse.
- SPF parsing (re-checked at `9ba8ec7`): `Fields(record)[1:]` only after the `v=spf1` check; CIDR,
  prefix lengths, macros and modifier names index within bounds; include and
  redirect cycles caught on canonical names; every `follow` spends a query.
- SPF output: every string goes through `Shown`, ESC and high bytes stay out
  of `--format ascii`, openmetrics labels are fixed; `readSPF` checks the
  result enum and server; SPF reaches the exit code only by `--expect spf:ok`.
- SPF runs on its own transports and checker, joins the trace after the walk
  through a buffered channel, sits in `apart`, and never reaches dnstree-web.
- `--pcap`: writes only the named file, refuses `--dot`, `--doh`, `-`,
  `--from` and `--watch`, not settable from the file; UDP and IPv4 lengths
  drop rather than wrap, TCP segments stay under 1480; `Record` is under a
  mutex; never reaches dnstree-web.
- `--check-edns`: spends before each fan-out, attaches after `wait.Wait()`,
  every step `Aside`; OPT read after `Unpack`, a missing one is `no-opt`;
  `read.go` validates kind, state and fault; off in dnstree-web.
- Out-of-zone nameservers on any budget: every side walk spends the run-wide
  counter, `maxSideResolution` still caps nesting, `pending` shrinks.
- CLI errors echo only the user's arguments, quoted by the flag package.
- A policy of more than 512 terms, at the name or behind an include, is not
  read and leaves the check undecided (`TestLongPolicy`).
- The nameserver sweep stops starting walks once the budget is spent, after
  the one that says it gave up (`TestSweepStopsAtTheBudget`).
- `plain()` returns the flag package's error when the name it matched is no
  flag.
- The resolver split keeps behaviour; `afford` spends before every fan-out and
  `askAll` waits before any `attach` (glue, keys, serial, exposure, CSYNC).
- `look()` stops on a spent budget, saves and restores `chased`, and every
  caller handles `stopped` and `Err` before reading the result; `walkFrom`
  clones the recorded cut's chain.
- SVCB: alias loops caught by `seen`, the chain capped at `--max-cname`, `.`
  means no service, `service()` only type-switches, hints are `netip.Addr`.
- `--mail`: null MX, hosts deduplicated, two TLSA names per host; `dane` and
  `none` need a Secure path, a bogus MX stops the check; policies re-parsed
  through the codec, more than one versioned record is invalid.
- CSYNC states need a Secure chain at the zone and a Secure CSYNC set;
  `serialBefore` is RFC 1982; an empty or unknown bitmap indexes nothing.
- Bootstrap: only under `InsecureAt(zone)`, in-zone nameservers skipped, every
  signal Secure, "missing" needs a signed denial, names over 255 refused.
- SERVFAIL diagnosis: one CD=1 `Recheck` per resolver that failed, on its own
  slot; never in dnstree-web.
- UDP replies are copied out of the pooled buffer before `Unpack`.
- `trace/propagation.go` is arithmetic on recorded TTLs (RFC 2308 negative
  TTL); keys and DS only from Secure verdicts.
- SVCB/HTTPS, TLSA, DNSKEY, DS and MX sets sort canonically in the codec; SPF
  `\DDD` refuses values past 255.
- rdap: redirects only to https and at most 3; bootstrap URLs https with a
  host; the domain through `ldh()`; body capped at 1 MiB; ctx plus a 10 s
  client timeout; lists and strings capped; every string through
  `Registration.Shown`; in `apart`; skipped under `--from`; not in dnstree-web.
- `Trace.Shown` covers `Mail`, `ServicePath`, `Registration`, `Propagation`,
  `Check`, `About`, `CSYNC`, `Bootstrap` and `Resolver.Unchecked`; a hostile
  value in each of the golden's string leaves reached no renderer raw and
  nothing above 127 in ascii; a fuzz of `Read` and every renderer found no
  panic.
- `read.go` validates the new enums (`Failure`, `DANEState`, `PolicyFound`,
  `CSYNCState`, `BootstrapState`, `SignalingState`, `RegistrationState`,
  `Area`, `Grade`), SVCB addresses, `registered`/`expires` and the mail shape.
- History reads only within the cache (`OpenRoot`), non-blocking and only a
  regular file (`TestLoadIgnoresAFIFO`), names `[a-z0-9.-]`, capped at 1 MiB;
  `Save` renames over a planted link.
- `ordered()` covers AVC, RESINFO, WALLET, CLA and CSYNC too
  (`TestOrderedByItsOctets`).
- `read.go` errors quote every name from the file (`TestReadRefuses` checks
  each error for control bytes).
- TLSA data has to be as long as its matching type for the record to count.
- `TestTraceShownEveryField` fills every string kind; only the enums
  `read.go` checks are let through raw (`readChecked`).
- dnstree-web: a panicking walk releases its slot once, drops `inFlight`,
  stores nothing and answers 500; `Mail`, `SVCB`, `CheckDS`, `CheckNS`, rdap,
  propagation, check and the comparison never reach it.
- `--spf` grace (re-checked at `9ba8ec7`): the goroutine always sends, `ask` stops on ctx, the grace
  cancels with `DeadlineExceeded`.
- File of defaults: `pcap`, `against` and the earlier list refused; `rdap` is
  settable on purpose and writes nothing.
- SPF budget and recursion: depth is bounded by the query budget, a policy by
  512 terms, so the tree holds at most 513 terms per query; `trace.Shown`
  escapes every byte outside printable ASCII, bidi controls included.
- SPF terms part on a space alone, mechanism names fold ASCII letters only,
  and a domain-spec holds printable ASCII, macros as RFC 7208 7.1 writes them
  and, without one, labels of 1 to 63 octets in at most 253 (`TestCheck`).
