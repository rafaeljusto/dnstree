---
name: dnstree-audit
description: Security and bug audit of dnstree — hostile DNS responses, resolver termination, DNSSEC validation integrity, resource leaks, races, and output injection — reported as verified findings with severity, location, a reproducing scenario and a fix. Use when asked to audit, security review, bug hunt or threat-model the repository or one of its packages. Takes an optional scope (a package path, an area name: wire, resolver, dnssec, transport, output, disk, concurrency, or `full` to ignore the coverage ledger and redo everything).
---

# dnstree audit

You are auditing an iterative DNS resolver and tracer as a Go systems engineer
and DNS security researcher (RFC 1035, 2181, 4034/4035, 5155, 6840, 9715).
Read `AGENTS.md` first: its invariants are the contract, and breaking one is a
finding even when nothing crashes.

## Threat model

- **The attacker is any server the walk talks to.** Every authoritative server
  on the path, every server a referral names, and anyone who can spoof or
  rewrite a UDP answer. They control every byte after the question.
- **The user runs the CLI** and reads its output in a terminal, a browser
  (`--web`), a JSON consumer or a Graphviz file. Record data is attacker text.
- **Scripts trust the exit codes** (0/1/2/3). A wrong one is a security bug:
  `secure` or `insecure` where `bogus` belongs is a validation bypass.
- `internal/testutil/fakens` is test code. Its bugs are Low at most, unless
  they hide a real bug by making a test pass for the wrong reason.

## Ground truth about the code

- The wire codec is `codeberg.org/miekg/dns` **v2**, not hand-rolled. Don't
  report compression-pointer loops or length-field overflows inside the library
  unless you reproduce one against the pinned version in `go.mod`. What to audit
  is *our* use of what it hands back: an `Unpack` that was never called (EDNS0
  reads as zero), unchecked type assertions on `dns.RR`, indexing `[0]` into
  sections, labels or rdata slices that can be empty, `nil` OPT, and trusting
  counts, owners or classes the library does not check.
- The codec does not escape names (see AGENTS.md). Any other belief about what
  it does is checked with a pack and unpack round trip before a finding, a
  fix or a comment rests on it.
- Only `transport`, `resolver`, `dnssec` and `fakens` may import the codec. An
  import anywhere else is a layering finding.
- Budgets live in `internal/resolver/budget.go`. Find every loop or recursion
  that follows data from a response and check that it spends from a budget.
- Look at the `hostile_test.go` files and `fakens.Behaviour` before reporting:
  if a scenario is already tested and passes, it isn't a finding.

## Start from the last audit

[`coverage.md`](coverage.md) is the ledger: the commit the last audit ran at,
the findings still open, and what was checked and found sound. Read it first.

1. **The commits since then come first.** `git log <commit>..HEAD`, and read
   every diff in full. A fix for an earlier finding is the likeliest place for
   the next one: try the same attack one step to the side — the same record
   forged another way, the same text through another sink, the check moved
   ahead of the one it depended on.
2. **Then the open findings**: is each still reproducible, or fixed for real?
3. **Then the areas below**, skipping a sound item whose files no commit since
   has touched.

With no scope, that is the whole audit. `full` ignores the ledger and works
through every area. Without a ledger, audit everything.

The audit is done when a run finds nothing Critical or High and nothing has
changed since. Say so plainly; the next run then only has commits to look at.

## Areas

Work through them in this order unless the scope names one.

1. **wire: what a response can make us do.** `internal/resolver`
   (`classify.go`, `records`, `soa`, `service`, `cnameTarget`, `signerOf`),
   `internal/transport` (EDNS0, NSID, ECS and extended errors), `internal/dnssec`.
   Look for panics from empty or oversized sections, wrong-type records in a
   section, zero-label or root owners, huge TXT/SVCB/NSEC bitmaps, mismatched
   QNAME/ID/class in the reply, and integer conversions (`uint8`/`uint16` label
   counts, TTLs, sizes).
2. **resolver: termination and path integrity.** Referral loops, and referrals
   that go sideways or up. CNAME and DNAME cycles. Nameserver-name side walks
   that recurse into each other. Glue and bailiwick: judged against the zone
   the *answering* server serves (see AGENTS.md; narrowing it is also a bug).
   Cache poisoning across side walks. `--all` fan-out that can outspend the
   budget. TC handling, TCP fallback and EDNS0/FORMERR retries staying inside
   one hop. Every failure has to become a step, never an abort.
3. **dnssec: never claims more than it checked.** RRSIG validity windows,
   signer name versus zone, labels field versus owner (wildcard expansion),
   key tag collisions (several keys with one tag must all be tried),
   DS digest types, and the algorithm set (unknown means `indeterminate`, not
   `bogus`, and not `secure` either — but only for a record whose signature was
   checked first). NSEC/NSEC3 denial: canonical ordering, wrap-around at the
   zone apex, opt-out, NSEC3 iteration caps (RFC 9276, which is also a
   CPU-exhaustion vector), closest encloser, type bitmaps, and the
   insecure-delegation proof, which for opt-out needs the closest encloser
   proof too (RFC 5155 8.9), not just a span covering the delegation. Any path where a missing record is taken as proof
   of something breaks an invariant.
4. **transport: resources and cancellation.** Conns closed on every path,
   deadlines set from `ctx`, DoH response bodies bounded (`io.LimitReader`) and
   status or content-type checked, TLS verification actually tied to the server
   name, TCP length prefix honoured, and a reply read against the query that
   was sent.
5. **output: attacker text reaching the user.** ANSI and control bytes in
   record data or NSID in the tree and live renderers (terminal injection,
   cursor movement that forges lines). HTML and JS injection in
   `internal/render/web` (payload embedding, `</script>` breakout), and what the
   local server binds to and accepts (Host header, DNS rebinding, any origin).
   DOT label escaping. `--format ascii` staying below codepoint 128. Width
   counting on hostile runes.
6. **disk: `internal/history`.** File names built from the question (path
   traversal, separators, case, IDNs), permissions, atomic writes, and a
   corrupt or hostile cache file being read back.
7. **concurrency.** `run.attach` from any goroutine other than the walk's,
   `Config.Asking` or the live tail reading the trace, AS lookups outliving the
   run, goroutines left blocked after ctx is cancelled, and shared state in
   `fakens`.

`internal/asn`, `internal/recursive`, `internal/cli` and `cmd/` are in scope too,
at lower priority: config file parsing, and AS lookups that must never fail or
stall a resolution.

## Method

- For a whole-repo audit, if your agent can run subagents, give areas 1–3 to
  one and areas 4–7 to another, in parallel. Tell each the threat model and the
  ground truth above. Then verify what comes back yourself: subagents
  over-report.
- **A finding has to be reproduced.** Prefer a `fakens` scenario or a
  unit test that feeds the crafted `dns.Msg` or RR. Put it in a temporary
  `zz_audit_<topic>_test.go` in the package, run it with
  `go test -race -run <Name> ./internal/<pkg>/`, include the code in the report,
  then delete the file. Anything you could not reproduce is marked
  **Unverified** and can be at most Low.
- After you touch concurrent code or fakens, run `go test -race -count=2 ./...`.
  Both races this repository has had only showed up on the second run.
- Don't use `make live` or the real internet to build a PoC.
- Don't fix anything unless asked. Don't commit. The ledger is the one file an
  audit writes.
- A fix for a finding goes through the `dnstree-review` skill before it lands.

## Severity

- **Critical**: attacker-controlled validation bypass (`secure` for forged
  data, or an exit code other than 3 for a broken chain), or code execution or
  file write outside the history directory.
- **High**: a crafted response crashes the process or hangs it past the budget
  and timeouts. Terminal or HTML injection that can forge output.
- **Medium**: resource exhaustion bounded only by the timeouts, a leak across
  many hops, a race detector hit, or a wrong but non-security verdict
  (`bogus` where `indeterminate` is right).
- **Low**: a hardening gap with no demonstrated trigger, fakens-only bugs, or
  unverified suspicions.
- **Informational**: invariant drift or layering violations with no impact yet.

## Report

No findings is a complete result. When nothing reproduces, say so in one line
with the commit, give the checked-and-sound list, and stop. Don't lower the bar,
stretch a severity or promote an Unverified suspicion to fill the table.

Otherwise open with a table ordered by severity: severity, one-line title,
location.
Then one block per finding:

- **Severity**: Critical / High / Medium / Low / Informational (plus
  *Unverified* when it applies)
- **Category**: Buffer Safety / Protocol Logic / Resource Leak / Security
  Bypass / Output Injection / Concurrency / Invariant
- **Location**: [file.go:L123](internal/pkg/file.go#L123), with a link for each
  place involved
- **Description**: what breaks and why, naming the AGENTS.md invariant if one
  is broken
- **Malicious input scenario**: what the hostile server sends, as a concrete
  message or `fakens` setup, then the reproducing test and its output
- **Remediation**: the fix as a Go diff, using the stdlib and the existing
  dependency. No new dependencies. Point to the test that should stay.

End with what you checked and found sound, one line each. Keep it plain. Don't
pad it with generic advice that isn't tied to a line of this code.

Then rewrite [`coverage.md`](coverage.md) in the same shape it has: the commit
audited, the date and scope, the open findings (one line each, with location),
and the sound list. A finding that has been fixed leaves the ledger once the
reproducing test has been kept in the tree. A sound item whose files changed
is re-checked before it stays.
