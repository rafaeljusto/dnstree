# Working on dnstree

dnstree resolves a name the way a resolver does — one hop at a time from the
root servers down — and draws the path it took. This file records the decisions
and behaviours that the source does not state on its own. [README.md](README.md)
says what the tool does; [CONTRIBUTING.md](CONTRIBUTING.md) covers branching,
pull requests and the commit prefixes that decide the version.

## Before handing work back

```bash
make check   # build, go vet, golangci-lint, go test -race ./..., govulncheck
```

That is what CI runs. Two things it does not:

- `make live` goes out to the real root servers. It is never part of `check`;
  CI runs it weekly, because the embedded hints and trust anchors go stale
  silently and nothing else notices.
- `go test -race -count=2 ./...` after touching anything concurrent or anything
  in `internal/testutil/fakens`. Both data races this repository has had only
  showed up on the second run.

Renderer goldens are rewritten with `go test ./internal/render/... -update`.
Read the diff before keeping it: those files are the user-visible output.

## Releasing

`make dist` builds the whole release: the archives, a Debian, RPM and Alpine
package per Linux architecture, the Homebrew formula and the checksums over all
of them. It is the same target the release workflow runs, so what ships can be
reproduced without a runner. [`packaging/README.md`](packaging/README.md) says
how the pieces fit; `nfpm` is fetched at a pinned version, like golangci-lint,
and is not a dependency of the module.

## Do not commit

The maintainer reviews and signs every commit. Write the message, print it, and
stop — no `git commit`, `git push` or `git tag`. Releases are cut by a workflow
that reads the commit subjects since the last tag and works out the version;
tagging by hand skips both the calculation and the changelog.

## Layering

- `internal/trace` is the model. The resolver writes it; every renderer only
  reads it. A renderer that re-derives a DNS fact, rather than drawing what the
  walk recorded, is a bug waiting for the two to disagree.
- Only `transport`, `resolver` and `dnssec` — plus `fakens`, which has to speak
  the wire format — may import the DNS codec. Keeping it out of the trace, the
  renderers and the AS lookups is what makes them testable without a network.
- `cmd/dnstree` wires things together and owns nothing.
- One dependency, on purpose. Adding a second needs an argument.

## Invariants

Each of these has been a bug, or would be a silent regression.

- **Bailiwick is judged against the zone the answering server serves**, not
  against the zone being delegated. That is what lets the root hand out gTLD
  server addresses. Narrowing it strands real delegations — the symptom is a
  walk that never reaches the answer.
- **Every walk ends.** Anything that follows a delegation is bounded by a
  budget, and a hostile or broken zone must not be able to spend more than it.
- **A trace is always drawn.** A failure is a step, not an abort: lame servers,
  timeouts and exhausted budgets are recorded where they happened.
- **Steps join the trace only through `run.attach`, and only from the goroutine
  doing the walking.** The parallel queries `--all` makes are joined before any
  of their hops is attached. `Config.Stepped` watchers read the whole trace
  inside that call, which is safe for exactly that reason; a hop attached from
  anywhere else is a data race against the live drawing.
- **DNSSEC never claims more than it checked.** An algorithm this build does not
  know, or a denial of existence it cannot read, is `indeterminate` — never
  `bogus`. Bogus is exit code 3 and has to keep meaning something.
- **The AS lookups are best effort.** They start as the walk discovers each
  server, are waited on briefly after it, and never fail a resolution. When they
  come back empty they say in one line which of the two things went wrong: the
  lookups could not get through, or they ran out of time.
- **Exit codes are a contract**: 0 an answer, 1 the command line, 2 no answer,
  3 a broken chain of trust. Scripts read them; do not repurpose one.
- **`--format ascii` emits nothing above codepoint 127** — a test asserts it,
  because the format exists for pasting into documents.
- **`schema_version` in the JSON output** is bumped whenever a field changes
  meaning or goes away.
- **Emoji belong in labels, never in branch prefixes.** A two-cell glyph in a
  prefix pulls every line below it out of alignment.
- **Live frames are cut to the terminal width, counting display cells rather
  than bytes**: escapes take no room and an emoji takes two. A line that wrapped
  would occupy two rows, and the next redraw would come up one row short and
  smear the drawing down the terminal. The frames are scratch — they are wiped
  and the finished tree is written where they stood, byte for byte what a run
  without `--live` prints.
- **A live frame is a tree and a tail, and only the tree may read the trace.**
  The tail — the queries in flight and the footer — is redrawn on a timer, from
  a goroutine that never touches the trace the walk is still building; it works
  off the counters `Config.Asking` feeds it and the lines the last `Stepped`
  rendered. A tick goes back over the tail rows alone and leaves the tree where
  it is; a screen that has been resized falls back to a whole frame, since the
  cut and the width every line was drawn to have both just changed.
- **`Config.Asking` is the only thing that says a walk is waiting.** Nothing
  joins the trace until an answer is in, so between one hop and the next
  `Stepped` has nothing to report and a slow server is indistinguishable from a
  hang. The hook returns the function that ends the query; `--all` has several
  out at once, so it is called from several goroutines and may not read the
  trace.

## The DNS library

`codeberg.org/miekg/dns` is the v2 API. Idioms from v1 (`github.com/miekg/dns`)
do not port: messages come from `dns.NewMsg`, the DO bit is `Msg.Security`, the
EDNS0 buffer is `Msg.UDPSize`, record data lives in the `rdata` subpackage, and
the name helpers are in `dnsutil`. A handler is given a message with only the
header and the question unpacked — call `Unpack()` before reading anything else,
or the EDNS0 fields read as zero.

Go 1.27 is the baseline, and the code uses it: `sync.WaitGroup.Go`,
`slog.DiscardHandler`, `new(expr)`, `strings.Lines` and `strings.SplitSeq`.

## Tests

- The engine is tested offline against in-process authoritative servers
  (`internal/testutil/fakens`), signed hierarchies included. `fakens.Behaviour`
  has a knob for each way a server misbehaves — silence, REFUSED, lameness,
  truncation, FORMERR on EDNS0, latency, out-of-bailiwick glue and five ways to
  break a chain of trust. A change to the way a delegation is followed belongs
  with a scenario that reproduces it on purpose.
- Tests against the real internet go behind `//go:build live`.
- Table tests are keyed by a sentence that says what the case is, not by index.
- `fakens` replaces its zone whole through an `atomic.Pointer` and serialises
  signing behind a mutex, because handlers run concurrently and the library
  writes to the records it signs. New state in there needs the same care.

## Keeping the surface in sync

A new flag or format shows up in four places, and missing one is the usual
review comment: the usage string in `internal/cli/cli.go`, the flag table in
`README.md`, the landing page in `docs/` (published by the pages workflow), and
the tests. Every example in the README and on the page is real output, pasted
from an actual run — regenerate it rather than editing it by hand.

The man page is not a fifth place. `cmd/mkman` renders it from `cli.Usage` at
release time, and refuses to render a usage text whose shape it cannot read, so
a flag added to the usage string reaches the packages on its own.

## Style

- Comments explain why, in sentences, and only where the reason is not on the
  page. The code already says what.
- Output copy is plain and lowercase: it names what happened instead of
  apologising for it, and a warning says what to do about it.
- Commit messages are short. So are the comments.
