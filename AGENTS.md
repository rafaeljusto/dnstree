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

That is what CI runs, less hadolint (`make lint-docker`) and the packaging dry
run (`make dist`). Two things it does not run:

- `make live` goes out to the real root servers. It is never part of `check`;
  CI runs it weekly, because the embedded hints and trust anchors go stale
  silently and nothing else notices.
- `go test -race -count=2 ./...` after touching anything concurrent or anything
  in `internal/testutil/fakens`. Both data races this repository has had only
  showed up on the second run.

Renderer goldens are rewritten with `make goldens`.
Read the diff before keeping it: those files are the user-visible output. The
same command writes `docs/trace.schema.json`, the copy of the JSON Schema the
pages workflow serves: that workflow uploads what is committed and builds
nothing, so the copy is in the tree and a test fails when it and `--schema`
have drifted apart.

## Releasing

`make dist` builds the whole release: the archives, a Debian, RPM and Alpine
package per Linux architecture, the Homebrew formula and the checksums over all
of them. It is the same target the release workflow runs, so what ships can be
reproduced without a runner. [`packaging/README.md`](packaging/README.md) says
how the pieces fit; `nfpm`, like golangci-lint, comes from the PATH or is
fetched at the version the Makefile pins, and is not a dependency of the module.

## Do not commit

The maintainer reviews and signs every commit. Write the message, print it, and
stop — no `git commit`, `git push` or `git tag`. Releases are cut by a workflow
that reads the commit subjects since the last tag and works out the version;
tagging by hand skips the calculation, and the tag carries no changelog.

## Layering

- `internal/trace` is the model. The resolver writes it; every renderer only
  reads it. A renderer that re-derives a DNS fact, rather than drawing what the
  walk recorded, is a bug waiting for the two to disagree.
- Only `transport`, `resolver` and `dnssec` — plus `fakens`, which has to speak
  the wire format — may import the DNS codec. Keeping it out of the trace, the
  renderers and the AS lookups is what makes them testable without a network.
  `internal/layering` fails on any other import of it.
- `cmd/dnstree` wires things together and owns nothing.
- Two dependencies, on purpose: the DNS codec, and `golang.org/x/sys` for the
  terminal size. Adding a third needs an argument.

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
  know, or a denial of existence it cannot compute, is `indeterminate` — never
  `bogus`. Bogus is exit code 3 and has to keep meaning something. Only a
  record the zone above has signed can earn `indeterminate`: an unsigned DS is
  anyone's, whatever algorithm it names, and is `bogus`.
- **What a zone does not say is checked like what it does.** An insecure
  delegation, an NXDOMAIN, a NODATA and a wildcard all rest on a proof the zone
  signed, never on an absence: an absence is what anyone able to drop records
  from a response can manufacture.
- **A minimised hop is never the answer.** Under `--qmin` a zone is asked about
  a shorter name, and its NODATA or NXDOMAIN is about that name. `Step.Minimised`
  keeps `Trace.Result` — and so the exit code, `--expect` and `--diff` — from
  reading one as the resolution's own.
- **A signature's time left is read against `Trace.Started`, never the clock.**
  That is what makes a trace drawn again with `--from` say what it said when it
  was made, and keeps the goldens still. Staleness is a share of the life a
  signature was made for, not a fixed margin: online signers hand out
  signatures that last a day, fresh every time.
- **Nothing reaches the disk unless `--diff` asks for it.** `internal/history`
  is the only writer, it keeps one file per question, and the file names what
  was looked up and when. A cache that cannot be read or written costs the
  comparison and says so in one line, never the resolution. What the file does
  not carry cannot be compared, which is what keeps a comparison from claiming
  to have watched something no walk recorded.
- **The AS lookups are best effort.** They start as the walk discovers each
  server, are waited on briefly after it, and never fail a resolution. When they
  come back empty they say in one line which of the two things went wrong: the
  lookups could not get through, or they ran out of time.
- **The file of defaults is parsed as arguments, ahead of the command line.**
  A flag added to the flag set works in the file without being written out a
  second time, and the command line wins by being read last. Flags that answer
  the same question in different ways — the family, the transport — are listed
  in `groups` in `internal/cli/config.go`, so naming one on the command line
  replaces what the file chose instead of colliding with it.
- **Exit codes are a contract**: 0 an answer, 1 the command line, 2 no answer,
  3 a broken chain of trust, 4 an `--expect` that did not hold. Scripts read them; do not repurpose one.
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

Names come back as the raw octets the server sent, unescaped: owners and every
name inside rdata (NS, CNAME, MX, SOA, SVCB targets). Text rdata — TXT, CAA,
HINFO, NAPTR, URI, SVCB values — comes back escaped. A name has to be escaped
before it is drawn, but not before it is queried or checked against TLS, which
need the octets themselves: the trace keeps the octets, and every renderer
draws the copy `Trace.Shown` makes of it. Check any other belief about what the codec does
with a pack and unpack round trip before building on it.

Go 1.27 is the baseline, and the code uses it: `sync.WaitGroup.Go`,
`slog.DiscardHandler`, `new(expr)`, `strings.Lines` and `strings.SplitSeq`.

## Tests

- The engine is tested offline against in-process authoritative servers
  (`internal/testutil/fakens`), signed hierarchies included. `fakens.Behaviour`
  has a knob for each way a server misbehaves — silence, REFUSED, lameness,
  truncation, FORMERR on EDNS0, latency, out-of-bailiwick glue, six ways to
  break a chain of trust, signatures near expiry, NXDOMAIN for an empty
  non-terminal, and broken cookies and CDS. A change to the way a delegation is followed belongs
  with a scenario that reproduces it on purpose.
- Tests against the real internet go behind `//go:build live`.
- Table tests are keyed by a sentence that says what the case is, not by index.
- `fakens` replaces its zone whole through an `atomic.Pointer`, serialises
  signing behind a mutex and signs copies of the zone's records, because
  handlers run concurrently and the library writes to the records it signs.
  New state in there needs the same care.

## Keeping the surface in sync

A new flag or format shows up in four places, and missing one is the usual
review comment: the usage string in `internal/cli/cli.go`, the flag table in
`README.md`, the landing page in `docs/` (published by the pages workflow), and
the tests. Every example in the README and on the page is real output, pasted
from an actual run — regenerate it rather than editing it by hand.

The man page is not a fifth place. `cmd/mkman` renders it from `cli.Usage` in
`make man`, which CI's packaging job runs on every pull request, and refuses to
render a usage text whose shape it cannot read, so a flag added to the usage
string reaches the packages on its own.


`dnstreerc.example` is written by hand, but it is not a fifth place either.
`TestExampleParses` reads it as it ships and then reads every run of adjacent
setting lines in it with the comment markers taken off, so a flag that is
renamed or dropped, or an example value that stops being one, fails there. That
is why every setting in the file is written as `name = value` and why settings
that contradict each other are kept apart by a line of prose. What the test
cannot notice is a new flag missing from the file: it is a menu rather than the
surface, and a flag worth setting every day belongs on it.

## Style

- Comments explain why, in sentences, and only where the reason is not on the
  page. The code already says what.
- Output copy is plain and lowercase: it names what happened instead of
  apologising for it, and a warning says what to do about it.
- Commit messages are short. So are the comments.
