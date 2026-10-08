# Working on dnstree

dnstree resolves a name the way a resolver does — one hop at a time from the
root servers down — and draws the path it took. This file records the decisions
and behaviours that the source does not state on its own. [README.md](README.md)
says what the tool does; [CONTRIBUTING.md](CONTRIBUTING.md) covers branching,
pull requests and the commit prefixes that decide the version.

## Skills

The repository ships its own skills in `.agents/skills/` (linked from
`.claude/skills/`): `dnstree-commit`, `dnstree-review`, `dnstree-audit`,
`dnstree-docs`, `dnstree-e2e` and `dnstree-modernise`. When one of them covers the task, use it
over a general-purpose skill that does something similar: they know the rules
this file sets down, and the others do not.

`packaging/plugin/skills/dnstree` is not one of them: it ships to users, and
teaches their models to run the tool, not to work on it.

## Before handing work back

```bash
make check   # build, go vet, golangci-lint, go test -race ./..., the pages' tests under node, govulncheck
```

That is what CI runs, less hadolint (`make lint-docker`), the packaging dry
run (`make dist` and `make web-lambda`) and the two image builds. Two things it does not run:

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
nothing, beyond naming the latest release in the page's package lines, so the
copy is in the tree and a test fails when it and `--schema`
have drifted apart.

## Releasing

`make dist` builds everything but the images and the Lambda zip: the archives, a Debian, RPM and
Alpine package per Linux architecture, the Homebrew formula and the checksums
over all of them. It is the same target the release workflow runs, so what ships
can be reproduced without a runner. The two images come from `make image-push
image-web-push`, in a job of their own. [`packaging/README.md`](packaging/README.md) says
how the pieces fit; `nfpm`, like golangci-lint, comes from the PATH or is
fetched at the version the Makefile pins, and is not a dependency of the module.
The Lambda zip comes from `make web-lambda`, and nothing publishes it.

## Do not commit

The maintainer reviews and signs every commit. Write the message, print it, and
stop — no `git commit`, `git push` or `git tag`. Releases are cut by a workflow
that reads the commit subjects since the last tag and works out the version;
tagging by hand skips the calculation, and the tag carries no changelog.
`dnstree-commit` writes the messages with the prefixes that workflow reads.

## Layering

- `internal/trace` is the model. The resolver writes it; every renderer only
  reads it. A renderer that re-derives a DNS fact, rather than drawing what the
  walk recorded, is a bug waiting for the two to disagree.
- Only `transport`, `resolver` and `dnssec` — plus `fakens`, which has to speak
  the wire format — may import the DNS codec. Keeping it out of the trace, the
  renderers and the AS lookups is what makes them testable without a network.
  `internal/layering` fails on any other import of it, and on the trace, the
  renderers, explain, expect, history, the capture, the AS lookups, the SPF
  check, the registry lookup or the TLSA check reaching it through another
  package.
- `cmd/dnstree` wires things together and owns nothing.
- Three dependencies, on purpose: the DNS codec, `golang.org/x/sys` for the
  terminal size, and `golang.org/x/net` for names typed in any script
  (`idna`), which the codec leaves to its callers, and for the organisational
  domain DMARC falls back to (`publicsuffix`, whose list is as old as the
  pinned version). Adding a fourth needs an argument.

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
- **A signed response is checked against the zone its signer names.** A server
  serving both sides of a cut it never referred the walk across answers, and
  refers, with the child's keys. The chain crosses into the signer's zone first,
  with its DS asked of the same server and proved like any other, and only for a
  signer between the answering zone and the name. Checked against the zone the
  walk was referred to, every delegation below `net.br.` came out bogus.
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
- **Nothing reaches the disk unless `--diff` or `--pcap` asks for it.**
  `internal/history` is the only writer of the cache: it keeps one file per
  question, and the file names what was looked up and when. `--pcap` writes
  the one file it is named, and the file of defaults cannot name one. A capture
  is rebuilt, never sniffed: it holds plain DNS only, so it refuses `--dot` and
  `--doh` rather than misrepresent TLS. A cache that cannot be read or written costs the
  comparison and says so in one line, never the resolution. What the file does
  not carry cannot be compared, which is what keeps a comparison from claiming
  to have watched something no walk recorded.
- **dnstree-web runs walks for strangers.** Every transport it hands the
  resolver goes through `transport.Guard` with `transport.Public`, and every
  other resolver option stays at zero, so a new flag reaches the service only
  on purpose. Redirects are rebuilt from the checked view, name and type, never
  from the path asked, and a forwarded client address is the header's last
  entry.
- **The AS lookups are best effort.** They start as the walk discovers each
  server, are waited on briefly after it, and never fail a resolution. When they
  come back empty they say in one line which of the two things went wrong: the
  lookups could not get through, or they ran out of time.
- **`--rdap` and `--tlsa` are the only requests that are not DNS.** `--rdap`
  goes over HTTPS to the services IANA's bootstrap file names, refuses a
  redirect off HTTPS and reads a bounded answer. `--tlsa` connects on port 25
  only to the addresses DNSSEC proved for the MX hosts DANE covers, with a
  timeout and a bound on what it reads. Both are best effort like the AS
  lookups: what cannot be asked costs the check, in one line, never the walk,
  and an address that cannot be reached is never a mismatch. dnstree-web
  imports neither, and `internal/layering` fails if it comes to.
- **The file of defaults is parsed as arguments, ahead of the command line.**
  A flag added to the flag set works in the file without being written out a
  second time, and the command line wins by being read last. Flags that answer
  the same question in different ways — the family, the transport — are listed
  in `groups` in `internal/cli/config.go`, so naming one on the command line
  replaces what the file chose instead of colliding with it.
- **Exit codes are a contract**: 0 an answer, 1 the command line, 2 no answer,
  3 a broken chain of trust, 4 an `--expect` that did not hold. Scripts read them; do not repurpose one.
  A run of several walks exits with the worst of them, ranked 3, 2, 4, 0 — not
  the highest number.
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
draws the copy `Trace.Shown` makes of it.

The codec sorts the trailing value of CAA, URI and NULL records shortest first,
TXT records, and the types built on them (AVC, RESINFO, WALLET, CLA), by how
many strings they hold, text by its escaped form, and CSYNC by the types its
bitmap lists, rather than by octet, so those sets, and HINFO and the other
types of text alone, are verified, and signed in fakens, in the RFC 3597
generic form. NAPTR and HIP compare text the same way but hold names, which
that form would not lowercase, so they are left as they are. A new type with a trailing variable field or text
needs the same check. Check any other belief about what the codec does with a pack and unpack
round trip before building on it.

Go 1.27 is the baseline, and the code uses it: `sync.WaitGroup.Go`,
`slog.DiscardHandler`, `new(expr)`, `strings.Lines` and `strings.SplitSeq`.

## Tests

- The engine is tested offline against in-process authoritative servers
  (`internal/testutil/fakens`), signed hierarchies included. `fakens.Behaviour`
  has a knob for each way a server misbehaves — silence, REFUSED, lameness,
  truncation, FORMERR on EDNS0, latency, out-of-bailiwick glue, six ways to
  break a chain of trust, signatures near expiry, NXDOMAIN for an empty
  non-terminal, SERVFAIL for a single type, broken cookies and CDS, eight ways
  to mishandle EDNS (RFC 8906), and zone transfers and recursion open to
  strangers or reset. A change to the way a delegation is followed belongs
  with a scenario that reproduces it on purpose.
- Tests against the real internet go behind `//go:build live`.
- What a zone or a stranger wrote and is parsed or escaped by hand is fuzzed
  against a property, not an example: the SPF check, a saved walk read into
  every renderer, the live line cut, the escaper of each format, and the
  names dnstree-web redirects to. `make check` replays the seeds and the
  inputs kept under `testdata/fuzz`; `make fuzz` searches. An input a search
  finds stays in `testdata/fuzz` once it is fixed.
- The pages' logic lives in `walk.js` beside each page (and `space.js`,
  `pack.js` and `film.js` beside the scene), which touch neither the DOM nor
  WebGL; the page scripts only draw what those return. `internal/render/web/jstest` tests them
  with node's own runner and the JSON golden as the walk, and there is no
  `package.json`: the tests import nothing node does not ship. A new module
  goes in the file list in `internal/render/web/web.go`, or
  `TestImportsAreServed` fails.
- Table tests are keyed by a sentence that says what the case is, not by index.
- `fakens` replaces its zone whole through an `atomic.Pointer`, serialises
  signing behind a mutex and signs copies of the zone's records, because
  handlers run concurrently and the library writes to the records it signs.
  New state in there needs the same care.

## Keeping the surface in sync

A new flag or format shows up in four places, and missing one is the usual
review comment: the usage string in `internal/cli/cli.go`, the flag table in
`README.md`, the landing page in `docs/` (published by the pages workflow), and
the tests. A flag that needs more than a row is explained in `docs/guide/`, and
its row links there. Every example in the README, the guide and on the page is
real output, pasted from an actual run — regenerate it rather than editing it by
hand.

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

The plugin's skill is held the same way: `TestSkillFlagsExist` fails on a flag
it names that the usage does not, and `TestSkillCommandsParse` parses every
command it shows. A flag that answers a question users bring to a model belongs
in its table.

## Style

- Comments explain why, in sentences, and only where the reason is not on the
  page. The code already says what.
- Output copy is plain and lowercase: it names what happened instead of
  apologising for it, and a warning says what to do about it.
- Commit messages are short. So are the comments.
