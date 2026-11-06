# Working on dnstree

dnstree resolves a name the way a resolver does — one hop at a time from the
root servers down — and draws the path it took. This file records the decisions
and behaviours that the source does not state on its own. [README.md](README.md)
says what the tool does; [CONTRIBUTING.md](CONTRIBUTING.md) covers branching,
pull requests and the commit prefixes that decide the version.

## Skills

The `dnstree-*` skills in `.agents/skills/` know the rules this file sets down;
when one covers the task, use it over a general-purpose skill.
`packaging/plugin/skills/dnstree` is not one of them: it ships to users, and
teaches their models to run the tool, not to work on it.

## Before handing work back

`make check` is what CI runs, less hadolint, the packaging dry run and the image
builds. Three things it does not run:

- `make live` goes out to the real root servers. CI runs it weekly, because the
  embedded hints and trust anchors go stale silently.
- `go test -race -count=2 ./...` after touching anything concurrent or anything
  in `internal/testutil/fakens`. Both data races this repository has had only
  showed up on the second run.
- `make fuzz` searches, where `check` only replays. After changing a package a
  fuzz test covers, search it for a minute with
  `FUZZPKG=internal/<pkg> FUZZTIME=1m`.

Renderer goldens, and `docs/trace.schema.json`, are rewritten with
`make goldens`. Read the diff before keeping it: those files are the
user-visible output.

## Releasing and committing

The maintainer reviews and signs every commit. Write the message with
`dnstree-commit`, print it, and stop — no `git commit`, `git push` or `git tag`.
A workflow cuts releases and works out the version from the commit subjects
since the last tag; a tag made by hand skips that and carries no changelog.
`dnstree-release` gets a release ready.

## Layering

- `internal/trace` is the model. The resolver writes it; every renderer only
  reads it. A renderer that re-derives a DNS fact, rather than drawing what the
  walk recorded, is a bug waiting for the two to disagree.
- Only `transport`, `resolver`, `dnssec` and `fakens` import the DNS codec, so
  everything else is testable without a network. `internal/layering` enforces
  it.
- `cmd/dnstree` wires things together and owns nothing.
- The three dependencies in `go.mod` are on purpose; a fourth needs an
  argument. DMARC finds the policy above a name by walking up the tree
  (RFC 9989), not from a public suffix list.

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
  doing the walking.** `--all`'s parallel queries are joined before any hop is
  attached. `Config.Stepped` and the live drawing read the trace inside that
  call; a hop attached from anywhere else is a data race. `Config.Asking` runs
  on several goroutines and never reads the trace.
- **DNSSEC never claims more than it checked.** What this build cannot check —
  an unknown algorithm, an RSA exponent the codec cannot load, a denial it
  cannot compute — is `indeterminate`, never `bogus`, and only for a record the
  zone above signed. An unsigned DS is anyone's, and is `bogus`. Bogus is exit
  code 3 and has to keep meaning something.
- **A signed response is checked against the zone its signer names**, not the
  zone the walk was referred to: one server can serve both sides of a cut. See
  `crossCut` in `internal/resolver/walk.go`. Getting this wrong made every
  delegation below `net.br.` bogus.
- **What a zone does not say is checked like what it does.** An insecure
  delegation, an NXDOMAIN, a NODATA and a wildcard all rest on a proof the zone
  signed, never on an absence: anyone able to drop records can manufacture one.
- **A minimised hop is never the answer.** Under `--qmin` a zone's NODATA or
  NXDOMAIN is about a shorter name. `Step.Minimised` keeps `Trace.Result`, and
  so the exit code, `--expect` and `--diff`, from reading one as the answer.
- **Time is read against `Trace.Started`, never the clock**, so a trace drawn
  again with `--from` says what it said, and the goldens stay still. Under
  `--replay` the capture sets the clock: a new timing goes through `run.since`,
  never `time.Since`. Staleness is a share of a signature's life, not a fixed
  margin.
- **Nothing reaches the disk unless `--diff` or `--pcap` asks for it.**
  `internal/history` is the only writer of the cache. A capture is rebuilt,
  never sniffed, so it refuses `--dot` and `--doh`. A cache that cannot be read
  or written costs the comparison, in one line, never the resolution.
- **dnstree-web runs walks for strangers.** Every transport it hands the
  resolver goes through `transport.Guard` with `transport.Public`, and every
  other resolver option stays at zero, so a new flag reaches the service only
  on purpose. Redirects are rebuilt from the checked view, name and type, never
  from the path asked, and a forwarded client address is the header's last
  entry.
- **Best-effort checks never fail a walk.** The AS lookups, `--rdap` and
  `--tlsa` cost their own check, in one line that says why, and an address that
  cannot be reached is never a mismatch. `--rdap` and `--tlsa` are the only
  requests that are not DNS: HTTPS only, bounded reads, and `--tlsa` connects
  only to public addresses DNSSEC proved. dnstree-web imports neither.
- **The file of defaults is parsed as arguments, ahead of the command line**,
  so a new flag works there for free. Flags that answer the same question in
  different ways go in `groups` in `internal/cli/config.go`.
- **Exit codes are a contract**: 0 an answer, 1 the command line, 2 no answer,
  3 a broken chain of trust, 4 an `--expect` that did not hold. A run of several
  walks exits with the worst, ranked 3, 2, 4, 0 — not the highest number.
- **A check's own lookups are not the run's.** Walks made for `--mail`,
  `--dkim`, `--deps` and the like start at a step marked `Apart` (`run.look`);
  the chain of trust and the exit code read only `Trace.judged`, so somebody
  else's broken zone never exits 3.
- **`--format ascii` emits nothing above codepoint 127**: it exists for pasting
  into documents.
- **`schema_version` in the JSON output** is bumped whenever a field changes
  meaning or goes away.
- **Emoji belong in labels, never in branch prefixes.** A two-cell glyph in a
  prefix pulls every line below it out of alignment.
- **Live frames are cut to the terminal width in display cells, not bytes.** A
  line that wraps smears the next redraw down the terminal. The finished tree
  is byte for byte what a run without `--live` prints.

## The DNS library

`codeberg.org/miekg/dns` is the v2 API. Idioms from v1 (`github.com/miekg/dns`)
do not port: messages come from `dns.NewMsg`, the DO bit is `Msg.Security`, the
EDNS0 buffer is `Msg.UDPSize`, record data lives in the `rdata` subpackage, and
the name helpers are in `dnsutil`. A handler is given a message with only the
header and the question unpacked — call `Unpack()` before reading anything else,
or the EDNS0 fields read as zero.

Names come back as the raw octets the server sent, unescaped; text rdata comes
back escaped. The trace keeps the octets, which queries and TLS need, and every
renderer draws the escaped copy `Trace.Shown` makes.

The codec sorts some types out of canonical order; `misordered` in
`internal/dnssec/dnssec.go` lists them. Check any other belief about the codec
with a pack and unpack round trip before building on it.

Use Go 1.27 idioms: `sync.WaitGroup.Go`, `new(expr)`, `strings.Lines`,
`strings.SplitSeq`.

## Tests

- The engine is tested offline against `internal/testutil/fakens`, which has a
  `Behaviour` knob for each way a server misbehaves. A change to the way a
  delegation is followed comes with a scenario that reproduces it.
- Tests against the real internet go behind `//go:build live`.
- What a zone or a stranger wrote and is parsed or escaped by hand is fuzzed
  against a property, not an example. An input a search finds stays in
  `testdata/fuzz` once it is fixed.
- The pages' logic lives in the `.js` modules beside each page, which touch
  neither the DOM nor WebGL. `internal/render/web/jstest` tests them with node's
  own runner; there is no `package.json`, so they import only what node ships.
- Table tests are keyed by a sentence that says what the case is, not by index.

## Keeping the surface in sync

A new flag or format shows up in four places, and missing one is the usual
review comment: the usage string in `internal/cli/cli.go`, the flag table in
`README.md`, the landing page in `docs/`, and the tests. A flag that needs more
than a row is explained in `docs/guide/`, and its row links there. Every example
in the README, the guide and on the page is real output, pasted from an actual
run — regenerate it rather than editing it by hand.

The man page is rendered from the usage string. Tests catch a stale flag in
`dnstreerc.example` or the plugin's skill, but not a missing one: a flag worth
setting every day belongs in the example, and one users ask a model about
belongs in the skill's table.

## Style

- Comments explain why, in sentences, and only where the reason is not on the
  page.
- Output copy is plain and lowercase: it names what happened instead of
  apologising for it, and a warning says what to do about it.
- Commit messages and comments are short.
- What an agent writes for people — replies, the reports the skills produce,
  commit messages, PR bodies, discussion posts — is in ASD-STE100 (Simplified
  Technical English), for readers whose first language is not English. Code,
  commands, flags and pasted output stay as they are. This file and the skills
  are not held to it.
