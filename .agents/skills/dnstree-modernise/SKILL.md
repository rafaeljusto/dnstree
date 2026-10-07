---
name: dnstree-modernise
description: Go over dnstree as an experienced Go engineer who knows Go 1.27 and refactor what would be more elegant, faster or simpler to extend — modern idioms, duplication, awkward seams, allocations on hot paths — without changing a byte of what the tool prints. Applies the behaviour-preserving changes, proposes the larger ones, then runs dnstree-review on the result and fixes what it finds. Use when asked to modernise, refactor, tidy, clean up or speed up the code, or "/dnstree-modernise". Takes an optional scope (a package path, or an area: idioms, design, perf, tests). Never commits, pushes or tags.
---

# dnstree modernise

> As an experienced Go developer and software engineer, with the knowledge of
> the latest Go 1.27 features, would you change or refactor something in this
> tool to make it more elegant, faster or more flexible?

Answer that question with changes, not an essay. Read `AGENTS.md` first: an
invariant outranks elegance every time, and a refactor that breaks one is a
regression however nice it reads.

## Hard rules

- **Never `git commit`, `git push` or `git tag`.** The last step prints
  messages; the maintainer applies them.
- Start from a clean tree. If `git status --short` shows changes, stop and ask.
- **Output does not move.** No golden under `internal/render/**/testdata`, no
  `docs/trace.schema.json`, no exit code and no line of copy changes. A
  refactor that needs one to change is a feature or a fix, and is proposed,
  not applied.
- No new dependency in `go.mod`, and no dependency bump. Tools run with
  `go run pkg@version` are fine; they are not dependencies of the module.
- Layering stays as `AGENTS.md` sets it: the DNS codec only in `transport`,
  `resolver`, `dnssec` and `fakens`; renderers read the trace and derive
  nothing.
- No churn. A change has to earn its diff: less code, a clearer seam, a
  measured gain, or an idiom the rest of the tree already uses. Renaming for
  taste, reordering, and abstractions with one caller are not changes.
- Leave the code under an open finding in the audit ledger
  (`../dnstree-audit/coverage.md`) alone. Refactoring it either fixes the
  finding, which is a `fix:` with its own test, or moves it out from under
  the ledger's link. Name the finding in the report if it got in the way.
- Read [`decisions.md`](decisions.md) before proposing anything. What it
  records as declined stays declined unless the code under it has changed.

## 1. Know what the toolchain offers

Work from the installed Go, not from memory:

```bash
go version                                  # must be the go.mod baseline or newer
cat "$(go env GOROOT)/api/go1.27.txt"       # every API added in 1.27
cat "$(go env GOROOT)/api/go1.26.txt"       # and in 1.26
go tool fix help                            # the modernizers this toolchain ships
go fix -diff ./...                          # what they would rewrite today
```

`go fix -diff` output is the cheapest win: apply it with `go fix ./...`, then
read every hunk, since a fixer can be right about the idiom and wrong about the
intent (an `omitzero` that changes what the JSON prints is an output change).

Then look for what no fixer finds. The ones that pay off in this tree:

- **Iterators.** A function that builds a slice only for its caller to range
  over it once is an `iter.Seq`. Walking a trace's steps, a section's records
  or a zone's labels are the usual places. `slices.Collect`, `maps.Keys` and
  `slices.Sorted(maps.Keys(m))` replace hand-rolled copies.
- **Errors.** `errors.AsType[T]` over `errors.As` with a declared variable;
  `errors.Join` over an error slice formatted by hand.
- **Small helpers.** `cmp.Or` for the first non-zero default, `min`/`max`,
  `slices.IndexFunc`/`ContainsFunc`, `strings.Cut*`, `sync.OnceValue(s)` over a
  `sync.Once` guarding a package variable, `new(expr)` over a temporary taken
  by address.
- **Tests.** `t.Context()`, `b.Loop()`, `testing/synctest` for anything that
  waits on a timer (the live tail, AS lookups, server timeouts) instead of
  real sleeps, `t.Chdir`, `t.ArtifactDir` where a test writes files.
- **`encoding/json/v2`.** Tempting, but it marshals nil slices, HTML and
  field order differently from v1. The JSON output is a contract
  (`schema_version`, the golden, the schema copy). Only propose it with the
  golden unchanged and a reason beyond novelty.

Anything else from the API files is fair game when it removes code here.

## 2. Survey

With no scope, cover every area below. For a whole-repo run, if your agent can
run subagents, split the areas across two or three of them in parallel, give
each the hard rules and step 1's list, and ask for candidates only — no edits.
Verify what comes back yourself: subagents over-report and under-read.

1. **idioms** — step 1, across the tree.
2. **design** — duplication between renderers (`internal/render/*`) that
   belongs on the trace or in a shared helper; functions too long to hold in
   your head (`resolver`, `dnssec` and `cli` are where they grow);
   option structs or flag plumbing that a new flag has to touch in more places
   than the four `AGENTS.md` lists; interfaces with one implementation and no
   test double; exported names nothing outside the package uses.
3. **perf** — the hot paths are the walk (message building, classification,
   signature checks), the renderers on large traces, and the live redraw.
   Look for allocations in loops, repeated `strings.ToLower` or
   `dnsutil` canonicalisation of the same name, maps rebuilt per call,
   `fmt.Sprintf` where `strconv` or `strings.Builder` does, and regexps
   compiled per call. Network time dwarfs CPU in a real walk, so a perf change
   has to show up in a benchmark, not in a guess.
4. **tests** — helpers repeated across packages that belong in
   `internal/testutil`, table tests keyed by index, sleeps that
   `synctest` removes, fakens setups copied rather than shared.

For each candidate note: where, what changes, why it is better (fewer lines,
fewer allocations, one place instead of three), and the risk. Drop anything
whose answer to "why" is taste.

## 3. Decide what to apply

Sort the candidates into two piles:

- **Apply**: behaviour-preserving, contained to a package or a mechanical
  sweep, covered by existing tests.
- **Propose**: changes an exported API across packages, moves files, touches
  an invariant's code path (`run.attach`, budgets, bailiwick, the DNSSEC
  verdicts, `transport.Guard`), needs a golden to move, or is larger than a
  reviewer would read in one sitting. These go in the report with a sketch,
  and are only applied when the maintainer says so.

If the apply pile is empty, say so and go to the report. A tree that is
already in good shape is a result, not a reason to find something.

## 4. Apply

One theme at a time — all the `errors.AsType`, then the iterators, then a
single design change — so each lands as its own commit later.

After each theme:

```bash
go build ./... && go vet ./...
go test -race ./<packages touched>/...
```

For a perf change, write the benchmark first, against the current code, and
keep it in the tree:

```bash
go test -run '^$' -bench <Name> -benchmem -count 10 ./internal/<pkg>/ > old.txt
# apply the change
go test -run '^$' -bench <Name> -benchmem -count 10 ./internal/<pkg>/ > new.txt
go run golang.org/x/perf/cmd/benchstat@latest old.txt new.txt
```

Keep the change only if benchstat shows a significant gain in time or
allocations and the code is no worse to read. Put the files in the scratch
directory, not the repository, and quote the benchstat lines in the report.

Comments follow `AGENTS.md`: why, in a sentence, only where the code doesn't
say it. A refactor usually removes comments rather than adding them.

## 5. Verify

```bash
make check                                   # what CI runs
make goldens && git diff --exit-code -- internal/render docs/trace.schema.json
```

The second line must come back clean: a golden that moved means the refactor
changed output. Find out why and undo it, don't keep the new golden.

When anything concurrent or in `internal/testutil/fakens` changed, also run
`go test -race -count=2 ./...` — both races this repository has had only
showed up on the second run. Don't run `make live`.

## 6. Review

Invoke the `dnstree-review` skill on the working tree, and tell it step 5 has
run there: its separate worktree starts from HEAD and would test none of
these changes. Then:

- Fix every **blocking** and **should** finding, or drop the change it is
  about. Fix a **nit** when it is a line; leave it in the report otherwise.
- Re-run step 5, then `dnstree-review` again on what changed.
- Stop after three rounds. If review is still not **approve** or **approve
  with nits**, revert the theme that keeps failing and report it as a
  proposal instead.

## 7. Report

Nothing to change is a complete result. When the survey turns up nothing
worth its diff, say so in one line with the commit, list what was looked at
and found fine, one line each, and stop: no proposals, no commit messages.
Don't lower the bar or dress up taste as a proposal to fill the report.

Otherwise open with one line: how many themes applied, how many proposed, and whether
`make check` and the goldens are clean.

Then:

- **Applied** — one block per theme: what changed and why it is better, the
  files (as links), and the benchstat lines for a perf change.
- **Proposed** — one block per proposal: the problem in the code today, the
  sketch of the change, what it would touch, and the risk. Short enough to
  turn into an issue.
- **Review** — the final verdict from `dnstree-review` and any nits left.

Append to [`decisions.md`](decisions.md) whatever the maintainer declines, one
line each with the reason, so the next run does not propose it again. Remove a
line when the code it was about is gone.

When something was applied, finish with the `dnstree-commit` skill: one message per theme, with the
`refactor:`, `perf:` or `test:` prefix its table gives. Print them; don't run
them.
