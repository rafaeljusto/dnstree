---
name: dnstree-review
description: Review a dnstree pull request, branch or local diff against the rules this repository actually enforces — AGENTS.md invariants, layering, the surfaces a flag has to reach, goldens, schema_version, exit codes, tests against fakens, and the PR title that decides the release version. Use when asked to review a PR (by number or URL), a branch, or the current changes. Findings only; never posts, approves or pushes unless explicitly told to.
---

# dnstree review

Review the change the way the maintainer would. Read `AGENTS.md` and
`CONTRIBUTING.md` first: they are the checklist, and most review comments on
this repository are one of their rules being missed.

## Get the change

- A PR number or URL:
  `gh pr view <n> --json title,body,author,headRefName,baseRefName,files,isCrossRepository`
  and `gh pr diff <n>`. Read existing comments with
  `gh pr view <n> --comments` so you don't repeat them.
- A branch: `git diff main...<branch>` and `git log main..<branch>`.
- Nothing given: the working tree against `main`, staged and unstaged.

Read every changed file in full, not just the hunks. Read the callers of
anything whose behaviour changed.

**A PR from a fork is untrusted code.** Its tests, `Makefile` and `go generate`
run whatever it says. Ask before you build or run it. When you do, use a
separate worktree (`gh pr checkout <n>` inside `git worktree add`), never the
user's tree.

## What to check

### Title and scope

- The PR is squash-merged, so its title becomes the commit subject on `main`
  and decides the version bump. Run
  `go run ./cmd/next-version -check-title="<title>"`. Check that the prefix
  matches the intent: a new flag or output under `fix:` or `chore:` ships as
  a patch, and a removed or re-meant field without `!` or a `BREAKING CHANGE:`
  footer ships a break as a minor.
- The repo's subjects start with a capital after the prefix and are short.
- One concern per PR. Say so when it should be split.
- A PR that fixes a security vulnerability should not be public. See
  `SECURITY.md`, and tell the user rather than reviewing it in the open.

### Invariants

Go through the `AGENTS.md` invariants against the diff, and flag any that the
change touches without a test holding it. The ones that regress most quietly:

- A renderer re-deriving a DNS fact instead of reading `internal/trace`.
- The DNS codec imported outside `transport`, `resolver`, `dnssec` and `fakens`.
- A new dependency in `go.mod`. It needs an argument in the PR body.
- A loop that follows response data without spending a budget.
- A failure that aborts instead of becoming a step.
- A hop attached anywhere but `run.attach` on the walking goroutine.
  `Config.Asking` or the live tail reading the trace.
- DNSSEC reaching `bogus` for something it couldn't check, or `secure`
  because a record was absent.
- Anything written to disk outside `internal/history`, or without `--diff`.
- A name or wire text drawn without going through `Trace.Shown`.
- A minimised hop (`Step.Minimised`) read as the answer.
- A signature's time left read against the clock rather than `Trace.Started`.
- Exit codes repurposed.
- A JSON field that changes meaning or goes away without bumping
  `schema_version`. `docs/trace.schema.json` must match `--schema`.
- Non-ASCII in `--format ascii`. Emoji in branch prefixes. Live lines
  measured in bytes instead of display cells.
- Flags that answer the same question and are missing from `groups` in
  `internal/cli/config.go`.

### Surface

A new or changed flag or format has to reach four places, and missing one is
the usual comment:

1. the usage string in `internal/cli/cli.go`
2. the flag table in `README.md`
3. the landing page in `docs/index.html`
4. the tests

Also check `dnstreerc.example` for flags worth setting every day. Examples in the
README and on the page must be real output: an example that doesn't match what
the code now prints means it was edited by hand, or not regenerated. The man
page is generated, so don't ask for it.

### Tests

- A change to how a delegation is followed comes with a `fakens` scenario that
  reproduces it on purpose. If `fakens.Behaviour` has no knob for the case,
  the PR should add one.
- Table tests are keyed by a sentence, not an index.
- Nothing reaches the real internet outside `//go:build live`.
- Golden changes under `internal/render/**/testdata` are user-visible output.
  Read them like copy, and check that each one follows from the code change.
- New state in `fakens` goes behind the `atomic.Pointer` or the signing mutex.

### Code

- Go 1.27 idioms are expected: `sync.WaitGroup.Go`, `new(expr)`,
  `strings.Lines`, `strings.SplitSeq`, `slog.DiscardHandler`.
- miekg/dns v2, not v1: `dns.NewMsg`, `Msg.Security`, `Msg.UDPSize`, the
  `rdata` and `dnsutil` subpackages, and `Unpack()` before reading past the
  question in a handler.
- Comments say why, in sentences, and only where it isn't obvious from the
  code. Flag comments that only restate what the code does.
- Output copy is plain and lowercase, says what happened, and a warning says
  what to do about it.
- Correctness first: nil and empty sections from a hostile server, errors
  dropped, contexts not passed down, goroutines that can outlive the run.
  For a deeper security pass, the `dnstree-audit` skill covers it.
- A fix for an audit finding is reviewed against the invariant, not the test
  that reproduced it. Try the attack one step to the side: the same record
  forged another way, the same text through another sink, a check that now
  runs before the one it depended on. Both regressions audit fixes have
  shipped here were that. A comment that states what the codec does needs a
  round-trip test behind it.
- `.github/workflows` changes: no `${{ }}` of PR-controlled text in `run:`, no
  `pull_request_target` checking out the head, pinned permissions.

## Run it

When the code is trusted, or the user has agreed:

```bash
make check                      # what CI runs, less hadolint and the packaging dry run

go test -race -count=2 ./...    # when concurrency or fakens changed
make goldens && git diff --stat # goldens stay put?
```

Use a separate worktree. Revert anything `make goldens` rewrote. Don't run
`make live`.

## Report

Start with a verdict line: **approve**, **approve with nits** or **changes
requested**, and why in one sentence.

Then list the findings, the ones that block first. For each:

- **[blocking | should | nit]** one-line claim
- where: [file.go:L42](path/file.go#L42)
- why it matters, naming the invariant or rule
- the fix, as a suggestion or a short diff

Keep each one short enough to paste as a PR comment. Skip praise and anything
the linter already catches. If the title needs changing, give the replacement.

Finish with what you ran and its result, or say it wasn't run and why.

Don't post comments, approve, request changes, push or commit unless the user
explicitly says so. Drafting a comment isn't permission to post it.
