---
name: dnstree-docs
description: Review dnstree's documentation as a whole — README, the landing page in docs/index.html, CONTRIBUTING, AGENTS, SECURITY, the packaging and next-version READMEs, install.md, dnstreerc.example and the project skills — against the code and against each other. Finds contradictions, flags or behaviour nobody documented, stale examples, broken links, and prose that is longer than it needs to be. Use when asked to review, audit, proofread or tidy the docs, or before a release. Takes an optional scope (a file, or an area name: flags, examples, install, contributor, page). Findings only; edits nothing unless asked.
---

# dnstree docs review

Review the documentation the way a new user and a new contributor would read
it, and check every claim against the code, which wins. Read `AGENTS.md` first:
its "Keeping the surface in sync" and "Style" sections are the rules the docs
are held to.

## What is in scope

| File | Reader | Holds |
| --- | --- | --- |
| `README.md` | users | the full reference: flag table, one section per feature |
| `docs/index.html` | users | the landing page: the pitch, shorter than the README |
| `dnstreerc.example` | users | a menu of settings worth making every day |
| `packaging/install.md` | users | the install section appended to release notes |
| `SECURITY.md` | users, reporters | supported versions, reporting, what the tool trusts |
| `CONTRIBUTING.md` | contributors | branching, PRs, commit prefixes, testing |
| `AGENTS.md` | agents, maintainers | decisions and invariants the code does not state |
| `packaging/README.md`, `cmd/next-version/README.md` | maintainers | release mechanics |
| `.github/pull_request_template.md` | contributors | what a PR is asked for |
| `.agents/skills/*/SKILL.md` | agents | review and audit checklists |

Out of scope: `CODE_OF_CONDUCT.md`, the man page (rendered from `cli.Usage`),
`docs/trace.schema.json` (a test already holds it to `--schema`) and the page
`--format web` serves, which is output rather than documentation.

## Sources of truth

Check the docs against these, never against each other alone:

- **Flags and defaults**: the `Usage` constant in `internal/cli/cli.go`, and
  the flag set that parses them in the same file.
- **Exit codes**: `cmd/dnstree` and wherever the code it calls picks them.
- **Formats**: the `--format` switch in `internal/cli`, and `internal/render`.
- **What the output looks like**: the goldens under `internal/render/**/testdata`.
- **Build, test and release**: `Makefile`, `.github/workflows/*.yml`, `go.mod`
  (the Go version) and `tapes/` (what the demo recordings type).
- **JSON**: `schema_version` and `--schema`.

## What to check

### 1. Consistency

- Every flag in `Usage` appears in the README flag table with the same meaning
  and default, and every row in the table is a flag that still exists. Start
  with the mechanical pass below, then read the rows against the usage lines.
- Features the page names exist in the README, and the page doesn't promise
  anything the README or the code doesn't. Section counts on the page ("Six
  ways out", "One line, six facts") still match what follows them.
- Exit codes agree everywhere they are listed: README, page, `SECURITY.md`,
  `AGENTS.md`, the skills. A code the binary returns and a list leaves out is a
  finding in the list.
- The install commands agree across the README, `packaging/install.md` and the
  page's "Get it" section: package names, the tap, the container image, the
  `go install` path, and placeholders like `@BARE@` that the release workflow
  fills in.
- `dnstreerc.example` uses real flag names in `name = value` form, and what its
  comments say a setting does matches the usage line.
- Rules that live in two places say the same thing: `CONTRIBUTING.md` and
  `AGENTS.md` on commit prefixes and testing, `next-version/README.md` on how a
  subject becomes a version, the skills on anything `AGENTS.md` states. The
  skills copy invariants, so they drift first.
- Every `make` target, file path, package, test name and workflow a doc names
  exists. Every relative link and `#anchor` resolves, including images, GIFs
  and videos on the page and in the README.
- One spelling throughout. The repository writes British English ("colour",
  "licence", "recognise"), except where it quotes a flag or keyword.

### 2. Missing documentation

- A flag with no README row, or a row with no section where the flag's
  behaviour isn't obvious from one line (anything that changes the exit code,
  writes to disk, opens a port or talks to a third party).
- A behaviour users hit with no mention: the file of defaults and its lookup
  order, `--diff`'s cache location, what `--format web` binds to, environment
  variables the code reads (`grep -rn 'os.Getenv\|LookupEnv' --include=*.go`),
  signals, and what goes to stderr rather than stdout.
- A decision in the code a maintainer would need and `AGENTS.md` doesn't have.
  Only raise one that has bitten or would regress silently: that file is for
  the non-obvious, not for everything.
- A `make` target or workflow a contributor needs that the README's
  "Developing" section or `CONTRIBUTING.md` doesn't mention.
- A new flag worth setting every day that isn't in `dnstreerc.example`. That
  file is a menu, so a missing one-off flag is not a finding.

### 3. Examples

Every example is supposed to be real output pasted from a run (see
`AGENTS.md`). You can't prove that offline, but you can catch the ones that
can't be real any more:

- A line in an example that no renderer prints now: a footer, verdict or label
  whose wording has changed. Compare against the goldens and `grep` the
  renderer for the string.
- A command in an example, a tape or the page that uses a flag or format that
  no longer exists, or a combination the CLI rejects.
- JSON examples with fields the schema no longer has, or a stale
  `schema_version`.
- An example and its prose disagreeing: the text says three queries, the
  footer says four.

Don't regenerate examples yourself. That goes to the real root servers; say
which ones need it and, only if the user agrees, run them.

### 4. Length and tone

The house style is in `AGENTS.md`: plain, short, says what happens, doesn't
apologise. The README is the reference, so a section can be as long as the
behaviour needs. The page sells, so it should be shorter than the README on
every topic.

Flag, with a rewrite:

- A paragraph that restates the usage line or the table row above it.
- The same explanation in two README sections, or copied word for word from
  the README onto the page.
- Hedging and filler: "simply", "just", "basically", "note that", "it is
  worth mentioning", "in order to", nested asides.
- A sentence that explains DNS in general where the reader needs to know what
  dnstree does. One clause of background is plenty; link the RFC for the rest.
- Maintainer detail in user docs (how a test works, why a package is split),
  or user detail in `AGENTS.md`.
- A section whose heading doesn't say what it's about.

Don't flag length where each sentence carries a fact. Give each rewrite as the
replacement text and say how many words it saves. Skip rewrites that only
reshuffle.

### 5. The page itself

`docs/index.html` is committed and served as it is, with no build step:

- `<title>`, meta description and Open Graph tags match the README's tagline
  and point at files that exist (`social-card.png`, the icons).
- Every `<img>` and `<video>` has alt text or a label that says what it shows,
  and the GIF/MP4 pairs both exist.
- Tabs and panels line up: each tab's `aria-controls` names a panel that
  exists, and each panel shows the format its tab names.
- No version numbers, dates or counts that go stale without anyone noticing.
- Links to the repository, releases and the schema are absolute and correct.

## Mechanical pass

Run these first, under `bash` (zsh reads the backticks in the patterns). They
find the gaps; reading decides whether each one is real.

```bash
# Each usage flag: README mentions, page mentions, dnstreerc.example settings.
for f in $(awk '/^const Usage = `/,/^`/' internal/cli/cli.go \
    | grep -oE '^  -{1,2}[a-z0-9-]+(, -{1,2}[a-z0-9-]+)?' \
    | grep -oE -- '-{1,2}[a-z0-9-]+' | sort -u); do
  printf '%-18s readme=%-3s page=%-3s rc=%s\n' "$f" \
    "$(grep -c -- "\`$f[\` ]" README.md)" \
    "$(grep -c -- "$f\b" docs/index.html)" \
    "$(grep -cE "^#? ?${f#--} *=" dnstreerc.example)"
done

# Flags the docs name that the usage doesn't.
grep -ohE -- '--[a-z][a-z0-9-]+' README.md docs/index.html dnstreerc.example \
  tapes/*.tape | sort -u

# make targets the docs name.
grep -ohE '(`|^|<code>)make [a-z-]+' *.md packaging/*.md docs/index.html \
  | grep -oE 'make [a-z-]+' | sort -u
grep -oE '^[a-z-]+:' Makefile
```

`readme=0` is a finding. `page=0` usually isn't: the page doesn't list every
flag. Check relative links by hand or with a short script over `](...)`,
`href=` and `src=`, resolving each against the file's directory.

## History

Reviews run again and again, and their fixes are the next review's input. A
suggestion that undoes an earlier one is a loop, not a finding. Before writing
a rewrite, a `verbose` or a `nit`, look at where the text came from:

```bash
git log --format='%h %ad %s' --date=short -L<first>,<last>:<file>
git log --format='%h %s' -S'<phrase>' -- <file>
```

- If a `docs:` commit set the text to what it says now, and nothing it
  describes has changed since, leave it. Only a `wrong` or `stale` finding,
  backed by code newer than that commit, may reopen it; cite the commit.
- Never suggest wording a past commit replaced. Read the removed lines in
  `git show <commit> -- <file>` before proposing a sentence.
- A value that has been changed by hand release after release, such as a
  version number, needs a placeholder or a script, not another bump.
- Check `git log --oneline --grep='^docs:'` for the last review's commits. What
  it rewrote for length is settled unless the behaviour moved.

## Method

- For a whole review, if your agent can run subagents, give the user-facing
  set (README, page, install, `dnstreerc.example`, `SECURITY.md`) to one and
  the contributor set (`CONTRIBUTING.md`, `AGENTS.md`, the packaging and
  next-version READMEs, the PR template, the skills) to another, in parallel.
  Give each the sources of truth above. Do the cross-set checks yourself (exit
  codes, commit prefixes, install commands), and verify what comes back:
  subagents over-report, especially on length.
- A finding cites both sides: the doc line and the code line or other doc it
  contradicts. If you can't point at the other side, it's a question, not a
  finding.
- Don't run `make live` or `make demos`, or regenerate examples, without asking.
  Tell subagents the same. Any command that names a question goes to the root
  servers, even one meant to test the flag parser: test the parser with
  `go test ./internal/cli`.

- Don't edit anything unless asked. When asked to fix, regenerate examples
  instead of editing them by hand, change the `Usage` string rather than the
  man page, and don't commit.

## Report

Open with one line: how many findings, and the one that most needs fixing.

Then a table grouped by category (Consistency, Missing, Examples, Length,
Page), most important first, then one entry per finding:

- **[wrong | missing | stale | verbose | nit]** one-line claim
- where: [README.md:L113](README.md#L113), and the other side, such as
  [cli.go:L49](internal/cli/cli.go#L49)
- the fix: the replacement text, or what to add and where

`wrong` is a doc that tells the reader something false. It outranks everything
else, since a reader acts on it. `nit` is spelling, punctuation or a word
choice.

End with what you checked and found sound, one line each, and which examples
need regenerating against the real servers.
