---
name: dnstree-pr
description: Write the pull request body for the current dnstree branch, a PR number or a local diff — the visual summary, before-and-after evidence and merge danger of the `pr` skill (mattpocock/skills), poured into the sections of `.github/pull_request_template.md`, with the checklist ticked only where this session has proof. Use when asked for a PR body or description, to "write the PR", or "/dnstree-pr". Prints the body; never runs gh pr create, gh pr edit, git commit or git push.
---

# dnstree PR body

A wrapper around the `pr` skill from
[mattpocock/skills](https://github.com/mattpocock/skills/blob/main/skills/engineering/pr):
its content, this repository's template as the shape. Print the body, don't
post it.

## Hard rules

1. **Never run `gh pr create`, `gh pr edit`, `git commit` or `git push`.**
   Read-only `git` and `gh pr view` / `gh pr diff` are expected.
2. **The template's headings stay, in its order**: the description, `##
   Related Issue`, `## Checklist`, `## Further comments`. No heading of `pr`'s
   own is added at the top level. The template's HTML comments are dropped.
3. **Every output in the body is real**, pasted from a run made in this
   session — the same rule `AGENTS.md` sets for the README.
4. **A checklist box is ticked only on proof** (see below). An unticked box
   is honest; a ticked one nobody checked is not.

## Steps

1. **Load `pr`.** Invoke the `pr` skill (`mattpocock-skills:pr`) for its menu
   of visuals and its Evidence and Merge Danger rules. If it is not installed,
   read the link above. Its `GLOSSARY.md` is `AGENTS.md` here: say walk, hop,
   step, trace, delegation, zone, chain of trust — the words the code uses.

2. **Read the change.** With no argument, the branch against `main`:
   ```bash
   git log --oneline main..HEAD
   git diff main...HEAD --stat
   git diff main...HEAD
   ```
   With a PR number, `gh pr view <n>` and `gh pr diff <n>`. Mention
   uncommitted changes in one line; they are not in the PR.

3. **Title.** Take it from `dnstree-commit`'s rules, or the PR's own, and
   check it — it is what the release reads:
   ```bash
   go run ./cmd/next-version -check-title="<title>"
   ```

4. **Gather evidence**, best first:
   - The tool's own output, before and after. Build the base in a worktree
     under the scratchpad and run both binaries on the same question:
     ```bash
     SCRATCH=$(mktemp -d)   # or the session's scratchpad
     git worktree add "$SCRATCH/base" main
     (cd "$SCRATCH/base" && go build -o "$SCRATCH/dnstree-before" ./cmd/dnstree)
     go build -o "$SCRATCH/dnstree-after" ./cmd/dnstree
     git worktree remove "$SCRATCH/base"
     ```
     Prefer a question whose answer will not drift — `--replay` of a
     capture, or a zone that shows the case today. Add `--format ascii` when
     the tree is pasted.
   - The golden diff, when renderer output changed: that is the user-visible
     change already, so quote the hunk.
   - The test that fails on the base and passes on the branch, by name, as
     `pr` asks — a `fakens` scenario says what a server did wrong.
   - The exit code, when it changed. It is a contract.

5. **Judge the merge danger** in dnstree's terms:
   - **One-way doors**: an exit code re-meant, a JSON field dropped or
     re-meant (`schema_version` bumped), a flag renamed or removed (scripts
     and `dnstreerc` files break), the history cache's file format, anything
     already shipped in a package. Everything else rolls back with a revert.
   - **Blast radius**, one word: the layer touched — `resolver`, `dnssec`,
     `transport`, `renderer`, `web`, `cli`, `packaging`, `docs`. Then say
     what it reaches: every walk, one flag, one format, dnstree-web's
     strangers.

6. **Fill the checklist.** Tick:
   - the title box, when step 3 passed;
   - `make check`, only when it ran in this session against this tree and
     passed — offer to run it otherwise;
   - tests, when the diff adds or changes a test that covers the change;
   - documentation, when the diff reaches the surfaces `AGENTS.md` lists for
     what changed, or nothing user-visible changed.

   Leave the contributing guidelines, security policy and security
   confirmation boxes for the author: they are attestations, not facts in
   the diff.

## Shape

````markdown
<one or two lines: why, in the problem's terms>

<pr's Summary: the smallest visual that shows the point — a call tree of the
walk, a diff of the drawn tree, a file tree for a refactor>

**Before:** <command, output or failing test>
**After:** <same command, output or passing test>

<a BREAKING CHANGE block, as the template's comment shows, when the title
carries `!` or the change closes a one-way door>

## Related Issue

<#1234, or the discussion it came from; for a bug nobody reported, what
broke and the command that shows it; for docs alone, "None.">

## Checklist

<the template's boxes, verbatim, ticked per step 6>

## Further comments

**Door:** <one-way or two-way> — <why, one line>
**Blast radius:** <one word> — <what it reaches>

<alternatives considered, only when the change is large or the choice was
not obvious>
````

Keep prose short: `pr` skips preambles, and so do the reviewers here.

## Deliver

The title, then the body in one fenced block the maintainer can paste.
Below it, one line per box left unticked that the session could have
checked, and what would tick it. Then stop.
