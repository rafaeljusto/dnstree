---
name: dnstree-commit
description: Write the commit messages, and the pull request title, for the current dnstree changes — prefixes from the table the release workflow reads, subjects in the repository's own style, unrelated work split into separate commits with the files each covers, and a branch name when on main. Use when asked for a commit message, a PR title, to "commit" the work, or to describe the changes for git. Prints the messages; never runs git commit, git add, git push or git tag.
---

# dnstree commit

Write the messages for the maintainer to apply. Print them, don't run them.

## Hard rules

1. **Never run `git commit`, `git push` or `git tag`.** The maintainer
   reviews and signs every commit, and releases are tagged by a workflow
   that works out the version from the subjects. See `AGENTS.md`.
2. Don't run `git add` unless asked to stage.
3. Read-only git (`status`, `diff`, `log`, `show`) is expected.

## Steps

1. **Read the change.**
   ```bash
   git status --short
   git diff --staged   # nothing staged: git diff
   ```
   With both staged and unstaged changes, write for the staged ones and
   mention the rest in one line. Read the files the diff touches when the
   hunks alone don't say why.

2. **Split by concern.** One message per logical change, each with the files
   it covers, ordered so `make check` passes after every one. Goldens
   rewritten by `make goldens` and `docs/trace.schema.json` go with the code
   that changed them, not in a commit of their own.

3. **Pick the prefix from the intent.** `cmd/next-version` reads it and
   decides the release, so a wrong prefix ships under the wrong version:

   | Prefix | Bump | Use for |
   | --- | --- | --- |
   | `feat:` (or `feature:`) | minor | a new flag, format, output or behaviour users see |
   | `fix:` | patch | a bug, including a security fix |
   | `perf:` | patch | faster, same output |
   | `docs:` | patch | README, `docs/`, contributor docs |
   | `refactor:` | patch | no behaviour change |
   | `test:` | patch | tests only, `fakens` knobs included |
   | `build:`, `ci:` | patch | `Makefile`, packaging, `go.mod`, workflows |
   | `chore:` | patch | housekeeping: goldens alone, skills, ignores |
   | `style:` | patch | formatting only |
   | `revert:` | patch | undoing an earlier commit |
   | `feat!:` or a `BREAKING CHANGE:` footer | major | a removed or re-meant flag, exit code or JSON field |

   A JSON field that changes meaning also needs `schema_version` bumped in
   the same commit; say so if the diff doesn't.

4. **Check the subject.**
   ```bash
   go run ./cmd/next-version -check-title="<subject>"
   ```

5. **Branch.** On `main`, suggest one. The history has no pattern beyond
   dependabot's, so use `<type>/<short-slug>` from the commit's own prefix
   and subject: `fix/escape-extra-text`.

6. **PR title.** Pull requests are squash-merged and the title becomes the
   subject on `main`, so it is what the release reads. When the branch has
   more than one commit, suggest a title that covers them all, with the
   highest prefix any of them needs, and check it the same way.

## Format

```
<prefix>: <What changed, imperative, capitalised, ≤ 72 chars>

<why, 1-3 lines, only when the subject doesn't say it>

Co-Authored-By: Claude <model> <noreply@anthropic.com>
```

- The subject reads like the history (`git log --oneline -20`): imperative,
  capital after the prefix, no period, no scope, and it names what the tool
  now does rather than which file changed — `fix: Escape EXTRA-TEXT in the
  JSON output`, `feat: Say what each hop asked`.
- The body says the problem and why this is the fix, wrapped at 72. Skip it
  when the subject is enough. Never list the files.
- A `BREAKING CHANGE:` footer says what a script or user has to change.
- The trailer is last, after a blank line, with the model name exactly as
  the environment gives it.

## Deliver

Each message in a block the maintainer can paste, headed by the files it
covers. Drop `-S` if `git config commit.gpgsign` is already true.

```
git switch -c fix/escape-extra-text

### 1/2 — internal/render/jsonout/*, docs/trace.schema.json
git add internal/render/jsonout docs/trace.schema.json
git commit -S -F- <<'MSG'
fix: Escape EXTRA-TEXT in the JSON output

A server's extended-error text reached --format json raw, so jq -r
could draw its escapes on the terminal. Escape it whole, as the tree
does, without the tree's clipping.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
MSG

### 2/2 — ...

PR title: fix: Escape EXTRA-TEXT in the JSON output
```

Then stop.
