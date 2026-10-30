---
name: dnstree-release
description: Get dnstree ready for a release — confirm the version the commits since the last tag ask for, run the checks every release needs, decide from the diff which of dnstree-e2e, dnstree-docs, dnstree-audit, dnstree-dig and the fuzz search this release needs and run those, and report each step as run or skipped, with the reason. Use when asked to prepare, check or get ready for a release, or "/dnstree-release". Takes an optional tag to compare from (defaults to the latest). Never commits, pushes, tags or starts the release workflow.
---

# dnstree release

The release workflow cuts the tag. This skill makes sure what it would cut has
been checked as far as the change calls for, and no further. Read `AGENTS.md`
first: its "Before handing work back" and "Releasing" sections are the gates,
and its "Do not commit" section holds here too.

Asking for this skill is permission for everything it runs that talks to the
real DNS: `make live`, `dnstree-e2e` and `dnstree-dig`. Run every snippet
under `bash`. zsh does not split a command held in a variable, and reads the
backticks in some patterns.

## 1. Where things stand

```bash
git fetch --tags origin
git status --short                       # clean, apart from what you were asked to keep
git rev-parse --abbrev-ref HEAD          # main
git rev-list --count HEAD..origin/main   # 0: nothing on main you have not got
gh run list --branch main --limit 3      # CI on HEAD, if gh is there
```

Stop and say so if the branch is not `main`, it is behind `origin/main`, or CI
failed on HEAD. Uncommitted changes are reported, not discarded.

## 2. The version

```bash
T=${TAG:-$(git describe --tags --abbrev=0)}
go run ./cmd/next-version -from "$T"
```

It prints every subject with the bump it earns and the version that results.
An `unclassified` subject is a finding: a feature under a plain subject ships
under a patch tag, and only the maintainer can fix that, before the release.

## 3. What the diff calls for

Work out the plan before running anything long, and print it.

```bash
S=<scratchpad>/release; mkdir -p "$S"
git log --format=%s "$T"..HEAD > "$S/subjects"
git diff --name-only "$T"..HEAD > "$S/files"
grep -E '\.go$' "$S/files" | grep -v '_test\.go$' | xargs -r -n1 dirname | sort -u > "$S/pkgs"
for p in $(cat "$S/pkgs"); do
  grep -qlE '^func Fuzz' "$p"/*_test.go 2>/dev/null && echo "$p"
done > "$S/fuzzed"
grep -n '^- \*\*Commit\*\*' .agents/skills/dnstree-audit/coverage.md
```

| Step | Run when | Scope |
| --- | --- | --- |
| `dnstree-e2e` | always | `quick` when `pkgs` is empty; the full run otherwise |
| `dnstree-docs` | a `feat:` or `feat!:` subject, or `files` touches `internal/cli/cli.go`, `README.md`, `docs/`, `dnstreerc.example` or `packaging/plugin/` | the full review for a `feat:`; otherwise each changed doc by name |
| `dnstree-audit` | `pkgs` holds a package in one of its areas: `internal/resolver`, `internal/dnssec`, `internal/transport`, `internal/spf`, `internal/dkim`, `internal/rdap`, `internal/dane`, `internal/render`, `internal/explain`, `internal/history`, `internal/capture`, `internal/server`, `cmd/dnstree-web`, `internal/recursive`, `internal/asn`, `internal/testutil/fakens` | no scope: it starts from the commits since its ledger. Skip it when the ledger's commit is HEAD, or a descendant of every commit that touched those packages |
| `dnstree-dig` | `pkgs` holds `internal/resolver`, `internal/dnssec` or `internal/transport`, or `go.mod` changed `codeberg.org/miekg/dns` | `curated` for a patch; the default sample for a minor or major |
| `make fuzz` | `fuzzed` is not empty | `FUZZPKG="<fuzzed>" FUZZTIME=1m` |

A step the table does not call for is skipped, and the report says which rule
left it out. Do not run one because there is time: the point of the table is
that a release costs what its change calls for.

The ledger check for the audit, for each commit that touched an audited package:

```bash
L=<ledger commit>
git log --format=%h "$T"..HEAD -- <audited packages in pkgs> |
  while read c; do git merge-base --is-ancestor "$c" "$L" || echo "$c"; done
```

Anything printed is a commit the ledger has not seen, and the audit runs.

## 4. The gates

Every release, in this order, each to its own log. A failure here stops the
release: report it and skip section 5.

```bash
make check
go test -race -count=2 ./...
make live
make lint-docker
make dist
make web-lambda
make man
```

`make check` ends with govulncheck. Read its module results too
(`govulncheck -show verbose ./...`): an advisory in a required module that
has a fixed version is bumped before the release, in a `build(deps):` commit,
even when the code does not call it, because scanners downstream flag the
module either way. One with no fix is listed in the report.

## 5. The steps the diff called for

- `dnstree-e2e` and `dnstree-dig` both go to the real DNS and time things, so
  run them one after the other, never together.
- `dnstree-docs` and `dnstree-audit` are offline. If your agent can run
  subagents, give them one each, alongside the network steps. Each subagent
  invokes the skill itself with the scope from the plan, and is told it edits
  nothing but the audit's coverage ledger, which that skill rewrites. Tell the
  audit to skip its own fuzz search when `make fuzz` is already running.
- `make fuzz` runs alongside the offline steps.
- Where your agent can pick a model per subagent, give `dnstree-audit` the
  strongest one: it reasons about proofs and hostile servers. `dnstree-docs`,
  `dnstree-e2e` and `dnstree-dig` do with a mid tier, though a disagreement
  `dnstree-dig` cannot settle goes to the strongest. Nothing below that: the
  cases that matter are the ones whose output looks fine at a glance.

Verify what comes back before you report it: subagents over-report, and a
network failure is not a product failure until a rerun says so.

## 6. What blocks

| Blocks the release | Goes in the report for the maintainer |
| --- | --- |
| a gate that fails | an `unclassified` subject the maintainer chooses to keep |
| an e2e case that fails on the product, confirmed by a rerun | an e2e case that fails on the network, or a ux finding |
| a `wrong` docs finding | `missing`, `stale`, `verbose` and `nit` docs findings |
| an audit finding rated Critical or High | Medium and Low audit findings |
| a fuzz search that fails | any `dnstree-dig` disagreement: it is advisory, since a zone can be at fault as easily as the tool |
| an `unclassified` subject the maintainer has not seen | |

Fix what blocks only when asked. A fix made during the release goes through
`dnstree-review`, then `make check`, and its message comes from
`dnstree-commit`. Its prefix can raise the version, so run section 2 again.

## Report

Open with one line: ready or not, the version, and what blocks it if not.

Then one row per step, the gates included:

| Step | Ran | Why | Result |
| --- | --- | --- | --- |
| `make check` | yes | always | passed |
| `dnstree-dig` | no | no resolver, dnssec or transport change, codec unchanged | — |

Then the findings that block, the ones that do not, any changes left in the
working tree with the messages `dnstree-commit` wrote for them, and the next
step:

> Merge any open changes, then run the release workflow on `main` with
> `bump: auto` and `dry_run: true`, and again without the dry run once it
> names the version above.
