# next-version

Computes the release that follows the last tag, from the commits since it, so
the bump is derived from what shipped rather than picked by whoever is cutting
the release.

```bash
go run ./cmd/next-version                # report the next version
go run ./cmd/next-version -bump=minor    # force a bump level
go run ./cmd/next-version -from=v0.1.0   # diff from an explicit tag

go run ./cmd/next-version -check-title="feat: Draw a trace as a tree"
```

## How a change is classified

Every commit since the tag is read by the prefix of its subject. Merges are
skipped: the changes are on the branch itself, and a merge subject says nothing
about them.

| Subject | Bump |
| --- | --- |
| `feat:` | minor |
| `fix:`, `docs:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`, `chore:`, `style:`, `revert:` | patch |
| any prefix with `!` (`feat!:`), or a `BREAKING CHANGE:` footer | major |
| anything else | patch, **reported as unclassified** |

The release takes the highest bump any single commit asks for. Prefixes are
case-insensitive and may carry a scope, so `chore(deps):` is a patch.

## Before 1.0

While the major version is zero the project has promised nothing, so every
level shifts down one: a breaking change moves the minor, and a feature moves
only the patch.

| From | Change | To |
| --- | --- | --- |
| v0.1.0 | `fix:` | v0.1.1 |
| v0.1.0 | `feat:` | v0.1.1 |
| v0.1.0 | `feat!:` | v0.2.0 |

Tagging v1.0.0 ends that, and the usual arithmetic takes over.

## Unclassified changes

A subject with no known prefix counts as a patch and is listed as
unclassified — in the terminal with a `?`, and as a warning in the workflow
summary. **Read that list before releasing.** If one of them turns out to be a
feature, run the workflow again with `bump: minor`.

## Checking a subject

`-check-title` validates one subject against the table above and prints the
bump it earns, exiting non-zero with the accepted prefixes if it has none. The
`pr lint` workflow runs exactly that, so the check and the release read a
subject the same way — there is no second list of prefixes anywhere.

```console
$ go run ./cmd/next-version -check-title="feat: Draw a trace as a tree"
Accepted; this earns a minor bump.
```

Use it before opening a pull request, or to see why the check failed on one.

## Where it runs

`.github/workflows/release.yml` calls it on the `workflow_dispatch` path, where
it writes `version`, `previous_tag`, `bump` and `unclassified` to
`$GITHUB_OUTPUT` and a table of the changes to the run summary. The workflow
then creates that tag and releases it.

Use the workflow's `dry_run` input to see the version and the table without
tagging anything.

`.github/workflows/pr_lint.yml` calls it with `-check-title` on every pull
request. A squash merge puts the pull request title on `main` as the commit
subject, which is what the release then reads.
