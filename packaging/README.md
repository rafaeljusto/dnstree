# packaging

What a release ships beyond the archives: a Debian, an RPM and an Alpine
package per Linux architecture, and a Homebrew formula.

```bash
make dist VERSION=v0.1.2   # everything, into dist/
```

`dist` runs five stages in order, each reading the one before it:

| Stage | What it writes |
| --- | --- |
| `man` | `build/dnstree.1` and the gzipped copy the packages install |
| `archives` | the binary per platform, in `build/`, and a `.tar.gz` or `.zip` per platform in `dist/` |
| `packages` | `.deb`, `.rpm` and `.apk` per architecture, in `dist/` |
| `formula` | `dist/dnstree.rb`, pointing at the archives above |
| `checksums` | `dist/checksums.txt`, over every file |

`build/` is scratch and never published; `dist/` is what the release uploads.
Both are removed by `make clean`, which `dist` runs first.

## The man page

[`cmd/mkman`](../cmd/mkman) renders `dnstree.1` from `cli.Usage` — the same
string the binary prints for `--help`. A flag therefore cannot reach the help
without reaching the man page, and the generator fails rather than quietly
dropping a section it cannot parse. Nothing here is written by hand, and
`build/dnstree.1` is not committed.

The page also goes into every `.tar.gz`, because the Homebrew formula installs
it from there.

## The native packages

[`nfpm.yaml`](nfpm.yaml) describes one package; the `packages` target runs it
once per architecture and format. nfpm expands `PKG_ARCH` and `PKG_VERSION`
from the environment, but not a path it globs — so the architecture being
packaged is copied to `build/pkg/dnstree` first, which is where the config
looks.

`PKG_ARCH` is nfpm's name, not Go's: `arm7` becomes `armhf` on Debian,
`armv7hl` on RPM and `armv7` on Alpine. The mapping lives in `PKG_ARCHES` in
the [Makefile](../Makefile).

nfpm reads the version as semver, which `git describe` on an untagged tree is
not. A build without a tag packages as `0.0.0`; a release always has one.

The packages depend on nothing. The binary is static and reaches the root
servers by itself, and `ca-certificates` — read only by `--dot` and `--doh` —
is suggested rather than required.

## The Homebrew formula

[`brew-formula.sh`](../scripts/brew-formula.sh) writes `dnstree.rb` from the
archives already in `dist/`, so it needs their checksums and runs after them.
The formula pours those same archives rather than building from source: what a
Homebrew user runs is byte for byte what every other channel ships.

There is no tap. The formula is a release asset, installed from a file:

```bash
curl -LO https://github.com/rafaeljusto/dnstree/releases/download/v0.1.2/dnstree.rb
brew install --formula ./dnstree.rb
```

A tap would make `brew install rafaeljusto/tap/dnstree` and `brew upgrade`
work. It needs a `homebrew-tap` repository and a token that may push to it,
since the release workflow's own `GITHUB_TOKEN` cannot reach another
repository.

## The release notes

[`install.md`](install.md) is the install section appended to every release
body. The workflow substitutes `@BASE@`, `@VERSION@` and `@BARE@` — the
version with and without its leading `v`, which the archives and the packages
name differently. Change a package name here and change it there.
