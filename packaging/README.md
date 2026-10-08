# packaging

What a release ships beyond the archives: a Debian, an RPM and an Alpine
package per Linux architecture, a Homebrew formula and two container images.

```bash
make dist VERSION=v1.2.0   # everything, into dist/
```

`dist` runs five stages in order, each reading the one before it:

| Stage | What it writes |
| --- | --- |
| `man` | `build/dnstree.1` and the gzipped copy the packages install |
| `archives` | the binary per platform, in `build/`, and a `.tar.gz` or `.zip` per platform in `dist/`, each carrying `dnstreerc.example` |
| `packages` | `.deb`, `.rpm` and `.apk` per architecture, in `dist/` |
| `formula` | `dist/dnstree.rb`, pointing at the archives above |
| `checksums` | `dist/checksums.txt`, over every file |

`build/` is scratch and never published; `dist/` is what the release uploads.
Both are removed by `make clean`, which `dist` runs first.

## Cutting a release

A release is cut by running the `release` workflow from `main`: it reads the
commits since the last tag, works out the version their prefixes ask for,
creates the tag, and publishes the archives alongside two multi-architecture
images on `ghcr.io`, `dnstree` and `dnstree-web`. The same commits become the
changelog, carried by both the annotated tag and the release notes. `dry_run`
reports the version it would pick without tagging anything, and `bump`
overrides it. See [cmd/next-version](../cmd/next-version/) for how a subject
earns a bump. A package `ghcr.io` has not seen before starts out private: the
first release to publish one has to be followed by making it public in the
package's settings.

## The man page

[`cmd/mkman`](../cmd/mkman) renders `dnstree.1` from `cli.Usage` — the same
string the binary prints for `--help`. A flag therefore cannot reach the help
without reaching the man page, and the generator fails rather than quietly
dropping a section it cannot parse. Nothing here is written by hand, and
`build/dnstree.1` is not committed.

The page also goes into every `.tar.gz`, because the Homebrew formula installs
it from there.

## The example file of defaults

[`dnstreerc.example`](../dnstreerc.example) rides along with every channel: into
`/usr/share/doc/dnstree/` in the native packages, into each archive beside the
binary — the `.zip` included, since the file of defaults is read on Windows too
— and into Homebrew's `doc` from the tarball. It is checked by
`TestExampleParses` rather than by eye, so what ships parses.

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
curl -LO https://github.com/rafaeljusto/dnstree/releases/download/v1.2.0/dnstree.rb
brew install --formula ./dnstree.rb
```

A tap would make `brew install rafaeljusto/tap/dnstree` and `brew upgrade`
work. It needs a `homebrew-tap` repository and a token that may push to it,
since the release workflow's own `GITHUB_TOKEN` cannot reach another
repository.

## The container images

One `Dockerfile` builds both: `ghcr.io/rafaeljusto/dnstree`, and with
`--target web`, `ghcr.io/rafaeljusto/dnstree-web`. They are not part of `dist`.
The release workflow's `image` job runs `make image-push image-web-push` beside
it, tagging each with the version and `latest`, and CI builds both on every pull
request. `make image` and `make image-web` build them for this machine.

## The Lambda zip

`make web-lambda` builds `dnstree-web` for Lambda's `provided.al2023` runtime
and zips it with [`lambda/bootstrap`](lambda/bootstrap), the script Lambda
starts, into `build/`, one zip per architecture in `LAMBDA_ARCHES`. It is
uploaded by hand: CI builds it, and nothing publishes it.

## The plugin

[`plugin/`](plugin/) is a Claude Code plugin holding one skill, which teaches a
model to run dnstree. It is not built or released: Claude Code reads it straight
from the repository through
[`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json), which
has to sit at the root for `/plugin marketplace add rafaeljusto/dnstree` to
find it. The plugin carries no version, so an install follows the commit it
was taken from. `TestSkillFlagsExist` and `TestSkillCommandsParse` hold the
skill to the usage, the way `TestExampleParses` holds the example file.
`claude plugin validate .` checks the manifests.

## The release notes

[`install.md`](install.md) is the install section appended to every release
body. The workflow substitutes `@BASE@`, `@VERSION@` and `@BARE@` — the
version with and without its leading `v`, which the archives and the packages
name differently. Change a package name here and change it there.
