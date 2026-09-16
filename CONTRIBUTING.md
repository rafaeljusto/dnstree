# Contribute to dnstree

- [Introduction](#introduction)
- [FAQ](#faq)
- [How can I contribute?](#how-can-i-contribute)
- [Communication](#communication)
- [Contribute code](#contribute-code)
  - [Commit subjects decide the version](#commit-subjects-decide-the-version)
  - [Testing](#testing)
  - [Working with forks](#working-with-forks)
- [Disclosing vulnerabilities](#disclosing-vulnerabilities)
- [Code style](#code-style)
- [Conduct](#conduct)

## Introduction

_Please note_: We take security and our users' trust very seriously. If you
believe you have found a security issue in dnstree, please disclose it by
contacting us at cadastros@rafael.net.br.

There are many ways in which you can contribute. The goal of this document is to
provide a high-level overview of how you can get involved in dnstree.

As a potential contributor, your changes and ideas are welcome at any hour of
the day or night, on weekdays, weekends, and holidays. Please do not ever
hesitate to ask a question or send a pull request.

If you are unsure, just ask or submit the issue or pull request anyways. You
won't be yelled at for giving it your best effort. The worst that can happen is
that you'll be politely asked to change something. We appreciate any sort of
contributions and don't want a wall of rules to get in the way of that.

That said, if you want to ensure that a pull request is likely to be merged,
talk to us! You can find out our thoughts and ensure that your contribution
won't clash with dnstree's direction. A great way to do this is via
[dnstree Discussions](https://github.com/rafaeljusto/dnstree/discussions).

## FAQ

- I am new to the community. Where can I find the
  [dnstree Code of Conduct?](https://github.com/rafaeljusto/dnstree/blob/main/CODE_OF_CONDUCT.md)

- I have a question. Where can I get
  [answers to questions regarding dnstree?](#communication)

- I would like to contribute but I am not sure how. Are there
  [easy ways to contribute?](#how-can-i-contribute)
  [Or good first issues?](https://github.com/rafaeljusto/dnstree/labels/good%20first%20issue)

- I want to talk to other dnstree users.
  [How can I become a part of the community?](#communication)

## How can I contribute?

If you want to start to contribute code right away, take a look at the
[list of good first issues](https://github.com/rafaeljusto/dnstree/labels/good%20first%20issue).

There are many other ways you can contribute. Here are a few things you can do
to help out:

- **Give us a star.** It may not seem like much, but it really makes a
  difference. This is something that everyone can do to help out dnstree.
  Github stars help the project gain visibility and stand out.

- **Report what you found in the wild.** dnstree exists to make broken
  delegations visible. If it drew something you did not expect, or stayed quiet
  about something it should have caught, that is worth an issue — paste the
  walk it drew.

- **Answer discussions.** If you think you know an answer or can provide some
  information that might help, please share it.

- **Help with open issues.** Some of them may lack necessary information, some
  are duplicates of older issues. You can help out by guiding people through
  the process of filling out the issue template, asking for clarifying
  information or pointing them to existing issues that match their description
  of the problem.

- **Review documentation changes.** Most documentation just needs a review for
  proper spelling and grammar. If you think a document can be improved in any
  way, feel free to hit the `edit` button at the top of the page.

- **Help with tests.** Pull requests may lack proper tests or test plans. These
  are needed for the change to be implemented safely.

## Communication

Check out [dnstree Discussions](https://github.com/rafaeljusto/dnstree/discussions).
This is a great place for in-depth discussions and lots of code examples, logs
and similar data.

## Contribute code

Unless you are fixing a known bug, we **strongly** recommend discussing it with
the maintainers via a GitHub issue before getting started, to ensure your work
is consistent with dnstree's direction and architecture.

All contributions are made via pull requests. To make a pull request, you will
need a GitHub account; if you are unclear on this process, see GitHub's
documentation on [forking](https://help.github.com/articles/fork-a-repo) and
[pull requests](https://help.github.com/articles/using-pull-requests). Pull
requests should be targeted at the `main` branch. Before creating a pull
request, go through this checklist:

1. Create a feature branch off of `main` so that changes do not get mixed up.
2. [Rebase](http://git-scm.com/book/en/Git-Branching-Rebasing) your local
   changes against the `main` branch.
3. Run `make check`. It builds, lints, runs the whole suite under `-race` and
   checks the dependencies for known vulnerabilities — the same things CI runs.
4. Give every commit subject a descriptive prefix. See below: the release
   version is worked out from them.

If a pull request is not ready to be reviewed yet
[it should be marked as a "Draft"](https://docs.github.com/en/github/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/changing-the-stage-of-a-pull-request).

When pull requests fail the automated testing stages, authors are expected to
update their pull requests to address the failures until the tests pass.

Pull requests eligible for review

1. follow the repository's code formatting conventions;
2. include tests that prove that the change works as intended and does not add
   regressions;
3. document the changes in the code and/or the project's documentation;
4. pass the CI pipeline;
5. include a proper git commit message following the
   [Conventional Commit Specification](https://www.conventionalcommits.org/en/v1.0.0/).

Some other important notes when contributing:

- **Keep the dependency list short.** dnstree has exactly one dependency,
  `codeberg.org/miekg/dns`, because the standard library has no DNS wire-format
  codec. Everything else is standard library, and a pull request adding a
  dependency needs to argue for it.
- **Only three packages may import the DNS codec**: `transport`, `resolver` and
  `dnssec`, plus the fake nameserver that has to speak the wire format. The
  trace model, the renderers and the ASN lookups work on plain Go types, which
  is what keeps them testable without a network.
- **The tool always terminates and always draws what it learned.** Anything that
  follows a delegation needs a budget, and a hostile or broken zone must not be
  able to spend more than it.

### Commit subjects decide the version

Releases are cut by a workflow that reads the commits since the last tag and
works out the version their prefixes ask for. A subject with no known prefix
counts as a patch and is reported as unclassified, which means a feature under a
plain subject ships under a patch tag.

| Subject | Bump |
| --- | --- |
| `feat:` | minor |
| `fix:`, `docs:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`, `chore:`, `style:`, `revert:` | patch |
| any prefix with `!` (`feat!:`), or a `BREAKING CHANGE:` footer | major |

A pull request title is checked against the same table, since a squash merge
is what puts it on `main` as a commit subject. You can check one yourself:

```bash
go run ./cmd/next-version -check-title="feat: Draw a trace as a tree"
```

See [cmd/next-version](cmd/next-version/) for the details, including what
changes while the major version is still zero.

### Testing

The engine is tested offline against in-process authoritative servers
(`internal/testutil/fakens`), signed hierarchies included. If you are fixing the
way a delegation is followed, the fix belongs with a scenario that reproduces it
on purpose — there is a knob for lame servers, truncation, missing glue, broken
signatures and more.

```bash
make check   # what CI runs
make live    # goes out to the real root servers; never part of check
```

### Working with forks

```bash
# First you clone the original repository
git clone git@github.com:rafaeljusto/dnstree.git

# Next you add a git remote that is your fork:
git remote add fork git@github.com:<YOUR-GITHUB-USERNAME-HERE>/dnstree.git

# Next you fetch the latest changes from origin for main:
git fetch origin
git checkout main
git pull --rebase

# Next you create a new feature branch off of main:
git checkout -b my-feature-branch

# Now you do your work and commit your changes:
git add -A
git commit -a -m "fix: this is the subject line" -m "This is the body line. Closes #123"

# And the last step is pushing this to your fork
git push -u fork my-feature-branch
```

Now go to the project's GitHub Pull Request page and click "New pull request"

## Disclosing vulnerabilities

Please disclose vulnerabilities exclusively to
[cadastros@rafael.net.br](mailto:cadastros@rafael.net.br). Do not use GitHub
issues. See the [security policy](SECURITY.md).

## Code style

Run `make lint`. It runs `go vet` and golangci-lint, which covers the
formatting as well.

## Conduct

Whether you are a regular contributor or a newcomer, we care about making this
community a safe place for you and we've got your back.

[dnstree Community Code of Conduct](https://github.com/rafaeljusto/dnstree/blob/main/CODE_OF_CONDUCT.md)

We welcome discussion about creating a welcoming, safe, and productive
environment for the community. If you have any questions, feedback, or concerns
[please let us know](#communication).
