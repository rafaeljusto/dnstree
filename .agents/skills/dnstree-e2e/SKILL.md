---
name: dnstree-e2e
description: Use dnstree the way a user would — build the real binary, run every flag and format against the real DNS, and check that each run does what the usage text, the guide and the AGENTS.md invariants say it does, exit code included. Reports what broke, with the command that shows it. Use when asked to smoke test, end-to-end test, try every flag, check the tool still works, or before a release. Takes an optional scope (a group from cases.md, or `quick` for the command-line checks alone) and an optional git ref to build instead of the working tree. Edits nothing and commits nothing unless asked.
---

# dnstree e2e

Act as somebody who just installed dnstree. Build the binary, run it the way the
usage text says it can be run, and hold every run to what that text, the guide in
`docs/guide/` and the invariants in `AGENTS.md` promise. The unit tests and
`make live` run code. This runs the product, and finds what they don't: a flag
that parses but does nothing, an exit code that drifted, a raw library error on
the user's screen, a summary that miscounts.

The catalogue of runs is [cases.md](cases.md). Read it before starting.

## Arguments

- A scope: one group heading from `cases.md` (`cli`, `walk`, `dnssec`,
  `transport`, `zone`, `budget`, `start`, `formats`, `saved`, `script`,
  `config`, `long`, `web`), several separated by commas, or `quick`, which
  runs only the `cli` group: every other group walks at least once. Nothing
  given means every group.
- A git ref: build that instead of the working tree.

## Set up

Use bash, not zsh: the cases rely on word splitting, and an interactive zsh may
alias `cat` or `grep`. Everything goes in a run directory in the scratchpad,
never in the repository.

```bash
R=$PWD; E2E=<scratchpad>/e2e-$(date +%Y%m%dT%H%M%S); mkdir -p $E2E/{home,xdg-cache,xdg-config,cases}
git status --porcelain > $E2E/git-before
cd $E2E  # the files cases name, such as --pcap w.pcap, land here
```

Build with the race detector: a walk under `--all`, `--live` or `--watch` is the
only concurrent run anything makes against real servers.

- Working tree: `go -C $R build -race -o $E2E/dnstree ./cmd/dnstree` and the
  same for `./cmd/dnstree-web`.
- A ref: `git -C $R archive <ref> | tar -x -C $E2E/src` and build from there.
  Never check out, stash or touch the user's tree. Somebody may be editing it.

If the build fails, report that as the result and stop. Don't fix it.

Isolate every run from the user's own setup, and use the isolation to check
that nothing is written behind the user's back:

```bash
export HOME=$E2E/home XDG_CACHE_HOME=$E2E/xdg-cache XDG_CONFIG_HOME=$E2E/xdg-config
unset DNSTREE_CONFIG DNSTREE_CACHE
D=$E2E/dnstree
B="--no-asn --no-compare --color never"   # quiet base: no side lookups, no escapes
```

Record the environment, so a failure caused by the network is not called a bug:
`$D $B -6 --timeout 1s --retries 0 example.com` says whether IPv6 works, and
`nc -z -w2 1.1.1.1 853` whether DoT can leave the network. `--spf` and
`--check` ask the host's resolver: `dig +bufsize=1232 sendgrid.net TXT`, run a
few times, says whether its larger answers get through over UDP. A path that
drops them leaves the SPF check undecided, which is the environment. Note `dig`
and `dot` (Graphviz) if they are on the PATH: some checks use them.

Run each case through one helper, so every run is judged the same way:

```bash
run() { # run ID ARGS... ; stdin is passed through
  local id=$1; shift; local d=$E2E/cases/$id; mkdir -p $d
  printf '%q ' "$@" > $d/cmd
  timeout ${T:-120} $D "$@" > $d/out 2> $d/err; echo $? > $d/code
}
```

Independent cases may run in the background, but keep it to about four walks at
once: these are other people's servers, and a burst looks like abuse and gets
rate limited, which then reads as a failure.

## Judge every run

Each case in `cases.md` says what it expects. On top of that, hold every run to
these. A case only passes when all of them hold:

1. **The exit code is the contract**: 0 an answer, 1 the command line, 2 no
   answer, 3 a broken chain of trust, 4 an `--expect` that failed. 124 is the
   `timeout` killing it, which is a hang, and a hang is a finding.
2. **Nothing crashed or raced**: no `panic:`, `goroutine `, `runtime error` or
   `WARNING: DATA RACE` in either stream.
3. **A walk is always drawn.** Any run that walked, whatever it exited with,
   prints the tree in the tree formats (`. (root)` and a closing `✔` or `✘`
   line). A failure is a step, never an abort.
4. **Copy is plain and lowercase, and a warning says what to do.** A Go
   internal on the user's screen (`tls.Config`, `<nil>`, `%!`, a struct dump,
   a bare `open x: no such file or directory` without saying which flag) is a
   finding, even when the exit code is right. `--debug` lines are exempt.
5. **The summary agrees with the tree.** `N queries · M servers` should match
   the hops drawn, and the answer drawn should match `--format json` of the same
   question.
6. **`--color never` writes no escape; `ascii` and `waterfall-ascii` write
   nothing above 127** (`LC_ALL=C grep -c '[^ -~]'` on stdout is 0).
7. **Nothing reaches the disk unless `--diff` or `--pcap` asks.** After any
   case without either, `$E2E/home`, `$E2E/xdg-cache` and `$E2E/xdg-config`
   hold only what the case put there itself (a config file it wrote). After a
   `--diff` case, exactly one file per question appeared under the cache; after
   a `--pcap` case, the one file it named and nothing else.

Read the output too, not just the patterns. You are the user: if a line is
confusing, a hop is drawn twice, a warning contradicts the summary or a flag
seems to change nothing, write it down.

## When a case fails

Run it once more. The network fails more often than the code does. Then decide
which of these it is before calling it a bug:

- **environment**: no IPv6, port 853 blocked, offline, a server rate-limiting
  us. Mark it skipped and say why. It's not a failure.
- **target drift**: the zone the case uses changed. `example.com` stopped
  being signed, or `zonetransfer.me` closed its AXFR. Confirm with `dig` or
  with a different flag. Mark it skipped and propose the new target, or the new
  expectation, for `cases.md`.
- **skill drift**: the case is wrong, because the usage text now promises
  something else. Say so, and propose the edit to `cases.md`.
- **product**: dnstree does something the usage text, the guide or an
  invariant says it doesn't. That's a finding.

For a product finding, narrow it before you report it. Find the smallest
command that shows it, and say whether it holds with `--from` on a saved walk
(no network) and with another target. If the cause is easy to find in the
source, name the file and line. Don't fix it unless asked.

A crash, a hang, a walk that outruns its budget, or anything a server could
set off on purpose belongs to `dnstree-audit`. Narrow it down to the smallest
command, then report it as a hand-off: the command, what it showed, and the
area (`wire`, `resolver`, `dnssec`, `transport`, `output`, `disk`,
`concurrency`, `web`) for the audit to reproduce against `fakens`. A real
server is not a reproduction there.

## Coverage

The catalogue has to keep up with the binary. Before reporting, list every flag
`$D --help` prints (`-x`, `-4`, `-6` and every `--name`), and every format named
after `FORMAT is one of`. Check that each one appears in at least one case that
ran. A flag or format that no case covers is a **skill drift** finding. Write
the case it needs, run it, and propose adding it to `cases.md`.

## Clean up

Stop every background process the run started: `--format web`, `dnstree-web`
and `--watch`. Check `git -C $R status --porcelain` against `$E2E/git-before`. A
difference that the run made is a finding against the skill. Leave `$E2E` in
place, since the report points into it.

## Report

Start with one line: how many cases passed, failed and were skipped, the commit
or ref built, and how long the run took.

Then the findings, the product ones first, each as:

- **[bug | ux | docs | skill | audit]** one-line claim
- run: the exact command (from `$E2E/cases/<id>/cmd`), the exit code, and
  the lines of output that show it
- expected: what the usage, guide or invariant says, quoted or linked
- where, if found: [file.go:L42](path/file.go#L42)

Then the skipped cases and why, in one line each. Skip the passing cases.
Nobody reads a list of things that worked.

If the user wants a finding fixed, fix it as normal work, with a `fakens`
scenario where the walk is involved, and hand the commit message to
`dnstree-commit`. Never commit, push or tag.
