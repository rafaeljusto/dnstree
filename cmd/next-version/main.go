// Command next-version computes the release that follows the last tag, from the
// commits since it, so the bump comes from what shipped rather than from
// whoever happens to be cutting the release.
//
// Usage:
//
//	go run ./cmd/next-version                # report the next version
//	go run ./cmd/next-version -bump=minor    # force a bump level
//	go run ./cmd/next-version -from=v0.1.0   # diff from an explicit tag
//
// Every commit since the tag is classified by its Conventional Commits prefix,
// which is what this repository writes its subjects with:
//
//	feat:                                   -> minor
//	fix: docs: refactor: perf: test: ...    -> patch
//	any prefix with !, or BREAKING CHANGE:  -> major
//
// A commit with no recognisable prefix counts as a patch and is reported as
// unclassified, so a feature that went out under a plain subject is visible
// before the tag is cut rather than after.
//
// While the major version is zero the project has promised nothing, so every
// level shifts down: a breaking change moves the minor and anything else the
// patch. Tagging v1.0.0 ends that.
//
// Under GitHub Actions it appends version, previous_tag, bump and unclassified
// to $GITHUB_OUTPUT, and a table of the changes to $GITHUB_STEP_SUMMARY.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// initialVersion is what a repository with no tags releases first.
var initialVersion = version{0, 1, 0}

func main() {
	if err := run(os.Args[1:], os.Stdout, gitCommand); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, git runner) error {
	flags := flag.NewFlagSet("next-version", flag.ContinueOnError)
	flags.SetOutput(stdout)

	forced := flags.String("bump", "auto", "bump to apply: auto, patch, minor or major")
	from := flags.String("from", "", "tag to diff from (default: the highest version tag reachable)")
	to := flags.String("to", "HEAD", "revision to release")
	outputPath := flags.String("output", os.Getenv("GITHUB_OUTPUT"), "file to append key=value outputs to")
	summaryPath := flags.String("summary", os.Getenv("GITHUB_STEP_SUMMARY"), "file to append a summary to")
	if err := flags.Parse(args); err != nil {
		return err
	}

	forcedLevel, err := parseLevel(*forced)
	if err != nil {
		return err
	}

	previous, current := *from, version{}
	if previous == "" {
		if previous, current, err = previousTag(git, *to); err != nil {
			return err
		}
	} else if parsed, ok := parseVersion(previous); ok {
		current = parsed
	} else {
		return fmt.Errorf("%q is not a version tag", previous)
	}

	changes, err := changesSince(git, previous, *to)
	if err != nil {
		return err
	}

	level, unclassified := weigh(changes)
	if forcedLevel != bumpAuto {
		level = forcedLevel
	}

	next, bump := current.next(level), level.String()
	if previous == "" {
		// Nothing has been released, so there is nothing for a bump to move.
		next, bump = initialVersion, "initial"
	}

	report(stdout, previous, next, bump, changes)
	if err := appendOutputs(*outputPath, previous, next, bump, unclassified); err != nil {
		return err
	}
	return appendSummary(*summaryPath, previous, next, bump, changes, unclassified)
}

// runner runs a git command, so that the tests can answer without a repository.
type runner func(args ...string) (string, error)

func gitCommand(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(exit.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// previousTag is the highest version this repository has already released.
func previousTag(git runner, to string) (string, version, error) {
	out, err := git("tag", "--list", "v*", "--merged", to)
	if err != nil {
		return "", version{}, err
	}

	var (
		highest version
		tag     string
	)
	for line := range strings.Lines(out) {
		candidate, ok := parseVersion(line)
		if !ok {
			continue // a pre-release, a date, a name: not something to count from
		}
		if tag == "" || highest.less(candidate) {
			highest, tag = candidate, strings.TrimSpace(line)
		}
	}
	return tag, highest, nil
}

// change is one commit and the bump its subject earns.
type change struct {
	sha     string
	subject string
	level   bumpLevel
	known   bool
}

// changesSince reads the commits a release would carry, newest first. Merges
// are left out: this repository puts its changes on the branch itself, and a
// merge subject says nothing about them.
func changesSince(git runner, from, to string) ([]change, error) {
	span := to
	if from != "" {
		span = from + ".." + to
	}

	out, err := git("log", "--no-merges", "--format=%H%x1f%s%x1f%b%x1e", span)
	if err != nil {
		return nil, err
	}

	var changes []change
	for record := range strings.SplitSeq(out, "\x1e") {
		fields := strings.Split(strings.TrimSpace(record), "\x1f")
		if len(fields) < 2 || fields[0] == "" {
			continue
		}

		body := ""
		if len(fields) > 2 {
			body = fields[2]
		}
		level, known := classify(fields[1], body)
		changes = append(changes, change{sha: fields[0], subject: fields[1], level: level, known: known})
	}
	return changes, nil
}

// prefixPattern matches a Conventional Commits prefix: a word, an optional
// (scope), an optional ! and a colon.
var prefixPattern = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z-]*)\s*(?:\([^)]*\))?\s*(!?)\s*:`)

// levels is the whole vocabulary. Everything that is not a feature is a patch,
// because a release of nothing but fixes and chores is a patch release.
var levels = map[string]bumpLevel{
	"feat":     bumpMinor,
	"feature":  bumpMinor,
	"fix":      bumpPatch,
	"docs":     bumpPatch,
	"refactor": bumpPatch,
	"perf":     bumpPatch,
	"test":     bumpPatch,
	"build":    bumpPatch,
	"ci":       bumpPatch,
	"chore":    bumpPatch,
	"style":    bumpPatch,
	"revert":   bumpPatch,
}

// classify reads what a commit asks for. An unknown prefix counts as a patch
// and says it was not understood, which is the only way an unversioned feature
// can be caught before the tag.
func classify(subject, body string) (bumpLevel, bool) {
	for line := range strings.Lines(body) {
		if strings.HasPrefix(strings.TrimSpace(line), "BREAKING CHANGE:") {
			return bumpMajor, true
		}
	}

	match := prefixPattern.FindStringSubmatch(subject)
	if match == nil {
		return bumpPatch, false
	}
	if match[2] == "!" {
		return bumpMajor, true
	}
	level, known := levels[strings.ToLower(match[1])]
	if !known {
		return bumpPatch, false
	}
	return level, true
}

// weigh is the highest bump any single change asks for, and how many of them
// nobody could read.
func weigh(changes []change) (bumpLevel, int) {
	level, unclassified := bumpAuto, 0
	for _, change := range changes {
		if !change.known {
			unclassified++
		}
		if change.level > level {
			level = change.level
		}
	}
	return level, unclassified
}

type bumpLevel int

const (
	bumpAuto bumpLevel = iota // nothing to release
	bumpPatch
	bumpMinor
	bumpMajor
)

func (l bumpLevel) String() string {
	switch l {
	case bumpPatch:
		return "patch"
	case bumpMinor:
		return "minor"
	case bumpMajor:
		return "major"
	}
	return "none"
}

func parseLevel(s string) (bumpLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "":
		return bumpAuto, nil
	case "patch":
		return bumpPatch, nil
	case "minor":
		return bumpMinor, nil
	case "major":
		return bumpMajor, nil
	}
	return bumpAuto, fmt.Errorf("unknown bump %q: want auto, patch, minor or major", s)
}

type version struct {
	major, minor, patch int
}

func (v version) String() string { return fmt.Sprintf("v%d.%d.%d", v.major, v.minor, v.patch) }

func (v version) less(other version) bool {
	switch {
	case v.major != other.major:
		return v.major < other.major
	case v.minor != other.minor:
		return v.minor < other.minor
	default:
		return v.patch < other.patch
	}
}

func (v version) next(level bumpLevel) version {
	// Major version zero promises nothing, so every level shifts down: what
	// would break compatibility is only a minor, and a feature only a patch.
	if v.major == 0 {
		switch level {
		case bumpMajor:
			return version{0, v.minor + 1, 0}
		case bumpMinor, bumpPatch:
			return version{0, v.minor, v.patch + 1}
		}
		return v
	}

	switch level {
	case bumpMajor:
		return version{v.major + 1, 0, 0}
	case bumpMinor:
		return version{v.major, v.minor + 1, 0}
	case bumpPatch:
		return version{v.major, v.minor, v.patch + 1}
	}
	return v
}

// parseVersion accepts the plain vMAJOR.MINOR.PATCH this repository tags with.
func parseVersion(tag string) (version, bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(tag), "v"), ".")
	if len(parts) != 3 {
		return version{}, false
	}

	var parsed version
	for i, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return version{}, false
		}
		switch i {
		case 0:
			parsed.major = number
		case 1:
			parsed.minor = number
		case 2:
			parsed.patch = number
		}
	}
	return parsed, true
}

func report(w io.Writer, previous string, next version, bump string, changes []change) {
	since := "the first commit"
	if previous != "" {
		since = previous
	}
	fmt.Fprintf(w, "%d changes since %s\n\n", len(changes), since)

	for _, change := range changes {
		mark := " "
		if !change.known {
			mark = "?"
		}
		fmt.Fprintf(w, "  %s %-5s %s %s\n", mark, change.level, change.sha[:min(len(change.sha), 8)], change.subject)
	}
	if len(changes) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%s -> %s (%s)\n", cmpOr(previous, "nothing"), next, bump)
}

func appendOutputs(path, previous string, next version, bump string, unclassified int) error {
	if path == "" {
		return nil
	}
	return appendTo(path, fmt.Sprintf("version=%s\nprevious_tag=%s\nbump=%s\nunclassified=%d\n",
		next, previous, bump, unclassified))
}

func appendSummary(path, previous string, next version, bump string, changes []change, unclassified int) error {
	if path == "" {
		return nil
	}

	release := "a " + bump + " release"
	if previous == "" {
		release = "the first release"
	}

	var summary strings.Builder
	fmt.Fprintf(&summary, "## %s\n\n%s since %s, %s.\n\n",
		next, plural(len(changes), "change"), cmpOr(previous, "the first commit"), release)

	if unclassified > 0 {
		fmt.Fprintf(&summary, "> [!WARNING]\n> %s carry no known prefix and counted as a patch. "+
			"If one of them is a feature, release again with `bump: minor`.\n\n",
			plural(unclassified, "change"))
	}

	if len(changes) > 0 {
		summary.WriteString("| Bump | Commit | Subject |\n| --- | --- | --- |\n")
		for _, change := range changes {
			bump := change.level.String()
			if !change.known {
				bump += " (unclassified)"
			}
			fmt.Fprintf(&summary, "| %s | `%s` | %s |\n", bump, change.sha[:min(len(change.sha), 8)], change.subject)
		}
		summary.WriteString("\n")
	}
	return appendTo(path, summary.String())
}

func appendTo(path, text string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.WriteString(file, text); err != nil {
		return err
	}
	return file.Close()
}

func plural(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

func cmpOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
