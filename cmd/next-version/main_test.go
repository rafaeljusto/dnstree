package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tool writes to $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY by default, and
// `go test ./...` runs inside the release workflow: left set, a test that does
// not pass its own paths appends a fake release to the real job summary.
func TestMain(m *testing.M) {
	os.Unsetenv("GITHUB_OUTPUT")
	os.Unsetenv("GITHUB_STEP_SUMMARY")
	os.Exit(m.Run())
}

func TestClassify(t *testing.T) {
	tests := map[string]struct {
		subject string
		body    string
		level   bumpLevel
		known   bool
	}{
		"a feature":                {subject: "feat: Draw a trace as a tree", level: bumpMinor, known: true},
		"a fix":                    {subject: "fix: Take glue from the right server", level: bumpPatch, known: true},
		"a chore with a scope":     {subject: "chore(deps): bump miekg/dns", level: bumpPatch, known: true},
		"the case does not matter": {subject: "Feat: Draw a trace", level: bumpMinor, known: true},
		"a break":                  {subject: "feat!: Rename every flag", level: bumpMajor, known: true},
		"a break with a scope":     {subject: "fix(cli)!: Drop --retries", level: bumpMajor, known: true},
		"a break in the body": {
			subject: "refactor: Rework the trace model",
			body:    "The steps carry their own question now.\n\nBREAKING CHANGE: Step.Zone is gone.\n",
			level:   bumpMajor, known: true,
		},
		"a prefix nobody knows":        {subject: "wip: something", level: bumpPatch},
		"no prefix at all":             {subject: "Draw a trace as a tree", level: bumpPatch},
		"a colon that is not a prefix": {subject: "Update README: the samples were stale", level: bumpPatch},
		"nothing":                      {subject: "", level: bumpPatch},
		// A mention of a break that is not the footer says nothing.
		"a break only talked about": {
			subject: "docs: Explain what BREAKING CHANGE: means",
			level:   bumpPatch, known: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			level, known := classify(test.subject, test.body)
			if level != test.level || known != test.known {
				t.Errorf("got %s known=%v, want %s known=%v", level, known, test.level, test.known)
			}
		})
	}
}

func TestVersionNext(t *testing.T) {
	tests := map[string]struct {
		from  string
		level bumpLevel
		want  string
	}{
		// Before 1.0 every level shifts down: nothing was promised.
		"a break before 1.0":   {from: "v0.1.0", level: bumpMajor, want: "v0.2.0"},
		"a feature before 1.0": {from: "v0.1.0", level: bumpMinor, want: "v0.1.1"},
		"a fix before 1.0":     {from: "v0.4.7", level: bumpPatch, want: "v0.4.8"},
		"a break":              {from: "v1.4.2", level: bumpMajor, want: "v2.0.0"},
		"a feature":            {from: "v1.4.2", level: bumpMinor, want: "v1.5.0"},
		"a fix":                {from: "v1.4.2", level: bumpPatch, want: "v1.4.3"},
		"nothing to release":   {from: "v1.4.2", level: bumpAuto, want: "v1.4.2"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			from, ok := parseVersion(test.from)
			if !ok {
				t.Fatalf("%q is not a version", test.from)
			}
			if got := from.next(test.level).String(); got != test.want {
				t.Errorf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	for _, tag := range []string{"v1.2.3", "1.2.3", " v0.0.0 "} {
		if _, ok := parseVersion(tag); !ok {
			t.Errorf("got %q rejected, want it read as a version", tag)
		}
	}
	for _, tag := range []string{"v1.2", "v1.2.3-rc1", "nightly", "v1.2.x", "", "v-1.2.3"} {
		if _, ok := parseVersion(tag); ok {
			t.Errorf("got %q accepted, want it left alone", tag)
		}
	}
}

// fakeGit answers the two commands the tool runs.
func fakeGit(tags string, commits []string) runner {
	return func(args ...string) (string, error) {
		switch args[0] {
		case "tag":
			return tags, nil
		case "log":
			var out strings.Builder
			for i, commit := range commits {
				subject, body, _ := strings.Cut(commit, "\n")
				fmt.Fprintf(&out, "%040d\x1f%s\x1f%s\x1e", i, subject, body)
			}
			return out.String(), nil
		}
		return "", fmt.Errorf("unexpected git %v", args)
	}
}

func TestRun(t *testing.T) {
	tests := map[string]struct {
		tags     string
		commits  []string
		args     []string
		version  string
		bump     string
		previous string
	}{
		"a release of fixes": {
			tags:     "v0.1.0\nv0.0.9\n",
			commits:  []string{"fix: Ask with EDNS0", "docs: Write a README"},
			version:  "v0.1.1",
			bump:     "patch",
			previous: "v0.1.0",
		},
		"a feature before 1.0 is still a patch": {
			tags:     "v0.1.0\n",
			commits:  []string{"feat: Export a trace as JSON", "fix: Take the right glue"},
			version:  "v0.1.1",
			bump:     "minor",
			previous: "v0.1.0",
		},
		"a break moves the minor": {
			tags:     "v0.1.0\n",
			commits:  []string{"feat!: Rename every flag"},
			version:  "v0.2.0",
			bump:     "major",
			previous: "v0.1.0",
		},
		"the highest tag wins, whatever order they come in": {
			tags:     "v0.10.0\nv0.9.0\nnightly\nv0.2.0\n",
			commits:  []string{"fix: Something"},
			version:  "v0.10.1",
			bump:     "patch",
			previous: "v0.10.0",
		},
		"nothing released yet": {
			tags:     "",
			commits:  []string{"feat: Plant the tree"},
			version:  "v0.1.0",
			bump:     "initial",
			previous: "",
		},
		"a forced bump wins": {
			tags:     "v1.2.3\n",
			commits:  []string{"fix: Something small"},
			args:     []string{"-bump=minor"},
			version:  "v1.3.0",
			bump:     "minor",
			previous: "v1.2.3",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			summary := filepath.Join(t.TempDir(), "summary")
			args := append([]string{"-output", output, "-summary", summary}, test.args...)

			var stdout bytes.Buffer
			if err := run(args, &stdout, fakeGit(test.tags, test.commits)); err != nil {
				t.Fatalf("run: %v", err)
			}

			got := readOutputs(t, output)
			for key, want := range map[string]string{
				"version": test.version, "bump": test.bump, "previous_tag": test.previous,
			} {
				if got[key] != want {
					t.Errorf("got %s=%q, want %q", key, got[key], want)
				}
			}
			if !strings.Contains(stdout.String(), test.version) {
				t.Errorf("got %q, want the version reported", stdout.String())
			}

			written, err := os.ReadFile(summary)
			if err != nil {
				t.Fatalf("reading the summary: %v", err)
			}
			if !strings.Contains(string(written), test.version) {
				t.Errorf("got summary %q, want the version in it", written)
			}
		})
	}
}

// TestRunReportsUnclassified covers the point of the whole exercise: a change
// nobody prefixed has to be visible before the tag, not after.
func TestRunReportsUnclassified(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	summary := filepath.Join(t.TempDir(), "summary")

	var stdout bytes.Buffer
	err := run([]string{"-output", output, "-summary", summary}, &stdout,
		fakeGit("v1.0.0\n", []string{"Add a whole new transport", "fix: A real fix"}))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := readOutputs(t, output)["unclassified"]; got != "1" {
		t.Errorf("got unclassified=%q, want 1", got)
	}
	if !strings.Contains(stdout.String(), "?") {
		t.Errorf("got %q, want the unreadable change marked", stdout.String())
	}

	written, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("reading the summary: %v", err)
	}
	if !strings.Contains(string(written), "WARNING") {
		t.Errorf("got summary %q, want a warning in it", written)
	}
}

func TestRunRejects(t *testing.T) {
	tests := map[string][]string{
		"a bump nobody has":           {"-bump=huge"},
		"a tag that is not a version": {"-from=nightly"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(args, &bytes.Buffer{}, fakeGit("v1.0.0\n", nil)); err == nil {
				t.Error("got no error, want one")
			}
		})
	}
}

func readOutputs(tb testing.TB, path string) map[string]string {
	tb.Helper()

	written, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("reading the outputs: %v", err)
	}

	values := map[string]string{}
	for line := range strings.Lines(string(written)) {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[key] = value
		}
	}
	return values
}

func TestCheckTitle(t *testing.T) {
	accepted := map[string]string{
		"a feature": "feat: Draw a trace as a tree",
		"a fix":     "fix: Take glue from the right server",
		"a scope":   "chore(deps): Bump miekg/dns",
		"a break":   "feat!: Rename every flag",
		"any case":  "Feat: Draw a trace",
	}
	for name, title := range accepted {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := checkTitle(&out, title); err != nil {
				t.Fatalf("checkTitle(%q): %v", title, err)
			}
			if !strings.Contains(out.String(), "bump") {
				t.Errorf("got %q, want the bump it earns", out.String())
			}
		})
	}

	rejected := map[string]string{
		"no prefix":             "Draw a trace as a tree",
		"a prefix nobody knows": "wip: something",
		"nothing at all":        "",
	}
	for name, title := range rejected {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := checkTitle(&out, title)
			if err == nil {
				t.Fatalf("checkTitle(%q): got no error, want one", title)
			}
			// The prefixes it would have accepted come from the same map the
			// release reads, so the help cannot drift from the rule.
			for _, want := range []string{"feat", "fix", "chore"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("got %q, want it to list %q", err, want)
				}
			}
			if !strings.Contains(out.String(), "::error") {
				t.Errorf("got %q, want an annotation on the pull request", out.String())
			}
		})
	}
}

// TestCheckTitleIsAskedFor covers the flag itself: an empty title has to fail,
// which means the tool must tell an empty -check-title from no -check-title.
func TestCheckTitleIsAskedFor(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-check-title="}, &out, fakeGit("v1.0.0\n", nil)); err == nil {
		t.Error("got no error for an empty title, want one")
	}

	out.Reset()
	if err := run(nil, &out, fakeGit("v1.0.0\n", []string{"fix: Something"})); err != nil {
		t.Errorf("got %v without -check-title, want the version instead", err)
	}
	if !strings.Contains(out.String(), "v1.0.1") {
		t.Errorf("got %q, want the next version", out.String())
	}
}
