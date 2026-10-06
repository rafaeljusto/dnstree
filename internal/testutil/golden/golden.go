// Package golden compares what a renderer drew with the file in testdata that
// holds what it drew last, and rewrites the file under go test -update.
package golden

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// The Makefile's goldens target finds the packages to ask by their use of
// Compare: go test refuses -update in a package that does not import this one.
var update = flag.Bool("update", false, "rewrite the golden files")

// Updating reports whether the run was asked to rewrite the golden files.
func Updating() bool { return *update }

// Compare checks got against testdata/name.golden, or writes it there under
// -update.
func Compare(tb testing.TB, name, got string) {
	tb.Helper()

	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			tb.Fatalf("writing %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("%v (run go test -update to create it)", err)
	}
	if got != string(want) {
		tb.Errorf("output does not match %s, run go test -update to see the change\n--- got ---\n%s\n--- want ---\n%s",
			path, got, want)
	}
}
