// Package layering holds the rules on who may import what, checked over the
// whole tree. It has no code of its own, only the test that holds them.
package layering_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// codec is the DNS library, and speaks is who may import it. Keeping it out of
// the trace, the renderers and the AS lookups is what lets them be tested
// without a network (AGENTS.md, Layering).
const codec = "codeberg.org/miekg/dns"

var speaks = []string{
	"internal/transport",
	"internal/resolver",
	"internal/dnssec",
	"internal/testutil/fakens", // it has to answer in the wire format
}

// TestOnlyTheWireSpeaksTheCodec holds the layering rule, tests included.
func TestOnlyTheWireSpeaksTheCodec(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); relative != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || slices.Contains(speaks, filepath.ToSlash(filepath.Dir(relative))) {
			return nil
		}
		path = relative

		file, err := parser.ParseFile(fset, filepath.Join(root, path), nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			imported, _ := strconv.Unquote(spec.Path.Value)
			if imported == codec || strings.HasPrefix(imported, codec+"/") {
				t.Errorf("%s imports %s, which only %s may", path, imported, strings.Join(speaks, ", "))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the tree: %v", err)
	}
}

// moduleRoot is the directory holding go.mod, found from wherever the test runs.
func moduleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("finding the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}
