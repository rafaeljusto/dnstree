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

// apart are the packages that must not reach the codec through anything they
// import either: the trace, the renderers and the readings drawn from them,
// and the AS lookups. A package that imports one which speaks the codec brings
// the network into their tests all the same.
var apart = []string{
	"internal/trace",
	"internal/render/",
	"internal/explain",
	"internal/expect",
	"internal/history",
	"internal/asn",
}

// TestApartFromTheWire holds the layering rule through every import, so that
// a package kept apart cannot reach the codec by way of another.
func TestApartFromTheWire(t *testing.T) {
	root := moduleRoot(t)
	module := modulePath(t, root)

	// imports maps each package of the module, by its directory, to what its
	// non-test files import.
	imports := map[string][]string{}
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
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(relative))
		for _, spec := range file.Imports {
			imported, _ := strconv.Unquote(spec.Path.Value)
			imports[dir] = append(imports[dir], imported)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the tree: %v", err)
	}

	for dir := range imports {
		if !slices.ContainsFunc(apart, func(prefix string) bool { return dir == prefix || strings.HasPrefix(dir, prefix) }) {
			continue
		}
		if path := reaches(imports, module, dir, map[string]bool{}); path != nil {
			t.Errorf("%s reaches %s through %s; keep it apart from the wire", dir, codec, strings.Join(path, " -> "))
		}
	}
}

// reaches is the chain of imports by which dir comes to the codec, or nil.
func reaches(imports map[string][]string, module, dir string, seen map[string]bool) []string {
	if seen[dir] {
		return nil
	}
	seen[dir] = true
	for _, imported := range imports[dir] {
		if imported == codec || strings.HasPrefix(imported, codec+"/") {
			return []string{imported}
		}
		if inner, ok := strings.CutPrefix(imported, module+"/"); ok {
			if path := reaches(imports, module, inner, seen); path != nil {
				return append([]string{inner}, path...)
			}
		}
	}
	return nil
}

// modulePath is the module's import path, as go.mod declares it.
func modulePath(t *testing.T, root string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	for line := range strings.Lines(string(data)) {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(path)
		}
	}
	t.Fatal("go.mod declares no module")
	return ""
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
