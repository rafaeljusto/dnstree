package cli_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/cli"
)

// examplePath is the annotated file of defaults the repository ships. It is
// the one description of the surface that is written by hand rather than
// rendered from the usage, so a test reads it instead of a reviewer.
const examplePath = "../../dnstreerc.example"

// TestExampleParses reads the example as it ships, and then every block of
// settings in it with the comment markers taken off. A flag that is renamed or
// dropped, or an example value that stops being one, fails here rather than in
// the hands of whoever copied the file.
func TestExampleParses(t *testing.T) {
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("as it ships", func(t *testing.T) {
		parseFile(t, string(data))
	})

	for _, block := range blocks(string(data)) {
		t.Run(block, func(t *testing.T) {
			parseFile(t, block)
		})
	}
}

// blocks are the runs of adjacent setting lines, which is how the file groups
// the settings that belong together: the transport a --tls-ca needs, the roots
// a walk starts from. Anything else ends a run, so two settings that contradict
// each other are never read as one file.
func blocks(content string) []string {
	var (
		found   []string
		current []string
	)
	end := func() {
		if len(current) > 0 {
			found = append(found, strings.Join(current, "\n"))
			current = nil
		}
	}
	for line := range strings.Lines(content) {
		if setting, ok := uncomment(line); ok {
			current = append(current, setting)
			continue
		}
		end()
	}
	end()
	return found
}

// uncomment reports a commented setting as the line it stands for. A setting is
// a name and a value around an equals sign, which is how every example in the
// file is written; a comment that reads as a sentence has spaces where the name
// would be, and is prose.
func uncomment(line string) (string, bool) {
	text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
	name, _, ok := strings.Cut(text, "=")
	if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(strings.TrimSpace(name), " \t") {
		return "", false
	}
	return text, true
}

// parseFile runs content through Parse the way the file of defaults is read.
func parseFile(t *testing.T, content string) {
	t.Helper()

	t.Setenv(cli.ConfigEnv, write(t, content))
	if _, err := cli.Parse([]string{"example.com"}, io.Discard); err != nil {
		t.Errorf("Parse: %v\n%s", err, content)
	}
}
