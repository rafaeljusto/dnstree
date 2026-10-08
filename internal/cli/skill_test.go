package cli_test

import (
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/cli"
)

// skillPath is the skill the plugin ships, which teaches a model the flags. It
// is written by hand, so a test reads it instead of a reviewer.
const skillPath = "../../packaging/plugin/skills/dnstree/SKILL.md"

var longFlag = regexp.MustCompile(`--[a-z0-9][a-z0-9-]*`)

// TestSkillFlagsExist fails on a flag the skill names that the usage does not,
// which is what a renamed or dropped flag leaves behind.
func TestSkillFlagsExist(t *testing.T) {
	data, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	// --help comes from the flag package, and the usage is what it prints.
	known := append(longFlag.FindAllString(cli.Usage, -1), "--help")
	for _, name := range longFlag.FindAllString(prose(string(data)), -1) {
		if !slices.Contains(known, name) {
			t.Errorf("the skill names %s, which the usage does not", name)
		}
	}
}

var (
	inlineCommand = regexp.MustCompile("`(dnstree [^`]+)`")

	// placeholders stand in for what a model fills in, with values Parse takes.
	placeholders = strings.NewReplacer(
		"ZONE=NEWSERVER", "example.com=ns1.example.net",
		"SERVER", "ns1.example.net",
		"NAME", "example.com",
		"TYPE", "MX",
		"VALUE", "secure",
	)
)

// TestSkillCommandsParse runs every command the skill shows, in a code block
// or inline, through Parse, so an example that stops being one fails here
// rather than in a model's hands.
func TestSkillCommandsParse(t *testing.T) {
	data, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	commands := fenced(string(data))
	for _, match := range inlineCommand.FindAllStringSubmatch(string(data), -1) {
		commands = append(commands, placeholders.Replace(match[1]))
	}
	if len(commands) == 0 {
		t.Fatal("the skill shows no dnstree command")
	}
	for _, command := range commands {
		// --help is refused by Parse on purpose, so cmd/dnstree can print it.
		if command == "dnstree --help" {
			continue
		}
		t.Run(command, func(t *testing.T) {
			// Redirections and pipes belong to the shell, not to dnstree.
			line, _, _ := strings.Cut(command, " >")
			line, _, _ = strings.Cut(line, " |")
			if strings.ContainsAny(line, `"'$`) {
				t.Fatal("write the example without quotes or variables, so it can be read as arguments")
			}
			args := append([]string{"--no-config"}, strings.Fields(line)[1:]...)
			if _, err := cli.Parse(args, io.Discard); err != nil {
				t.Errorf("Parse: %v", err)
			}
		})
	}
}

// prose is a markdown text without the lines of its code blocks that run some
// other program, whose flags are not dnstree's.
func prose(content string) string {
	var (
		kept   strings.Builder
		inside bool
	)
	for line := range strings.Lines(content) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inside = !inside
		}
		if inside && trimmed != "" && !strings.HasPrefix(trimmed, "```") && !strings.HasPrefix(trimmed, "dnstree ") {
			continue
		}
		kept.WriteString(line)
	}
	return kept.String()
}

// fenced returns the dnstree command lines inside the code blocks of a
// markdown text.
func fenced(content string) []string {
	var (
		found  []string
		inside bool
	)
	for line := range strings.Lines(content) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "```") {
			inside = !inside
			continue
		}
		if inside && strings.HasPrefix(line, "dnstree ") {
			found = append(found, line)
		}
	}
	return found
}
