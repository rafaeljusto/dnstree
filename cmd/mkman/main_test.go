package main

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/cli"
)

func TestParse(t *testing.T) {
	tests := map[string]struct {
		usage string
		err   bool
	}{
		"a usage text with every part": {
			usage: "usage: dnstree [flags] NAME\n\nWhat it does.\n\n  --all   ask everyone\n\nExit codes: 0 fine.\n",
		},
		"exit codes as one indented entry per line": {
			usage: "usage: dnstree NAME\n\nWhat it does.\n\n  --all   ask everyone\n\nExit codes:\n  0 fine\n  1 not.\n",
		},
		"a synopsis of more than one line": {
			usage: "usage: dnstree NAME\nusage: dnstree TYPE\n\nWhat it does.\n\n  --all   ask everyone\n\nExit codes: 0 fine.\n",
			err:   true,
		},
		"a text that does not open with the synopsis": {
			usage: "dnstree [flags] NAME\n\n  --all   ask everyone\n\nExit codes: 0 fine.\n",
			err:   true,
		},
		"an indented line that is not a flag": {
			usage: "usage: dnstree NAME\n\nWhat it does.\n\n  --all\n\nExit codes: 0 fine.\n",
			err:   true,
		},
		"an exit code that is not a number": {
			usage: "usage: dnstree NAME\n\nWhat it does.\n\n  --all   ask everyone\n\nExit codes: fine.\n",
			err:   true,
		},
		"no flags at all": {
			usage: "usage: dnstree NAME\n\nWhat it does.\n\nExit codes: 0 fine.\n",
			err:   true,
		},
		"nothing saying what the command does": {
			usage: "usage: dnstree NAME\n\n  --all   ask everyone\n\nExit codes: 0 fine.\n",
			err:   true,
		},
		"an empty text": {
			usage: "",
			err:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parse(tt.usage)
			if tt.err && err == nil {
				t.Fatalf("got no error, want one")
			}
			if !tt.err && err != nil {
				t.Fatalf("got error %v, want none", err)
			}
		})
	}
}

// The page is only worth generating while it says what the binary says, so
// every flag and every exit code the command prints has to reach it.
func TestRenderCoversTheCommandLine(t *testing.T) {
	doc, err := parse(cli.Usage)
	if err != nil {
		t.Fatalf("got error %v, want none", err)
	}

	page := render(doc, "0.1.2", "2026-09-16")

	for _, opt := range doc.options {
		for word := range strings.FieldsSeq(strings.ReplaceAll(opt.flags, ",", " ")) {
			if !strings.HasPrefix(word, "-") {
				continue
			}
			if !strings.Contains(page, `\fB`+roff(word)+`\fR`) {
				t.Errorf("got a page without %s", word)
			}
		}
	}

	// Every flag line of the usage text became an option in the page.
	if got, want := strings.Count(page, ".TP\n"), len(doc.options)+len(doc.exits); got != want {
		t.Errorf("got %d tagged paragraphs, want %d", got, want)
	}

	for _, want := range []string{
		`.TH DNSTREE 1 "2026-09-16" "dnstree 0.1.2" "User Commands"`,
		".SH NAME", ".SH SYNOPSIS", ".SH DESCRIPTION", ".SH OPTIONS",
		".SH EXIT STATUS", ".SH EXAMPLES", ".SH SEE ALSO",
		"dnstree \\- " + roff(cli.Summary),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("got a page without %q", want)
		}
	}

	for _, code := range []string{"0", "1", "2", "3"} {
		if !strings.Contains(page, "\\fB"+code+"\\fR\n") {
			t.Errorf("got a page without exit code %s", code)
		}
	}
}

// A control character at the start of a line is a request, and an unescaped
// backslash swallows what follows it.
func TestRoff(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"a hyphen is the minus sign a flag needs": {in: "--all", want: `\-\-all`},
		"a backslash is escaped":                  {in: `a \ b`, want: `a \e b`},
		"a leading dot is not a request":          {in: ".TH", want: `\&.TH`},
		"a leading quote is not a request":        {in: "'tis", want: `\&'tis`},
		"a dot inside a line is left alone":       {in: "end. next", want: "end. next"},
		"a later line is escaped too":             {in: "one\n.two", want: "one\n\\&.two"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := roff(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFlagSpec(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"one flag":                  {in: "--all", want: `\fB\-\-all\fR`},
		"a flag and its alias":      {in: "-4, -6", want: `\fB\-4\fR, \fB\-6\fR`},
		"a flag that takes a value": {in: "--format FORMAT", want: `\fB\-\-format\fR \fIFORMAT\fR`},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := flagSpec(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSynopsis(t *testing.T) {
	got := synopsis("dnstree [flags] NAME [TYPE]")
	want := ".B dnstree\n[\\fIflags\\fR] \\fINAME\\fR [\\fITYPE\\fR]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
