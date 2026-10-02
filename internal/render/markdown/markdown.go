// Package markdown writes a walk as a short report to paste into a ticket, an
// incident write-up, a pull request or a chat: what was asked and what it came
// to, the tree, what the walk says about itself, and what the resolvers made
// of the same question.
package markdown

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Render writes the report. The findings are the caller's, as they are for
// [tree.Explain]: a report always says what the walk came to, so the caller
// passes the sentences --explain would print whether or not it was asked for.
//
// Only what Markdown agrees on nearly everywhere is used: a heading, a code
// fence, a list and a table. Everything a server wrote is escaped, so a name
// or a record cannot open a link, a tag or a table cell of its own.
func Render(w io.Writer, tr *trace.Trace, findings []explain.Finding) error {
	if tr == nil {
		return nil
	}
	shown := tr.Shown()

	// The tree is drawn by the tree renderer, so the report and the terminal
	// cannot come to disagree about the walk. It goes in a fence, where
	// nothing needs escaping and its columns stay where they were drawn.
	var drawn bytes.Buffer
	plain := tree.Options{Charset: tree.Unicode, Color: tree.ColorNever}
	if err := tree.Render(&drawn, tr, plain); err != nil {
		return err
	}
	tree.Summary(&drawn, tr, plain)

	out := bufio.NewWriter(w)
	fmt.Fprintf(out, "### %s: %s\n\n", code(shown.Question.Name+" "+shown.Question.Type), verdict(shown))
	if !shown.Started.IsZero() {
		fmt.Fprintf(out, "walked on %s\n\n", shown.Started.UTC().Format("2006-01-02 15:04 MST"))
	}
	fence := strings.Repeat("`", max(3, longestRun(drawn.String(), '`')+1))
	fmt.Fprintf(out, "%s\n%s%s\n", fence, drawn.String(), fence)

	if len(findings) > 0 {
		_, _ = out.WriteString("\n**what happened**\n\n")
		for _, finding := range findings {
			fmt.Fprintf(out, "- %s%s\n", level(finding.Level), escape(finding.Text))
		}
	}

	if len(shown.Resolvers) > 0 {
		_, _ = out.WriteString("\n**resolvers**\n\n| resolver | answer | time |\n| --- | --- | --- |\n")
		for _, answer := range shown.Resolvers {
			if answer == nil {
				continue
			}
			fmt.Fprintf(out, "| %s | %s | %s |\n",
				escape(resolverName(answer.Server)), said(shown, answer), elapsed(answer))
		}
	}
	return out.Flush()
}

// verdict is what the heading says the walk came to, in the summary's own
// word, and how far the chain of trust got where it was followed.
func verdict(tr *trace.Trace) string {
	text := tree.Verdict(tr)
	if chain := tr.Chain(); chain != nil && text != "bogus" {
		text += ", " + escape(string(chain.DNSSEC.State))
	}
	return text
}

// level marks what a colour would have marked in a terminal. A note is what
// most of them are, and goes unmarked.
func level(l explain.Level) string {
	switch l {
	case explain.Fault:
		return "✘ "
	case explain.Warn:
		return "⚠ "
	default:
		return ""
	}
}

// said is one resolver's answer, held against the walk's in a word where the
// two agree, as the table cell writes it.
func said(tr *trace.Trace, answer *trace.Resolver) string {
	switch {
	case answer.Err != "":
		return "did not answer"
	case answer.Match == trace.MatchSame:
		return "agrees"
	}

	result := tr.Result()
	switch {
	case answer.Match != trace.MatchDiffers || result == nil:
		if answer.Rcode == "" {
			return "-"
		}
		return "answered " + escape(answer.Rcode)
	case result.Rcode != answer.Rcode:
		return "differs: " + escape(answer.Rcode) + " where the walk found " + escape(result.Rcode)
	}
	answers := trace.Answers(answer.Records, tr.Question.Type)
	for i, text := range answers {
		answers[i] = data(text)
	}
	return "differs: " + tree.List(answers)
}

// data is record data as a table cell holds it. Escaping is not enough here:
// GitHub links URLs and notifies @mentions after escapes are read, but never
// inside a code span. A bar is written the way the DNS writes any octet, since
// the table splits on one even there. Empty, a span would be two backticks.
func data(text string) string {
	if text == "" {
		return "-"
	}
	return code(strings.ReplaceAll(text, "|", `\124`))
}

func resolverName(server trace.Server) string {
	switch {
	case !server.IP.IsValid():
		return "the resolver"
	case server.Port == 0 || server.Port == 53:
		return server.IP.String()
	default:
		return netip.AddrPortFrom(server.IP, server.Port).String()
	}
}

func elapsed(answer *trace.Resolver) string {
	if answer.Err != "" {
		return "-"
	}
	if answer.Elapsed >= time.Second {
		return answer.Elapsed.Round(100 * time.Millisecond).String()
	}
	return answer.Elapsed.Round(time.Millisecond).String()
}

// escape keeps text from meaning anything to Markdown. CommonMark lets any
// ASCII punctuation be escaped with a backslash, and GitHub reads \| inside a
// table cell as a bar rather than the end of it. Only what could mean
// something is escaped, since every backslash is noise where a paste is read
// raw: a heading, a list or a quote can only open a line, and a link cannot
// open without its bracket.
func escape(text string) string {
	const inline, opening = "\\`*_[]<>|~&", "#+->"
	// An ordered list opens with digits and a dot or a bracket, then a space.
	numbered := strings.IndexFunc(text, func(r rune) bool { return r < '0' || r > '9' })
	if numbered < 1 || !strings.HasPrefix(text[numbered:], ". ") && !strings.HasPrefix(text[numbered:], ") ") {
		numbered = -1
	}

	var b strings.Builder
	for i, r := range text {
		if strings.ContainsRune(inline, r) || (i == 0 && strings.ContainsRune(opening, r)) || i == numbered {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// code is text as a code span, delimited by more backticks than it holds in a
// row so that none of its own can end it. A span that starts or ends with a
// backtick is padded, which CommonMark strips again.
func code(text string) string {
	delimiter := strings.Repeat("`", longestRun(text, '`')+1)
	if strings.HasPrefix(text, "`") || strings.HasSuffix(text, "`") {
		text = " " + text + " "
	}
	return delimiter + text + delimiter
}

func longestRun(text string, c rune) int {
	longest, run := 0, 0
	for _, r := range text {
		if r != c {
			run = 0
			continue
		}
		run++
		longest = max(longest, run)
	}
	return longest
}
