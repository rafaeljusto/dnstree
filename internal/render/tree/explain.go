package tree

import (
	"bufio"
	"io"

	"github.com/rafaeljusto/dnstree/internal/explain"
)

// Explain writes findings under the tree they were read off: one sentence to a
// line, set apart from the summary by a blank line. It is prose about a
// resolution, so it belongs only to the formats a person reads; --format json
// and --format dot carry the same facts in the fields a program reads instead.
//
// What is in the list is the caller's business. The sentences the trace says
// about itself come from [explain.Findings], and what has changed since the
// last walk of the same question from the history package.
func Explain(w io.Writer, findings []explain.Finding, opts Options) {
	if len(findings) == 0 {
		return
	}

	paint := painter(colorEnabled(w, opts.Color))
	bullet := "· "
	if opts.Charset == ASCII {
		bullet = "- "
	}

	out := bufio.NewWriter(w)
	_, _ = out.WriteString("\n")
	for _, finding := range findings {
		_, _ = out.WriteString(paint.dim(bullet) + paint.finding(finding) + "\n")
	}
	_ = out.Flush()
}

// finding colours a sentence by how much it matters, leaving a note in the grey
// the summary is written in: what is wrong should be the only thing that draws
// the eye down here.
func (p painter) finding(finding explain.Finding) string {
	switch finding.Level {
	case explain.Fault:
		return p.paint(finding.Text, red)
	case explain.Warn:
		return p.paint(finding.Text, yellow)
	default:
		return p.dim(finding.Text)
	}
}
