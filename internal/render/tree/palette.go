package tree

import (
	"io"
	"os"
)

// ColorMode is when to emit ANSI escapes.
type ColorMode string

// When a rendering emits ANSI escapes.
const (
	ColorAuto   ColorMode = "auto" // only for a terminal that wants colour
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

// The subset of SGR codes the palette needs. Grey is the bright black of the
// 16 colour palette, which survives both light and dark terminals better than
// the faint attribute.
const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	grey    = "\x1b[90m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
)

// painter paints a string, or does not.
type painter bool

func (p painter) paint(text, code string) string {
	if !p || text == "" {
		return text
	}
	return code + text + reset
}

func (p painter) server(name string) string { return p.paint(name, bold) }
func (p painter) dim(text string) string    { return p.paint(text, grey) }

// rcode follows the legend: NOERROR reads well, a refusal or a missing name is
// a warning, and a failure is a failure.
func (p painter) rcode(rcode string) string {
	switch rcode {
	case "NOERROR":
		return p.paint(rcode, green)
	case "NXDOMAIN", "REFUSED", "NOTIMP":
		return p.paint(rcode, yellow)
	case "":
		return ""
	default:
		return p.paint(rcode, red)
	}
}

// rrtype colours a record by what it carries, so a chain of types is legible at
// a glance.
func (p painter) rrtype(rrtype string) string {
	switch rrtype {
	case "A":
		return p.paint(rrtype, green)
	case "AAAA":
		return p.paint(rrtype, blue)
	case "CNAME", "DNAME":
		return p.paint(rrtype, yellow)
	case "TXT", "MX":
		return p.paint(rrtype, magenta)
	default:
		return rrtype
	}
}

// ColorEnabled decides once, for the whole rendering, whether w wants escapes.
// It is exported because the version banner asks the same question before it
// draws, and the answer has to be the one every rendering gives.
func ColorEnabled(w io.Writer, mode ColorMode) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	}

	// https://no-color.org, and a terminal that says it can do nothing.
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if term := os.Getenv("TERM"); term == "" || term == "dumb" {
		return false
	}

	return IsTerminal(w)
}

// IsTerminal reports whether w is something a person is watching, which is the
// only place cursor movement and colour belong.
func IsTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}
