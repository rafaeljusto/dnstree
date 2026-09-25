package cli

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
)

// home is where the banner sends anyone who wants more than a version.
const home = "github.com/rafaeljusto/dnstree"

// The SGR codes the banner paints with. They stay inside the 16 colour palette
// for the reason internal/render/tree gives: those survive a light terminal and
// a dark one alike, where a 256 colour ramp is at the mercy of the theme.
const (
	bannerReset = "\x1b[0m"
	bannerBold  = "\x1b[1m"
	bannerGrey  = "\x1b[90m"

	// Bright blue is the nearest the 16 colours come to the accent the mark is
	// drawn in everywhere else. Plain blue is the one colour that disappears
	// against a dark terminal, which is where this is mostly read.
	bannerBlue = "\x1b[94m"
)

// markBraille is the logo drawn in braille, where every cell is two dots wide
// and four tall and so carries detail no single character can. It is generated
// from docs/mark.svg, and the blanks in it are ordinary spaces rather than
// U+2800: a blank braille cell looks like a space without being one, and would
// leave the lines carrying whitespace that nothing trims.
var markBraille = [...]string{
	`        ⣶⡄  ⢀⣶`,
	`      ⢀ ⠈⢿⣆⣠⡿⠃⢀⣤⡀`,
	`    ⣀⡀⢿⣷⡀ ⣿⣿⠁⣠⣿⠟⣀⣀`,
	`    ⠉⠛⠳⢿⣿⣆⣿⣿⣼⡿⠟⠛⠋⠉`,
	`        ⠈⢿⣿⣿⠟`,
	`          ⣿⣿`,
	`          ⣿⣿`,
	`          ⣿⣿⡆`,
	`         ⠸⠿⠿⠇`,
}

// markASCII is the same logo in the characters every terminal already has.
// Nothing in it goes above codepoint 127, for the reason --format ascii does
// not: it has to draw the same in a font that was never asked to do more than
// code, and braille is a step further out than the branches of a tree are.
var markASCII = [...]string{
	`   \ | /`,
	`    \|/`,
	` \   |   /`,
	`  \__|__/`,
	`     |`,
	`    _|_`,
}

// WriteVersion says which build this is.
//
// A terminal that wants colour gets the mark drawn beside the version. Anything
// else gets the single line it has always got, because a version is parsed by
// install scripts and CI far more often than it is looked at, and drawing over
// that would break them for decoration.
//
// The charset picks which mark: --format ascii already means the terminal is
// not to be trusted with anything clever, so it says the same thing here.
func WriteVersion(w io.Writer, version string, charset tree.Charset, mode tree.ColorMode) {
	if !tree.ColorEnabled(w, mode) {
		fmt.Fprintln(w, "dnstree "+version)
		return
	}

	rows := markBraille[:]
	if charset == tree.ASCII {
		rows = markASCII[:]
	}

	width := 0
	for _, row := range rows {
		width = max(width, utf8.RuneCountInString(row))
	}

	beside := []string{
		bannerBold + "dnstree " + version + bannerReset,
		bannerGrey + home + bannerReset,
	}
	top := (len(rows) - len(beside)) / 2 // the text sits against the middle of the mark

	for i, row := range rows {
		line := i - top
		if line < 0 || line >= len(beside) {
			fmt.Fprintln(w, bannerBlue+row+bannerReset)
			continue
		}
		pad := strings.Repeat(" ", width-utf8.RuneCountInString(row))
		fmt.Fprintf(w, "%s%s   %s\n", bannerBlue+row+bannerReset, pad, beside[line])
	}
}
