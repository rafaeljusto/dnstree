package tree

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// The SGR codes the mark is painted with. They stay inside the 16 colour
// palette for the reason the tree does: those survive a light terminal and a
// dark one alike, where a 256 colour ramp is at the mercy of the theme.
const (
	MarkReset = "\x1b[0m"
	MarkBold  = "\x1b[1m"
	MarkGrey  = "\x1b[90m"

	// Bright blue is the nearest the 16 colours come to the accent the mark is
	// drawn in everywhere else. Plain blue is the one colour that disappears
	// against a dark terminal, which is where this is mostly read.
	MarkBlue = "\x1b[94m"
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

// WriteMark draws the logo with lines of text beside the middle of it. It is
// for a terminal that has already been found to want colour: the version and
// the address of a served page are both parsed off a pipe, and a caller asks
// ColorEnabled before it decorates either.
//
// The charset picks which mark: --format ascii already means the terminal is
// not to be trusted with anything clever, so it says the same thing here.
func WriteMark(w io.Writer, charset Charset, beside []string) {
	rows := markBraille[:]
	if charset == ASCII {
		rows = markASCII[:]
	}

	width := 0
	for _, row := range rows {
		width = max(width, utf8.RuneCountInString(row))
	}
	top := (len(rows) - len(beside)) / 2

	for i, row := range rows {
		line := i - top
		if line < 0 || line >= len(beside) {
			fmt.Fprintln(w, MarkBlue+row+MarkReset)
			continue
		}
		pad := strings.Repeat(" ", width-utf8.RuneCountInString(row))
		fmt.Fprintf(w, "%s%s   %s\n", MarkBlue+row+MarkReset, pad, beside[line])
	}
}
