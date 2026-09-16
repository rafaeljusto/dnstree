//go:build unix

package tree

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// terminalSize asks the terminal how much room a frame has, in columns and
// rows.
func terminalSize(w io.Writer) (width, height int) {
	file, ok := w.(*os.File)
	if !ok {
		return fallbackWidth, fallbackHeight
	}
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil || size.Col == 0 || size.Row == 0 {
		return fallbackWidth, fallbackHeight
	}
	return int(size.Col), int(size.Row)
}
