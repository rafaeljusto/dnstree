//go:build !unix

package tree

import "io"

// terminalSize is the size a terminal we cannot measure is assumed to have.
func terminalSize(io.Writer) (width, height int) {
	return fallbackWidth, fallbackHeight
}
