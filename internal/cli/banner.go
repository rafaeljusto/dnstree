package cli

import (
	"fmt"
	"io"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
)

// home is where the banner sends anyone who wants more than a version.
const home = "github.com/rafaeljusto/dnstree"

// WriteVersion says which build this is.
//
// A terminal that wants colour gets the mark drawn beside the version. Anything
// else gets the single line it has always got, because a version is parsed by
// install scripts and CI far more often than it is looked at, and drawing over
// that would break them for decoration.
func WriteVersion(w io.Writer, version string, charset tree.Charset, mode tree.ColorMode) {
	if !tree.ColorEnabled(w, mode) {
		fmt.Fprintln(w, "dnstree "+version)
		return
	}
	tree.WriteMark(w, charset, []string{
		tree.MarkBold + "dnstree " + version + tree.MarkReset,
		tree.MarkGrey + home + tree.MarkReset,
	})
}
