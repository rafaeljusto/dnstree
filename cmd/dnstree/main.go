// Command dnstree resolves a name iteratively from the root servers and draws
// the delegation path it followed.
package main

import (
	"fmt"
	"os"
)

const usage = `usage: dnstree [flags] NAME [TYPE]

dnstree is still being built: flag parsing and the iterative engine are not
wired up yet.
`

func main() {
	fmt.Fprint(os.Stderr, usage)
	os.Exit(1)
}
