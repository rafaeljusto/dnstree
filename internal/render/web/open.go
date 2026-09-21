package web

import (
	"fmt"
	"os/exec"
	"runtime"
)

// launch is how a browser is opened, a variable so that a test can watch it
// happen without a window appearing.
var launch = browser

// browser asks the desktop to open url, which is how every desktop wants to be
// asked: the command it names is the one a file manager uses for a link. It is
// best effort by design — a machine with no desktop, or none this knows how to
// ask, costs the run nothing, because the address is printed either way.
func browser(url string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		name = "xdg-open"
	}

	// Started rather than waited for: the command that opens a browser may well
	// be the browser, and it outlives the run.
	if err := exec.Command(name, append(args, url)...).Start(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
