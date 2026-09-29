//go:build !windows

package transport

import "syscall"

// resetErrno is how the system reports a connection its peer reset.
var resetErrno error = syscall.ECONNRESET
