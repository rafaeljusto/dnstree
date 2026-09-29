package transport

import "syscall"

// resetErrno is how Windows reports a reset, which the ECONNRESET the syscall
// package invents for it does not match.
var resetErrno error = syscall.WSAECONNRESET
