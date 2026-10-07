// Package output reads what a command writes while it is still running.
package output

import (
	"bytes"
	"regexp"
	"sync"
	"testing"
	"time"
)

// Buffer is written by the command's goroutine and read by the test's.
type Buffer struct {
	mutex sync.Mutex
	buf   bytes.Buffer
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buf.Write(p)
}

func (b *Buffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buf.String()
}

// Await waits for pattern to turn up in what has been written, and returns
// what it matched.
func (b *Buffer) Await(tb testing.TB, pattern string) string {
	tb.Helper()

	re := regexp.MustCompile(pattern)
	for range 400 {
		if found := re.FindString(b.String()); found != "" {
			return found
		}
		time.Sleep(10 * time.Millisecond)
	}
	tb.Fatalf("got %q, want %s in it", b.String(), pattern)
	return ""
}

// Address is the pattern of the line that says where a page is served.
const Address = `http://[^\s]+/`
