//go:build unix

package history_test

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/history"
)

// TestLoadIgnoresAFIFO is a FIFO planted in a cache somebody else can write
// to: opened to be read, with nobody writing, it would hold the run forever.
func TestLoadIgnoresAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "www.test_a.json"), 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}

	done := make(chan *history.Walk, 1)
	go func() { done <- history.Load(dir, question()) }()
	select {
	case walk := <-done:
		if walk != nil {
			t.Errorf("got %+v, want nothing read", walk)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load still waiting on the FIFO")
	}
}
