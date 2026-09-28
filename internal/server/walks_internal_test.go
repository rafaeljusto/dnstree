package server

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

func always() bool { return true }

func made(size int) func(context.Context) (*walked, error) {
	return func(context.Context) (*walked, error) {
		return &walked{page: bytes.Repeat([]byte("x"), size)}, nil
	}
}

func TestWalksKeptWithinTheirBytes(t *testing.T) {
	w := newWalks(1, time.Minute, time.Second)

	for i := range maxKeptBytes/(512<<10) + 4 {
		if _, err := w.get(t.Context(), strconv.Itoa(i), always, made(512<<10)); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if w.bytes > maxKeptBytes {
		t.Errorf("got %d bytes kept, want no more than %d", w.bytes, maxKeptBytes)
	}
	if _, ok := w.kept["0"]; ok {
		t.Error("got the oldest walk still kept, want it let go to make room")
	}

	if _, err := w.get(t.Context(), "huge", always, made(maxWalkBytes+1)); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, ok := w.kept["huge"]; ok {
		t.Error("got a walk larger than any is kept, want it served and not kept")
	}
}

func TestWalksLetGoOfTheExpired(t *testing.T) {
	w := newWalks(1, time.Nanosecond, time.Second)
	for _, key := range []string{"a", "b", "c"} {
		if _, err := w.get(t.Context(), key, always, made(10)); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if len(w.kept) != 1 || w.bytes != 10 {
		t.Errorf("got %d walks in %d bytes kept, want only the last", len(w.kept), w.bytes)
	}
}

func TestWalksBusy(t *testing.T) {
	w := newWalks(1, time.Minute, 20*time.Millisecond)
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_, _ = w.get(context.Background(), "slow", always, func(context.Context) (*walked, error) {
			close(started)
			<-release
			return &walked{}, nil
		})
	}()
	<-started
	defer close(release)

	if _, err := w.get(t.Context(), "other", always, made(1)); !errors.Is(err, errBusy) {
		t.Errorf("got %v, want %v while the only room is taken", err, errBusy)
	}
}

// TestWalksOutliveWhoAskedFirst covers the first visitor leaving while the walk
// waits for room: the others asking the same question still get it.
func TestWalksOutliveWhoAskedFirst(t *testing.T) {
	w := newWalks(1, time.Minute, time.Second)
	w.running <- struct{}{} // the only room is taken, for now

	first, leave := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := w.get(first, "q", always, made(1))
		result <- err
	}()
	for {
		w.mu.Lock()
		_, waiting := w.inFlight["q"]
		w.mu.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	leave()
	<-w.running

	if err := <-result; err != nil {
		t.Errorf("got %v, want the walk made once there was room", err)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(2, time.Minute)
	start := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

	for _, step := range []struct {
		name   string
		client string
		at     time.Duration
		want   bool
	}{
		{"the first walk", "a", 0, true},
		{"the second walk", "a", time.Second, true},
		{"one too many", "a", 2 * time.Second, false},
		{"somebody else", "b", 3 * time.Second, true},
		{"a minute on, counted again", "a", time.Minute, true},
	} {
		if got := l.allow(step.client, start.Add(step.at)); got != step.want {
			t.Errorf("%s: got %t, want %t", step.name, got, step.want)
		}
	}
}
