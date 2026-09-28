package server

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	errLimited = errors.New("server: the client has started enough walks for now")
	errBusy    = errors.New("server: no room for another walk")
)

// How much of the finished walks is kept, and the most one of them may take.
// The trace keeps every record a zone answers with, so a zone somebody built
// for it can make one walk far larger than the few kilobytes most come to.
const (
	maxKeptBytes = 32 << 20
	maxWalkBytes = 1 << 20
)

// walked is one finished walk, as the pages read it.
type walked struct {
	page, traceDoc []byte
	until          time.Time
}

func (w *walked) size() int { return len(w.page) + len(w.traceDoc) }

// call is a walk under way, which everybody asking the same question waits on.
type call struct {
	done chan struct{}
	made *walked
	err  error
}

// walks are the walks running and the ones just finished. The page asks for the
// walk it draws the moment it loads, a link handed round is opened by many
// people at once, and none of that is worth another trip from the root.
type walks struct {
	running chan struct{}
	keep    time.Duration
	queue   time.Duration // how long a walk waits for room before it is turned away

	mu       sync.Mutex
	kept     map[string]*walked
	bytes    int
	inFlight map[string]*call
}

func newWalks(atOnce int, keep, queue time.Duration) *walks {
	return &walks{
		running:  make(chan struct{}, atOnce),
		keep:     keep,
		queue:    queue,
		kept:     make(map[string]*walked),
		inFlight: make(map[string]*call),
	}
}

// get is the walk for key: kept, under way, or made now if admit lets it.
func (w *walks) get(ctx context.Context, key string, admit func() bool,
	walk func(context.Context) (*walked, error)) (*walked, error) {

	w.mu.Lock()
	if made, ok := w.kept[key]; ok && time.Now().Before(made.until) {
		w.mu.Unlock()
		return made, nil
	}
	if running, ok := w.inFlight[key]; ok {
		w.mu.Unlock()
		select {
		case <-running.done:
			return running.made, running.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !admit() {
		w.mu.Unlock()
		return nil, errLimited
	}
	running := &call{done: make(chan struct{})}
	w.inFlight[key] = running
	w.mu.Unlock()

	running.made, running.err = w.run(ctx, walk)

	w.mu.Lock()
	delete(w.inFlight, key)
	if running.err == nil {
		now := time.Now()
		running.made.until = now.Add(w.keep)
		w.store(key, running.made, now)
	}
	w.mu.Unlock()
	close(running.done)
	return running.made, running.err
}

// run waits a little for room among the walks running, and makes this one. The
// wait is not the request's: others asking the same question are waiting on
// it, and the one who asked first leaving is no reason to turn them away.
func (w *walks) run(ctx context.Context, walk func(context.Context) (*walked, error)) (*walked, error) {
	queued, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.queue)
	defer cancel()
	select {
	case w.running <- struct{}{}:
	case <-queued.Done():
		return nil, errBusy
	}
	defer func() { <-w.running }()
	return walk(ctx)
}

// store keeps a walk, making room first by letting go of the ones past their
// time and then the ones nearest it. The mutex is held.
func (w *walks) store(key string, made *walked, now time.Time) {
	if made.size() > maxWalkBytes {
		return
	}
	if old, ok := w.kept[key]; ok {
		w.bytes -= old.size()
		delete(w.kept, key)
	}
	for other, kept := range w.kept {
		if !now.Before(kept.until) {
			w.bytes -= kept.size()
			delete(w.kept, other)
		}
	}
	for w.bytes+made.size() > maxKeptBytes && len(w.kept) > 0 {
		var soonest string
		for other, kept := range w.kept {
			if soonest == "" || kept.until.Before(w.kept[soonest].until) {
				soonest = other
			}
		}
		w.bytes -= w.kept[soonest].size()
		delete(w.kept, soonest)
	}
	w.kept[key] = made
	w.bytes += made.size()
}

// limiter counts the walks each client starts in a window, and forgets them all
// when the window turns over, so that it holds no more than one window of
// clients.
type limiter struct {
	per    int
	window time.Duration

	mu     sync.Mutex
	since  time.Time
	counts map[string]int
}

func newLimiter(per int, window time.Duration) *limiter {
	return &limiter{per: per, window: window, counts: make(map[string]int)}
}

func (l *limiter) allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.since) >= l.window {
		l.since = now
		clear(l.counts)
	}
	if l.counts[client] >= l.per {
		return false
	}
	l.counts[client]++
	return true
}
