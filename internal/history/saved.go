package history

import (
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// maxSaved is the most files --history reads from one directory. Each is a
// whole walk to parse, so a longer history is read a stretch at a time.
const maxSaved = 20000

// Saved is what a directory of walks --format json wrote holds of one
// question.
type Saved struct {
	// Walks are those of the question, oldest first, each moment once.
	Walks []*Walk

	// Newest is the last of them in full, to be drawn.
	Newest *trace.Trace

	// Unread is each file that held no walk that could be read, with why,
	// escaped: a file name is anybody's to choose.
	Unread []string

	// Others counts the walks of other questions, which are left alone.
	Others int
}

// ReadDir reads every walk of the question saved in dir, as .json or
// .json.gz, with read, which is how --format json is read back: this package
// keeps no format of its own for a walk. Nothing is written. A file that
// holds no walk costs that file, never the rest.
func ReadDir(dir string, question trace.Question, read func(io.Reader) (*trace.Trace, error)) (*Saved, error) {
	// Opened within the directory, so that a link there cannot point a read
	// anywhere else.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".") && (strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz")) {
			files = append(files, name)
		}
	}
	if len(files) > maxSaved {
		return nil, fmt.Errorf("%s holds %d walks, and --history reads at most %d; move the older ones aside",
			dir, len(files), maxSaved)
	}

	saved := &Saved{}
	for _, name := range files {
		tr, err := readSaved(root, name, read)
		if err != nil {
			saved.Unread = append(saved.Unread, trace.Shown(fmt.Sprintf("%s: %v", name, err)))
			continue
		}
		if tr.Started.IsZero() {
			saved.Unread = append(saved.Unread, trace.Shown(name)+": it does not say when the walk was made")
			continue
		}
		walk := Of(tr, tr.Started)
		if !walk.Asks(question.Name, question.Type, question.Class) {
			saved.Others++
			continue
		}
		// The same moment twice is the same walk copied, and would read as a
		// stretch of no time at all.
		if slices.ContainsFunc(saved.Walks, func(w *Walk) bool { return w.Seen.Equal(walk.Seen) }) {
			continue
		}
		saved.Walks = append(saved.Walks, walk)
		if saved.Newest == nil || tr.Started.After(saved.Newest.Started) {
			saved.Newest = tr
		}
	}
	if len(saved.Walks) == 0 {
		return saved, fmt.Errorf("%s holds no walk of %s %s", dir, question.Name, question.Type)
	}
	slices.SortStableFunc(saved.Walks, func(a, b *Walk) int { return a.Seen.Compare(b.Seen) })
	return saved, nil
}

// readSaved is one file's walk. A FIFO planted in the directory would hold
// the open forever, so it does not wait, and only a plain file is read.
func readSaved(root *os.Root, name string, read func(io.Reader) (*trace.Trace, error)) (*trace.Trace, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a plain file")
	}

	var r io.Reader = f
	if strings.HasSuffix(name, ".gz") {
		// The reader of a walk stops at its own size limit, which bounds
		// what a small file can expand into as well.
		z, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		r = z
	}
	return read(r)
}

// FirstSeen is when the walks, read in order, first saw each key and DS, for
// --rollover to time its steps from as --diff would have.
func (s *Saved) FirstSeen() trace.Seen {
	for i := 1; i < len(s.Walks); i++ {
		s.Walks[i].Carry(s.Walks[i-1])
	}
	return s.Walks[len(s.Walks)-1].FirstSeen()
}
