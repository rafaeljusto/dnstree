package history_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/history"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// readWalk stands in for the reader of --format json: a file is a question
// and when its walk began, which is all ReadDir looks at.
func readWalk(r io.Reader) (*trace.Trace, error) {
	var doc struct {
		Name, Type string
		Started    time.Time
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, errors.New("not a trace")
	}
	return &trace.Trace{Question: trace.Question{Name: doc.Name, Type: doc.Type, Class: "IN"}, Started: doc.Started}, nil
}

func walkFile(t *testing.T, dir, name, question string, started time.Time) {
	t.Helper()
	q := strings.Fields(question)
	data, _ := json.Marshal(map[string]any{"Name": q[0], "Type": q[1], "Started": started})
	if strings.HasSuffix(name, ".gz") {
		var buf bytes.Buffer
		z := gzip.NewWriter(&buf)
		_, _ = z.Write(data)
		_ = z.Close()
		data = buf.Bytes()
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadDir(t *testing.T) {
	dir := t.TempDir()
	walkFile(t, dir, "b.json", "www.test. A", seen.Add(10*time.Minute))
	walkFile(t, dir, "a.json", "www.test. A", seen.Add(5*time.Minute))
	walkFile(t, dir, "c.json.gz", "www.test. A", seen)
	walkFile(t, dir, "copy.json", "www.test. A", seen) // the same moment twice
	walkFile(t, dir, "other.json", "mail.test. MX", seen)
	walkFile(t, dir, "undated.json", "www.test. A", time.Time{})
	walkFile(t, dir, ".hidden.json", "www.test. A", seen.Add(time.Hour))
	walkFile(t, dir, "notes.txt", "www.test. A", seen.Add(time.Hour))
	for _, name := range []string{"broken.json", "\x1b[41mred.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	walkFile(t, filepath.Dir(outside), "outside.json", "www.test. A", seen.Add(2*time.Hour))
	if err := os.Symlink(outside, filepath.Join(dir, "link.json")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}

	saved, err := history.ReadDir(dir, trace.Question{Name: "www.test", Type: "A", Class: "IN"}, readWalk)
	if err != nil {
		t.Fatal(err)
	}

	var got []time.Duration
	for _, walk := range saved.Walks {
		got = append(got, walk.Seen.Sub(seen))
	}
	if want := []time.Duration{0, 5 * time.Minute, 10 * time.Minute}; !slices.Equal(got, want) {
		t.Errorf("walks at %v, want %v: in order made, each moment once, nothing hidden, nothing outside", got, want)
	}
	if !saved.Newest.Started.Equal(seen.Add(10 * time.Minute)) {
		t.Errorf("newest started %v, want the last made", saved.Newest.Started)
	}
	if saved.Others != 1 {
		t.Errorf("%d walks of other questions, want 1", saved.Others)
	}
	unread := strings.Join(saved.Unread, "\n")
	if strings.Contains(unread, "\x1b") {
		t.Errorf("a file name carried an escape through: %q", unread)
	}
	for _, name := range []string{"broken.json", "undated.json", "link.json", "\\027[41mred.json"} {
		if !strings.Contains(unread, name) {
			t.Errorf("%s is not among the unread:\n%s", name, unread)
		}
	}
}

func TestReadDirWithNothingOfTheQuestion(t *testing.T) {
	dir := t.TempDir()
	walkFile(t, dir, "other.json", "mail.test. MX", seen)
	_, err := history.ReadDir(dir, trace.Question{Name: "www.test.", Type: "A", Class: "IN"}, readWalk)
	if err == nil || !strings.Contains(err.Error(), "holds no walk of www.test. A") {
		t.Errorf("got %v, want it said that there is no walk of the question", err)
	}
}

func TestReadDirThatIsNotThere(t *testing.T) {
	_, err := history.ReadDir(filepath.Join(t.TempDir(), "none"), trace.Question{Name: "www.test.", Type: "A", Class: "IN"}, readWalk)
	if err == nil {
		t.Error("read a directory that is not there")
	}
}
