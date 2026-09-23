// Package history remembers what a walk found, so that the next walk of the
// same question can say what has changed since.
//
// It keeps one small file per question, and it is the only thing in dnstree
// that writes to the disk. A run remembers nothing and reads nothing unless it
// is asked to: the file says which names were looked up and when, which is
// more than a diagnostic tool should leave lying about uninvited.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// DirEnv names the directory remembered walks are kept in, ahead of every
// conventional location.
const DirEnv = "DNSTREE_CACHE"

// Version is the shape of a remembered walk. A file written by another version
// is read as no file at all rather than brought forward: this is a cache, and
// the cost of dropping it is one run with nothing to compare.
const Version = 1

// Walk is what is worth remembering of one resolution. It is deliberately not
// the whole trace: what it does not carry cannot be compared, which is what
// keeps [Changes] from claiming to have watched something it never recorded.
type Walk struct {
	Version  int       `json:"version"`
	Question Question  `json:"question"`
	Seen     time.Time `json:"seen"`

	// Kind is what ended the resolution, empty where nothing did.
	Kind string `json:"kind,omitempty"`

	// Answer is the rdata that answered the question, sorted, and TTL the one
	// the zone put on it. A nameserver is free to rotate an RRset between one
	// question and the next, so the order is not kept and not compared.
	Answer []string `json:"answer,omitempty"`
	TTL    uint32   `json:"ttl,omitempty"`

	// Zones is the zone cuts the walk crossed, from the root down. The
	// nameserver that answered is not among them: which server of a zone
	// answers first is the zone's business and changes between two walks that
	// are otherwise the same.
	Zones []Zone `json:"zones,omitempty"`
}

// Zone is one zone cut as the walk found it.
type Zone struct {
	Name string `json:"name"`

	// NS are the nameserver names its parent delegated to, sorted. The root
	// has none: a walk is told where to start rather than referred there.
	NS []string `json:"ns,omitempty"`

	// DNSSEC is how far the chain of trust got here, empty for a walk that
	// followed no chain. An empty state is compared with nothing, so a run
	// without --dnssec neither learns nor forgets anything about the chain.
	DNSSEC string `json:"dnssec,omitempty"`
}

// Question is what the walk set out to answer, kept so that a file can be held
// against the question it is read for.
type Question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

// Of is what this walk will be remembered by.
func Of(tr *trace.Trace, now time.Time) *Walk {
	walk := &Walk{
		Version: Version,
		Question: Question{
			Name: tr.Question.Name, Type: tr.Question.Type, Class: tr.Question.Class,
		},
		Seen: now.UTC(),
	}

	if result := tr.Result(); result != nil {
		walk.Kind = string(result.Kind)
		walk.Answer = trace.Answers(result.Records, tr.Question.Type)
		walk.TTL = trace.TTL(result.Records, tr.Question.Type)
	}
	walk.Zones = zones(tr)
	return walk
}

// zones is the zone cuts the walk crossed, each with the delegation that
// pointed at it and the verdict the chain of trust reached there. The root is
// always the first of them, whether or not anything was checked at it.
func zones(tr *trace.Trace) []Zone {
	// A verdict names the zone it is about, which is not the zone of the step
	// it sits on: a cut is judged from above. The first verdict for a zone is
	// the one reached on entering it.
	states := make(map[string]string)
	for step := range tr.Steps() {
		if step.DNSSEC == nil || step.DNSSEC.Zone == "" {
			continue
		}
		if name := strings.ToLower(step.DNSSEC.Zone); states[name] == "" {
			states[name] = string(step.DNSSEC.State)
		}
	}

	crossed := []Zone{{Name: ".", DNSSEC: states["."]}}
	for step := range tr.Mainline() {
		if step.Delegation == nil {
			continue
		}
		// --all takes the same referral from every server of a zone, and
		// several servers may point at the same cut.
		name := step.Delegation.Zone
		if slices.ContainsFunc(crossed, func(zone Zone) bool { return strings.EqualFold(zone.Name, name) }) {
			continue
		}

		servers := slices.Clone(step.Delegation.NS)
		slices.Sort(servers)
		crossed = append(crossed, Zone{
			Name: name, NS: slices.Compact(servers), DNSSEC: states[strings.ToLower(name)],
		})
	}
	return crossed
}

// Dir is where remembered walks are kept: the directory named by the
// environment, then the XDG location, then the dot directory. os.UserCacheDir
// is not used for the same reason the file of defaults does not use
// os.UserConfigDir: on macOS it answers ~/Library/Caches, which is not where
// anyone looks for what a terminal program kept.
func Dir() (string, error) {
	if dir := os.Getenv(DirEnv); dir != "" {
		return dir, nil
	}

	dir := os.Getenv("XDG_CACHE_HOME")
	if dir == "" {
		if runtime.GOOS == "windows" {
			dir, _ = os.UserCacheDir()
		} else if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".cache")
		}
	}
	if dir == "" {
		return "", errors.New("there is nowhere to keep what this walk found")
	}
	return filepath.Join(dir, "dnstree"), nil
}

// Load is the last walk remembered for this question, nil where there is none
// to be held against. A file that cannot be read, that was written by another
// version, or that turns out to hold another question is no file at all: a
// cache that has gone bad costs one run its comparison and nothing more.
func Load(dir string, question trace.Question) *Walk {
	data, err := os.ReadFile(filepath.Join(dir, file(question.Name, question.Type)))
	if err != nil {
		return nil
	}

	var walk Walk
	if err := json.Unmarshal(data, &walk); err != nil || walk.Version != Version {
		return nil
	}
	if !sameQuestion(walk.Question, question) {
		return nil
	}
	return &walk
}

// Save remembers this walk as the one the next will be held against.
func Save(dir string, walk *Walk) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(walk, "", "  ")
	if err != nil {
		return err
	}
	// Written aside and renamed into place: a reader never sees half a file,
	// and a link planted at the name is replaced rather than written through.
	temp, err := os.CreateTemp(dir, ".walk-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(append(data, '\n')); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), filepath.Join(dir, file(walk.Question.Name, walk.Question.Type)))
}

func sameQuestion(remembered Question, asked trace.Question) bool {
	return strings.EqualFold(remembered.Name, asked.Name) &&
		strings.EqualFold(remembered.Type, asked.Type) &&
		strings.EqualFold(remembered.Class, asked.Class)
}

// file is what a question is kept under. The name is spelled out so that the
// cache can be read and thrown away by hand; two questions can still come down
// to the same file name, which is why the question is written inside the file
// and read back before the file is believed.
func file(name, qtype string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		name = "root"
	}
	return fmt.Sprintf("%s_%s.json", safe(name, 200), safe(qtype, 20))
}

// safe is text a file name can carry: lowercase, and anything else replaced.
func safe(text string, most int) string {
	var out strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			out.WriteRune(r)
		default:
			out.WriteByte('-')
		}
		if out.Len() >= most {
			break
		}
	}
	if out.Len() == 0 {
		return "-"
	}
	return out.String()
}
