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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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

	// Keys are the zone's keys and DS the records its parent holds for it,
	// where the chain of trust entered the zone and held, each with when a
	// remembered walk first saw it. That is what times the steps of a key
	// rollover: a record first seen at a time was published by then.
	Keys []Record `json:"keys,omitempty"`
	DS   []Record `json:"ds,omitempty"`
}

// Record is one key, or one DS, and when it was first seen.
type Record struct {
	Tag       uint16    `json:"tag"`
	Algorithm string    `json:"algorithm"`
	Since     time.Time `json:"since"`
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
	tr = tr.Shown()
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
	walk.Zones = zones(tr, walk.Seen)
	return walk
}

// Carry keeps when each key and DS still in place was first seen, from the
// walk remembered before this one. A zone this walk followed no chain into
// keeps what was remembered of it: a run without --dnssec says nothing about
// the keys, and is no reason to forget them.
func (w *Walk) Carry(before *Walk) {
	if before == nil {
		return
	}
	for i := range w.Zones {
		zone := &w.Zones[i]
		j := slices.IndexFunc(before.Zones, func(z Zone) bool { return strings.EqualFold(z.Name, zone.Name) })
		if j < 0 {
			continue
		}
		earlier := before.Zones[j]
		if zone.DNSSEC == "" {
			zone.Keys, zone.DS = earlier.Keys, earlier.DS
			continue
		}
		since(zone.Keys, earlier.Keys)
		since(zone.DS, earlier.DS)
	}
}

func since(now, before []Record) {
	for i := range now {
		for _, earlier := range before {
			if earlier.Tag == now[i].Tag && earlier.Algorithm == now[i].Algorithm &&
				!earlier.Since.IsZero() && earlier.Since.Before(now[i].Since) {
				now[i].Since = earlier.Since
			}
		}
	}
}

// FirstSeen is when the walk, carried forward, first saw each key and DS.
func (w *Walk) FirstSeen() trace.Seen {
	return func(name, rrtype string, tag uint16, algorithm string) time.Time {
		name = trace.Shown(name)
		for _, zone := range w.Zones {
			if !strings.EqualFold(zone.Name, name) {
				continue
			}
			records := zone.Keys
			if rrtype == "DS" {
				records = zone.DS
			}
			for _, record := range records {
				if record.Tag == tag && record.Algorithm == algorithm {
					return record.Since
				}
			}
		}
		return time.Time{}
	}
}

// zones is the zone cuts the walk crossed, each with the delegation that
// pointed at it and the verdict the chain of trust reached there. The root is
// always the first of them, whether or not anything was checked at it.
func zones(tr *trace.Trace, seen time.Time) []Zone {
	// A verdict names the zone it is about, which is not the zone of the step
	// it sits on: a cut is judged from above. The first verdict for a zone is
	// the one reached on entering it, and the first to record its keys is the
	// one they are kept from.
	states := make(map[string]string)
	keyed := make(map[string]*trace.DNSSECStatus)
	for step := range tr.Steps() {
		if step.DNSSEC == nil || step.DNSSEC.Zone == "" {
			continue
		}
		name := strings.ToLower(step.DNSSEC.Zone)
		if states[name] == "" {
			states[name] = string(step.DNSSEC.State)
		}
		if keyed[name] == nil && step.DNSSEC.State == trace.Secure && len(step.DNSSEC.Keys) > 0 {
			keyed[name] = step.DNSSEC
		}
	}
	zone := func(name string, servers []string) Zone {
		z := Zone{Name: name, NS: servers, DNSSEC: states[strings.ToLower(name)]}
		if status := keyed[strings.ToLower(name)]; status != nil {
			for _, key := range status.Keys {
				z.Keys = add(z.Keys, Record{Tag: key.Tag, Algorithm: key.Algorithm, Since: seen})
			}
			for _, ds := range status.DS {
				z.DS = add(z.DS, Record{Tag: ds.Tag, Algorithm: ds.Algorithm, Since: seen})
			}
		}
		return z
	}

	crossed := []Zone{zone(".", nil)}
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
		crossed = append(crossed, zone(name, slices.Compact(servers)))
	}
	return crossed
}

// add is records with one more, where it is not there already: a parent may
// publish a DS of the same key in more than one digest.
func add(records []Record, record Record) []Record {
	if slices.ContainsFunc(records, func(r Record) bool { return r.Tag == record.Tag && r.Algorithm == record.Algorithm }) {
		return records
	}
	return append(records, record)
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

// maxFile is far past what any walk is kept in: a summary of the zones and the
// answer, not the trace.
const maxFile = 1 << 20

// Load is the last walk remembered for this question, nil where there is none
// to be held against. A file that cannot be read, that was written by another
// version, or that turns out to hold another question is no file at all: a
// cache that has gone bad costs one run its comparison and nothing more.
func Load(dir string, question trace.Question) *Walk {
	// Opened within the cache, so that a link planted there cannot point the
	// read anywhere else, and read no further than any walk comes to. A FIFO
	// planted there would hold the open forever, so it does not wait, and
	// only a plain file is read.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil
	}
	defer root.Close()
	f, err := root.OpenFile(file(question.Name, question.Type), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(data) > maxFile {
		return nil
	}

	var walk Walk
	if err := json.Unmarshal(data, &walk); err != nil || walk.Version != Version {
		return nil
	}
	if !sameQuestion(walk.Question, question) || !walk.plain() {
		return nil
	}
	return &walk
}

// plain reports whether everything the findings would draw from the file is
// printable ASCII. Of keeps only what trace.Shown escaped, so anything else
// was written by somebody else, and drawn raw it could move the cursor.
func (w *Walk) plain() bool {
	texts := append([]string{w.Kind}, w.Answer...)
	for _, zone := range w.Zones {
		texts = append(append(texts, zone.Name, zone.DNSSEC), zone.NS...)
		for _, record := range slices.Concat(zone.Keys, zone.DS) {
			texts = append(texts, record.Algorithm)
		}
	}
	return !slices.ContainsFunc(texts, func(s string) bool {
		return strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r > '~' })
	})
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
