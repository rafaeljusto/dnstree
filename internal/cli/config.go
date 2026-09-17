package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ConfigEnv names the file of defaults outright, ahead of every conventional
// location.
const ConfigEnv = "DNSTREE_CONFIG"

// configFile is a file of defaults and how it was chosen. A file the run asked
// for by name has to be there; a conventional one is simply absent.
type configFile struct {
	path     string
	required bool
}

// Some flags say the same thing in different ways. A command line that names
// one of a group answers the whole group, so the file's choice is dropped
// rather than left to collide with it. --root is in one for a second reason:
// it is the only flag that may be repeated, so a file's roots would otherwise
// pile onto the command line's instead of giving way to them.
var groups = [][]string{
	{"4", "6"},
	{"udp", "tcp", "dot", "doh"},
	{"root", "root-hints"},
	{"resolver", "asn-resolver"},
	{"tls-ca", "tls-insecure"},
}

// defaultFile is where the defaults are read from when the command line does
// not say: the file named by the environment, then the XDG location, then the
// dot file. Only a file named outright has to exist.
func defaultFile() configFile {
	if path := os.Getenv(ConfigEnv); path != "" {
		return configFile{path: path, required: true}
	}
	for _, path := range []string{xdgFile(), dotFile()} {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return configFile{path: path}
		}
	}
	return configFile{}
}

// xdgFile is the conventional location. os.UserConfigDir is not used because on
// macOS it answers ~/Library/Application Support, which is not where anyone
// looks for the settings of a terminal program.
func xdgFile() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		if runtime.GOOS == "windows" {
			dir, _ = os.UserConfigDir()
		} else if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".config")
		}
	}
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "dnstree", "config")
}

func dotFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".dnstreerc")
}

// chosen reads the arguments that say which file of defaults to use, ahead of
// the parse the file itself feeds. Both flags are registered like any other, so
// this only has to find them first.
func chosen(flags *flag.FlagSet, args []string) (configFile, error) {
	var (
		path string
		off  bool
	)
	scan(flags, args, func(name, value string) {
		switch name {
		case "config":
			path = value
		case "no-config":
			off = value != "false"
		}
	})

	switch {
	case off && path != "":
		return configFile{}, fmt.Errorf("%w: --config and --no-config ask for opposite things", ErrUsage)
	case off:
		return configFile{}, nil
	case path != "":
		return configFile{path: path, required: true}, nil
	}
	return defaultFile(), nil
}

// defaults reads a file of defaults into arguments, in the order the file wrote
// them, and reports whether there was a file at all. The flags are looked up as
// they are read, so a name that is not a flag is reported against the line that
// wrote it rather than as a puzzle from the parser.
func defaults(flags *flag.FlagSet, file configFile) ([]string, bool, error) {
	if file.path == "" {
		return nil, false, nil
	}
	data, err := os.ReadFile(file.path)
	switch {
	case errors.Is(err, os.ErrNotExist) && !file.required:
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("%w: %w", ErrUsage, err)
	}

	var args []string
	line := 0
	for text := range strings.Lines(string(data)) {
		line++
		text = strings.TrimSpace(text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		name, value, given := setting(text)
		where := fmt.Sprintf("%s:%d", file.path, line)
		switch name {
		case "config", "no-config":
			return nil, false, fmt.Errorf("%w: %s: --%s says which file to read, so it cannot be read from one",
				ErrUsage, where, name)
		case "version":
			return nil, false, fmt.Errorf("%w: %s: --version is asked for, not set", ErrUsage, where)
		}

		switch f := flags.Lookup(name); {
		case f == nil:
			return nil, false, fmt.Errorf("%w: %s: %q is not a flag", ErrUsage, where, name)
		case !given && !boolean(f):
			return nil, false, fmt.Errorf("%w: %s: --%s takes a value", ErrUsage, where, name)
		case !given:
			value = "true"
		}
		args = append(args, "-"+name+"="+value)
	}
	return args, true, nil
}

// setting reads one line of a file of defaults: a long flag name, then the
// value it takes, written either way round the equals sign.
func setting(text string) (name, value string, given bool) {
	if name, value, ok := strings.Cut(text, "="); ok {
		return key(name), strings.TrimSpace(value), true
	}
	if i := strings.IndexAny(text, " \t"); i >= 0 {
		return key(text[:i]), strings.TrimSpace(text[i+1:]), true
	}
	return key(text), "", false
}

// key is the name of a flag, with the dashes a pasted command line brings.
func key(name string) string {
	return strings.TrimLeft(strings.TrimSpace(name), "-")
}

// override drops the defaults the command line has already answered, so a file
// that chose a transport does not collide with the one the run asks for.
func override(flags *flag.FlagSet, fileArgs, args []string) []string {
	given := make(map[string]string)
	scan(flags, args, func(name, value string) { given[name] = value })

	drop := make(map[string]bool)
	for _, group := range groups {
		for _, name := range group {
			if _, ok := given[name]; ok {
				for _, member := range group {
					drop[member] = true
				}
				break
			}
		}
	}

	// A format written once, at the end, cannot be drawn live. Asked for one,
	// the file's --live is about the other formats: it is dropped rather than
	// held against the run.
	if format := given["format"]; format == "json" || format == "dot" {
		drop["live"] = true
	}

	if len(drop) == 0 {
		return fileArgs
	}

	kept := make([]string, 0, len(fileArgs))
	for _, arg := range fileArgs {
		name, _, _ := strings.Cut(key(arg), "=")
		if !drop[name] {
			kept = append(kept, arg)
		}
	}
	return kept
}

// scan walks the flags at the front of args and reports each one, in order. It
// stops where the parser stops: at the first argument that is not a flag, so
// that the name being resolved cannot be mistaken for one.
func scan(flags *flag.FlagSet, args []string, visit func(name, value string)) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg == "--" || !strings.HasPrefix(arg, "-") {
			return
		}

		name, value, given := strings.Cut(key(arg), "=")
		f := flags.Lookup(name)
		if f == nil {
			return // the parse proper says so, with the usage
		}
		if !given && !boolean(f) {
			if i++; i == len(args) {
				return
			}
			value = args[i]
		}
		if !given && boolean(f) {
			value = "true"
		}
		visit(name, value)
	}
}

// boolean reports whether a flag stands on its own, the way the parser asks.
func boolean(f *flag.Flag) bool {
	value, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && value.IsBoolFlag()
}
