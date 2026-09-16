package cli_test

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/cli"
	"github.com/rafaeljusto/dnstree/internal/render/tree"
)

// TestMain puts the whole package in a home of its own. Every Parse reads a
// file of defaults, and the one on the machine running the tests is not it.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "dnstree-home")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	os.Unsetenv(cli.ConfigEnv)

	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

func TestParseDefaults(t *testing.T) {
	tests := map[string]struct {
		file  string
		args  []string
		want  cli.Config
		noASN bool
	}{
		"the file says what the command line leaves out": {
			file: "format = emoji\ndnssec\ntimeout = 3s\n",
			args: []string{"example.com"},
			want: cli.Config{Format: "emoji", DNSSEC: true, Timeout: 3 * time.Second},
		},
		"a value may be written without the equals sign": {
			file: "format emoji\n",
			args: []string{"example.com"},
			want: cli.Config{Format: "emoji"},
		},
		"a flag may be pasted in with its dashes": {
			file: "--dnssec\n--color never\n",
			args: []string{"example.com"},
			want: cli.Config{DNSSEC: true, Color: tree.ColorNever},
		},
		"comments and blank lines say nothing": {
			file: "# the tree, in emoji\n\n   # and nothing else\nformat = emoji\n",
			args: []string{"example.com"},
			want: cli.Config{Format: "emoji"},
		},
		"the command line wins over the file": {
			file: "format = emoji\ntimeout = 3s\n",
			args: []string{"--format", "ascii", "example.com"},
			want: cli.Config{Format: "ascii", Timeout: 3 * time.Second},
		},
		"a transport asked for replaces the one in the file": {
			file: "doh\n",
			args: []string{"--udp", "example.com"},
			want: cli.Config{Proto: "udp"},
		},
		"a family asked for replaces the one in the file": {
			file: "6\n",
			args: []string{"-4", "example.com"},
			want: cli.Config{Family: 4},
		},
		"the file's family stands when the command line is silent": {
			file: "6\n",
			args: []string{"example.com"},
			want: cli.Config{Family: 6},
		},
		"a boolean the file set can be turned back off": {
			file: "dnssec\n",
			args: []string{"--dnssec=false", "example.com"},
			want: cli.Config{},
		},
		"the file can skip the AS lookups": {
			file:  "no-asn\n",
			args:  []string{"example.com"},
			want:  cli.Config{},
			noASN: true,
		},
		"a format written once outlives the file's live drawing": {
			file: "live\nformat = emoji\n",
			args: []string{"--format", "json", "example.com"},
			want: cli.Config{Format: "json"},
		},
		"the type is still read from the command line": {
			file: "format = emoji\n",
			args: []string{"example.com", "mx"},
			want: cli.Config{Format: "emoji", Type: "MX"},
		},
		"the file can name every root": {
			file: "root = 192.0.2.1\nroot = ns.example.com@192.0.2.2:5353\n",
			args: []string{"example.com"},
			want: cli.Config{Roots: []cli.Root{
				{Addr: netip.MustParseAddrPort("192.0.2.1:0")},
				{Name: "ns.example.com.", Addr: netip.MustParseAddrPort("192.0.2.2:5353")},
			}},
		},
		"a root asked for replaces every one in the file": {
			file: "root = 192.0.2.1\nroot = 192.0.2.2\n",
			args: []string{"--root", "192.0.2.9", "example.com"},
			want: cli.Config{Roots: []cli.Root{{Addr: netip.MustParseAddrPort("192.0.2.9:0")}}},
		},
		"a root asked for replaces the file's hints": {
			file: "root-hints = hints\n",
			args: []string{"--root", "192.0.2.9", "example.com"},
			want: cli.Config{Roots: []cli.Root{{Addr: netip.MustParseAddrPort("192.0.2.9:0")}}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := write(t, test.file)

			got, err := cli.Parse(append([]string{"--config", path}, test.args...), io.Discard)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			want := complete(test.want)
			want.ASN, want.ConfigFile = !test.noASN, path
			if !reflect.DeepEqual(*got, want) {
				t.Errorf("got  %+v\nwant %+v", *got, want)
			}
		})
	}
}

// TestParseDefaultsFound covers where the file is looked for, which is the part
// nobody can see from the command line.
func TestParseDefaultsFound(t *testing.T) {
	t.Run("the environment names it", func(t *testing.T) {
		path := write(t, "format = emoji\n")
		t.Setenv(cli.ConfigEnv, path)

		if got := parse(t, "example.com"); got.ConfigFile != path || got.Format != "emoji" {
			t.Errorf("got %q and format %q, want %q read", got.ConfigFile, got.Format, path)
		}
	})

	t.Run("the XDG location comes next", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)
		path := filepath.Join(dir, "dnstree", "config")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("format = emoji\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		if got := parse(t, "example.com"); got.ConfigFile != path {
			t.Errorf("got %q, want %q", got.ConfigFile, path)
		}
	})

	t.Run("the dot file is the last place looked", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		path := filepath.Join(home, ".dnstreerc")
		if err := os.WriteFile(path, []byte("format = emoji\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		if got := parse(t, "example.com"); got.ConfigFile != path {
			t.Errorf("got %q, want %q", got.ConfigFile, path)
		}
	})

	t.Run("no file is no defaults, and no complaint", func(t *testing.T) {
		got := parse(t, "example.com")
		if got.ConfigFile != "" || got.Format != "tree" {
			t.Errorf("got %q and format %q, want nothing read", got.ConfigFile, got.Format)
		}
	})

	t.Run("no-config ignores the one that is there", func(t *testing.T) {
		t.Setenv(cli.ConfigEnv, write(t, "format = emoji\n"))

		if got := parse(t, "--no-config", "example.com"); got.ConfigFile != "" || got.Format != "tree" {
			t.Errorf("got %q and format %q, want nothing read", got.ConfigFile, got.Format)
		}
	})

	t.Run("config outranks the environment", func(t *testing.T) {
		t.Setenv(cli.ConfigEnv, write(t, "format = emoji\n"))
		path := write(t, "format = ascii\n")

		if got := parse(t, "--config", path, "example.com"); got.ConfigFile != path || got.Format != "ascii" {
			t.Errorf("got %q and format %q, want %q read", got.ConfigFile, got.Format, path)
		}
	})

	// The file is found before the command line is parsed, so a flag that takes
	// a value must not be mistaken for the end of the flags.
	t.Run("config is found behind a flag that takes a value", func(t *testing.T) {
		path := write(t, "dnssec\n")

		if got := parse(t, "--format", "ascii", "--config", path, "example.com"); got.ConfigFile != path {
			t.Errorf("got %q, want %q", got.ConfigFile, path)
		}
	})
}

func TestParseDefaultsRejects(t *testing.T) {
	tests := map[string]struct {
		file string
		args []string
	}{
		"a line that is not a flag":           {file: "colour = never\n"},
		"a value the flag cannot read":        {file: "timeout = soon\n"},
		"a value the flag will not take":      {file: "format = runes\n"},
		"a flag left without its value":       {file: "format\n"},
		"the name to resolve":                 {file: "example.com\n"},
		"a file that says which file to read": {file: "config = elsewhere\n"},
		"a file that asks for the version":    {file: "version\n"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"--config", write(t, test.file)}, test.args...)
			args = append(args, "example.com")

			if _, err := cli.Parse(args, io.Discard); !errors.Is(err, cli.ErrUsage) {
				t.Errorf("got error %v, want it to read as a usage problem", err)
			}
		})
	}

	t.Run("a file asked for by name that is not there", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nowhere")
		if _, err := cli.Parse([]string{"--config", path, "example.com"}, io.Discard); !errors.Is(err, cli.ErrUsage) {
			t.Errorf("got error %v, want it to read as a usage problem", err)
		}
	})

	t.Run("a file the environment names that is not there", func(t *testing.T) {
		t.Setenv(cli.ConfigEnv, filepath.Join(t.TempDir(), "nowhere"))
		if _, err := cli.Parse([]string{"example.com"}, io.Discard); !errors.Is(err, cli.ErrUsage) {
			t.Errorf("got error %v, want it to read as a usage problem", err)
		}
	})

	t.Run("config and no-config together", func(t *testing.T) {
		args := []string{"--config", write(t, ""), "--no-config", "example.com"}
		if _, err := cli.Parse(args, io.Discard); !errors.Is(err, cli.ErrUsage) {
			t.Errorf("got error %v, want it to read as a usage problem", err)
		}
	})
}

// TestParseDefaultsBlames covers the error text itself: a file of defaults is
// edited once and read for months, so a complaint about it has to say where.
func TestParseDefaultsBlames(t *testing.T) {
	path := write(t, "# defaults\nformat = emoji\ncolour = never\n")

	_, err := cli.Parse([]string{"--config", path, "example.com"}, io.Discard)
	if err == nil {
		t.Fatal("got no error, want one")
	}
	for _, want := range []string{path + ":3", "colour"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("got %q, want it to name %q", err, want)
		}
	}
}

// write puts a file of defaults where only this test can find it.
func write(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func parse(t *testing.T, args ...string) *cli.Config {
	t.Helper()

	cfg, err := cli.Parse(args, io.Discard)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

// complete fills in the defaults a case does not set, so that a table only says
// what it is about.
func complete(want cli.Config) cli.Config {
	if want.Name == "" {
		want.Name = "example.com"
	}
	if want.Type == "" {
		want.Type = "A"
	}
	if want.Proto == "" {
		want.Proto = "udp"
	}
	if want.Format == "" {
		want.Format = "tree"
	}
	if want.Color == "" {
		want.Color = tree.ColorAuto
	}
	if want.Timeout == 0 {
		want.Timeout = 2 * time.Second
	}
	if want.Retries == 0 {
		want.Retries = 1
	}
	return want
}
