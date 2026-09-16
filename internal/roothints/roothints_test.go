package roothints_test

import (
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/roothints"
)

func TestDefault(t *testing.T) {
	hints, err := roothints.Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if got, want := len(hints.Servers), 13; got != want {
		t.Errorf("got %d root servers, want %d", got, want)
	}

	for _, server := range hints.Servers {
		if !strings.HasSuffix(server.Name, ".root-servers.net.") {
			t.Errorf("unexpected root server name %q", server.Name)
		}
		var v4, v6 int
		for _, addr := range server.Addrs {
			if addr.Is4() {
				v4++
			} else {
				v6++
			}
		}
		if v4 != 1 || v6 != 1 {
			t.Errorf("%s: got %d IPv4 and %d IPv6 addresses, want 1 of each", server.Name, v4, v6)
		}
	}

	first := hints.Servers[0]
	if first.Name != "a.root-servers.net." {
		t.Errorf("got first server %q, want a.root-servers.net.", first.Name)
	}
	if want := netip.MustParseAddr("198.41.0.4"); first.Addrs[0] != want {
		t.Errorf("got %v for %s, want %v", first.Addrs[0], first.Name, want)
	}
}

func TestLoad(t *testing.T) {
	const hints = `
; a comment
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
.                        3600000      IN NS B.ROOT-SERVERS.NET. ; explicit class
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
; glue-less, and therefore useless to prime with
.                        3600000      NS    C.ROOT-SERVERS.NET.
; not the root zone, ignored
example.com.             3600         NS    ns.example.com.
`

	got, err := roothints.Load(strings.NewReader(hints))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := []roothints.Server{
		{Name: "a.root-servers.net.", Addrs: []netip.Addr{
			netip.MustParseAddr("198.41.0.4"),
			netip.MustParseAddr("2001:503:ba3e::2:30"),
		}},
		{Name: "b.root-servers.net.", Addrs: []netip.Addr{
			netip.MustParseAddr("170.247.170.2"),
		}},
	}
	if len(got.Servers) != len(want) {
		t.Fatalf("got %d servers, want %d: %+v", len(got.Servers), len(want), got.Servers)
	}
	for i, server := range got.Servers {
		if server.Name != want[i].Name {
			t.Errorf("server %d: got name %q, want %q", i, server.Name, want[i].Name)
		}
		if !slices.Equal(server.Addrs, want[i].Addrs) {
			t.Errorf("%s: got addresses %v, want %v", server.Name, server.Addrs, want[i].Addrs)
		}
	}
}

func TestLoadError(t *testing.T) {
	tests := map[string]string{
		"short line":        ".  3600000  NS",
		"bad address":       "a.root-servers.net. 3600000 A 198.41.0.4.5",
		"family mismatch":   "a.root-servers.net. 3600000 A 2001:503:ba3e::2:30",
		"no usable server":  "; nothing here",
		"glue without a ns": "a.root-servers.net. 3600000 A 198.41.0.4",
	}

	for name, hints := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := roothints.Load(strings.NewReader(hints)); err == nil {
				t.Error("got no error, want one")
			}
		})
	}
}

func TestLoadFile(t *testing.T) {
	if _, err := roothints.LoadFile(filepath.Join("data", "named.root")); err != nil {
		t.Errorf("LoadFile: %v", err)
	}
	if _, err := roothints.LoadFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("got no error for a missing file, want one")
	}
}
