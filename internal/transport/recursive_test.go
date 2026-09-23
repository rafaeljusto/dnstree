package transport_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

const recursiveZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    127.0.0.1
www   IN A    192.0.2.10
`

func TestAsk(t *testing.T) {
	server := fakens.New(t, fakens.Config{Origin: "test.", Zone: recursiveZone})
	carrier := transport.NewUDP(transport.Config{})

	answer, err := transport.Ask(t.Context(), carrier, server.Addr,
		trace.Question{Name: "www.test", Type: "A", Class: "IN"}, false, netip.Prefix{})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}

	if answer.Rcode != "NOERROR" {
		t.Errorf("got %s, want NOERROR", answer.Rcode)
	}
	if answer.Err != "" {
		t.Errorf("got error %q, want the server to have answered", answer.Err)
	}
	if answer.Elapsed <= 0 {
		t.Errorf("got %s, want a round trip that was measured", answer.Elapsed)
	}
	if answer.Server.IP != server.Addr.Addr() {
		t.Errorf("got %s, want the server that was asked", answer.Server.IP)
	}
}

// TestAskSilent covers the resolver being the thing that is broken, which says
// nothing about the walk and so is reported rather than returned as an error.
func TestAskSilent(t *testing.T) {
	carrier := transport.NewUDP(transport.Config{Timeout: 200 * time.Millisecond})

	// Port 1 is reserved and nothing answers there.
	answer, err := transport.Ask(t.Context(), carrier, netip.MustParseAddrPort("127.0.0.1:1"),
		trace.Question{Name: "www.test", Type: "A", Class: "IN"}, false, netip.Prefix{})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if answer.Err == "" {
		t.Errorf("got %+v, want the silence carried in the result", answer)
	}
}

func TestAskUnknownType(t *testing.T) {
	carrier := transport.NewUDP(transport.Config{})
	if _, err := transport.Ask(t.Context(), carrier, netip.MustParseAddrPort("127.0.0.1:53"),
		trace.Question{Name: "www.test", Type: "NONSENSE", Class: "IN"}, false, netip.Prefix{}); err == nil {
		t.Error("got no error, want a question that cannot be asked")
	}
}

func TestSystemFrom(t *testing.T) {
	tests := map[string]struct {
		file string
		want netip.AddrPort
	}{
		"the first server named": {
			file: "search example.com\nnameserver 192.0.2.1\nnameserver 192.0.2.2\n",
			want: netip.MustParseAddrPort("192.0.2.1:53"),
		},
		"a name is not an address": {
			file: "nameserver resolver.example.com\n",
		},
		"nothing at all": {file: "search example.com\n"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if err := os.WriteFile(path, []byte(test.file), 0o600); err != nil {
				t.Fatalf("writing the file: %v", err)
			}
			if got := transport.SystemFrom(path); got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}

	if got := transport.SystemFrom(filepath.Join(t.TempDir(), "missing")); got.IsValid() {
		t.Errorf("got %v, want nothing from a host that keeps no such file", got)
	}
}
