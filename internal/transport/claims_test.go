package transport_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

const claimsZone = `
@    IN SOA     ns hostmaster 1 7200 3600 1209600 3600
@    IN NS      ns
ns   IN A       127.0.0.1
dns  IN RESINFO qnamemin exterr=15-17 infourl=https://dns.test/guide
two  IN RESINFO qnamemin
two  IN RESINFO exterr=1
`

func TestClaims(t *testing.T) {
	t.Parallel()

	server := fakens.New(t, fakens.Config{Origin: "test.", Zone: claimsZone, TLS: true, DoH: true})
	lookedUp := fakens.New(t, fakens.Config{Origin: "test.", Zone: claimsZone, TLS: true,
		Behaviour: fakens.Behaviour{LookedUp: true}})
	trusting := transport.Config{Timeout: time.Second, TLS: server.ClientTLS()}
	loopback := netip.MustParseAddr("127.0.0.1")

	dot := func(target string, at *fakens.Server) trace.Designated {
		return trace.Designated{Priority: 1, Target: target, Protocols: []string{"dot"}, Port: at.TLSAddr.Port(),
			Hints: []netip.Addr{netip.MustParseAddr("::1"), loopback}}
	}
	doh := func(path string) trace.Designated {
		return trace.Designated{Priority: 1, Target: "dns.test.", Protocols: []string{"doh"}, Port: server.DoHAddr.Port(), DoHPath: path}
	}
	read := []string{"qnamemin", "exterr=15-17", "infourl=https://dns.test/guide"}

	tests := map[string]struct {
		cfg     transport.Config
		offers  []trace.Designated
		proto   string
		text    []string
		err     string
		skipped bool
	}{
		"a record served over dot is read, from the hint of the resolver's family": {
			cfg: trusting, offers: []trace.Designated{dot("dns.test.", server)}, proto: "dot", text: read,
		},
		"a private hint that is not the resolver's own is not dialled": {
			cfg: trusting, proto: "dot", text: read, offers: []trace.Designated{{
				Priority: 1, Target: "dns.test.", Protocols: []string{"dot"}, Port: server.TLSAddr.Port(),
				Hints: []netip.Addr{netip.MustParseAddr("10.0.0.53")},
			}},
		},
		"dot is asked before doh, whatever the order of the offers": {
			cfg: trusting, offers: []trace.Designated{doh("/dns-query{?dns}"), dot("dns.test.", server)}, proto: "dot", text: read,
		},
		"doh at the standard path is asked where nothing offers dot": {
			cfg: trusting, offers: []trace.Designated{doh("/dns-query{?dns}")}, proto: "doh", text: read,
		},
		"a record from a resolver that looked it up is dropped": {
			cfg: trusting, offers: []trace.Designated{dot("dns.test.", lookedUp)}, proto: "dot", err: trace.NotAuthoritative,
		},
		"a looked-up answer without a record is a resolver that publishes none": {
			cfg: trusting, offers: []trace.Designated{dot("none.test.", lookedUp)}, proto: "dot",
		},
		"two records are not read": {
			cfg: trusting, offers: []trace.Designated{dot("two.test.", server)}, proto: "dot", err: "2 records",
		},
		"a name with no record publishes none": {
			cfg: trusting, offers: []trace.Designated{dot("none.test.", server)}, proto: "dot",
		},
		"a certificate that does not verify is not read": {
			cfg: transport.Config{Timeout: time.Second}, offers: []trace.Designated{dot("dns.test.", server)}, proto: "dot", err: "certificate",
		},
		"doh at a path of its own is not asked": {
			cfg: trusting, offers: []trace.Designated{doh("/q{?dns}")}, skipped: true,
		},
		"an offer over doq alone is not asked": {
			cfg: trusting, offers: []trace.Designated{{Priority: 1, Target: "dns.test.", Protocols: []string{"doq"}}}, skipped: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			info := transport.Claims(t.Context(), tt.cfg, netip.AddrPortFrom(loopback, 53), tt.offers)
			if tt.skipped {
				if info != nil {
					t.Fatalf("got %+v, want nothing asked", info)
				}
				return
			}
			if info == nil {
				t.Fatal("got nothing asked")
			}
			if info.Proto != tt.proto || info.Server.IP != loopback {
				t.Errorf("got %s at %v, want %s at %v", info.Proto, info.Server.IP, tt.proto, loopback)
			}
			if tt.err == "" && info.Err != "" || !strings.Contains(info.Err, tt.err) {
				t.Errorf("got error %q, want %q", info.Err, tt.err)
			}
			if !slices.Equal(info.Text, tt.text) {
				t.Errorf("got %q, want %q", info.Text, tt.text)
			}
		})
	}
}

// TestClaimsDialsTheResolverWithoutHints covers an offer that gives no
// address: the encrypted resolver is taken to be where the plain one is.
func TestClaimsDialsTheResolverWithoutHints(t *testing.T) {
	t.Parallel()

	server := fakens.New(t, fakens.Config{Origin: "test.", Zone: claimsZone, TLS: true})
	offer := trace.Designated{Priority: 1, Target: "dns.test.", Protocols: []string{"dot"}, Port: server.TLSAddr.Port()}

	info := transport.Claims(t.Context(), transport.Config{TLS: server.ClientTLS()}, server.Addr, []trace.Designated{offer})
	if info == nil || info.Err != "" || len(info.Text) != 3 {
		t.Fatalf("got %+v, want the record read from the resolver's own address", info)
	}
}
