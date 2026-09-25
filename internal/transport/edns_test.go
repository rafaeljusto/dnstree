package transport_test

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

func TestWithSubnet(t *testing.T) {
	for _, tt := range []struct {
		name    string
		prefix  netip.Prefix
		udpSize uint16
		family  uint16
		netmask uint8
		address string
	}{{
		name:    "IPv4",
		prefix:  netip.MustParsePrefix("203.0.113.0/24"),
		udpSize: transport.DefaultUDPSize,
		family:  1, netmask: 24, address: "203.0.113.0",
	}, {
		name:    "IPv6",
		prefix:  netip.MustParsePrefix("2001:db8::/56"),
		udpSize: transport.DefaultUDPSize,
		family:  2, netmask: 56, address: "2001:db8::",
	}, {
		// The bits past the prefix are nobody's business, and RFC 7871 wants
		// them zero on the wire whatever the caller handed over.
		name:    "an address inside the prefix is masked",
		prefix:  netip.PrefixFrom(netip.MustParseAddr("203.0.113.57"), 24),
		udpSize: transport.DefaultUDPSize,
		family:  1, netmask: 24, address: "203.0.113.0",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := transport.NewQuery("www.test.", dns.TypeA, tt.udpSize, false)
			if err != nil {
				t.Fatalf("NewQuery: %v", err)
			}
			transport.WithSubnet(req, tt.prefix)

			if len(req.Pseudo) != 1 {
				t.Fatalf("got %d options, want the subnet", len(req.Pseudo))
			}
			subnet, ok := req.Pseudo[0].(*dns.SUBNET)
			if !ok {
				t.Fatalf("got %T, want a subnet option", req.Pseudo[0])
			}
			if subnet.Family != tt.family {
				t.Errorf("got family %d, want %d", subnet.Family, tt.family)
			}
			if subnet.Netmask != tt.netmask {
				t.Errorf("got netmask %d, want %d", subnet.Netmask, tt.netmask)
			}
			if got := subnet.Address.String(); got != tt.address {
				t.Errorf("got %s, want %s", got, tt.address)
			}
			if subnet.Scope != 0 {
				t.Errorf("got scope %d, want 0: a query claims no scope", subnet.Scope)
			}
		})
	}
}

// TestWithSubnetNeedsEDNS covers the query that has nowhere to carry an option.
// A query without EDNS0 is what a server that could not parse it is asked
// again with, and smuggling the option back in would fail it a second time.
func TestWithSubnetNeedsEDNS(t *testing.T) {
	req, err := transport.NewQuery("www.test.", dns.TypeA, 0, false)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}

	transport.WithSubnet(req, netip.MustParsePrefix("203.0.113.0/24"))
	if len(req.Pseudo) != 0 {
		t.Errorf("got %d options, want none", len(req.Pseudo))
	}
}

// TestWithSubnetUnset covers the ordinary walk, which tells nobody where it is.
func TestWithSubnetUnset(t *testing.T) {
	req, err := transport.NewQuery("www.test.", dns.TypeA, transport.DefaultUDPSize, false)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}

	transport.WithSubnet(req, netip.Prefix{})
	if len(req.Pseudo) != 0 {
		t.Errorf("got %d options, want none", len(req.Pseudo))
	}
}

func TestExtended(t *testing.T) {
	resp := new(dns.Msg)
	resp.Pseudo = []dns.RR{
		&dns.EDE{InfoCode: 15, ExtraText: "on the list"},
		&dns.EDE{InfoCode: 3},
		&dns.NSID{},
	}

	extended := transport.Extended(resp)
	if len(extended) != 2 {
		t.Fatalf("got %d, want the two extended errors and not the NSID", len(extended))
	}
	if extended[0].Code != 15 || extended[0].Reason != "Blocked" || extended[0].Text != "on the list" {
		t.Errorf("got %+v, want blocked with the server's own words", extended[0])
	}
	if !extended[0].Withheld() {
		t.Error("got an answer served, want one withheld: blocked is somebody's decision")
	}
	if extended[1].Withheld() {
		t.Errorf("got %+v withheld, want a stale answer to count as served", extended[1])
	}
}

func TestExtendedUnregisteredCode(t *testing.T) {
	resp := new(dns.Msg)
	resp.Pseudo = []dns.RR{&dns.EDE{InfoCode: 64000, ExtraText: "something local"}}

	extended := transport.Extended(resp)
	if len(extended) != 1 {
		t.Fatalf("got %d, want the one error", len(extended))
	}
	// A code this build has no name for is still the server saying something,
	// and dropping it would lose the only account of the answer there is.
	if extended[0].Code != 64000 || extended[0].Reason != "" {
		t.Errorf("got %+v, want the number carried with no name", extended[0])
	}
	if got := extended[0].String(); got != "64000: something local" {
		t.Errorf("got %q, want the number and the text", got)
	}
}

func TestEchoedSubnet(t *testing.T) {
	resp := new(dns.Msg)
	resp.Pseudo = []dns.RR{&dns.SUBNET{
		Family: 1, Netmask: 24, Scope: 20, Address: netip.MustParseAddr("203.0.113.0"),
	}}

	subnet := transport.EchoedSubnet(resp)
	if subnet == nil {
		t.Fatal("got nothing, want the echoed subnet")
	}
	if got := subnet.Prefix.String(); got != "203.0.113.0/24" {
		t.Errorf("got %s, want the prefix the server was sent", got)
	}
	if subnet.Scope != 20 {
		t.Errorf("got scope /%d, want /20", subnet.Scope)
	}
}

// TestEchoedSubnetAbsent covers the server that ignored the option, which is
// most of them: nothing came back, so nothing was tailored.
func TestEchoedSubnetAbsent(t *testing.T) {
	if subnet := transport.EchoedSubnet(new(dns.Msg)); subnet != nil {
		t.Errorf("got %+v, want nothing", subnet)
	}
	if subnet := transport.EchoedSubnet(nil); subnet != nil {
		t.Errorf("got %+v, want nothing", subnet)
	}
}

// TestWithNSID covers the question a query asks about the server itself: an
// empty option, since only the answer carries an identifier.
func TestWithNSID(t *testing.T) {
	req, err := transport.NewQuery("www.test.", dns.TypeA, transport.DefaultUDPSize, false)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}

	transport.WithNSID(req)
	if len(req.Pseudo) != 1 {
		t.Fatalf("got %d options, want the identifier asked for", len(req.Pseudo))
	}
	nsid, ok := req.Pseudo[0].(*dns.NSID)
	if !ok {
		t.Fatalf("got %T, want an NSID option", req.Pseudo[0])
	}
	if nsid.Nsid != "" {
		t.Errorf("got %q, want nothing: a query claims no identifier of its own", nsid.Nsid)
	}
}

// TestWithNSIDNeedsEDNS covers the query that has nowhere to carry an option,
// which is what a server that could not parse EDNS0 is asked again with.
func TestWithNSIDNeedsEDNS(t *testing.T) {
	req, err := transport.NewQuery("www.test.", dns.TypeA, 0, false)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}

	transport.WithNSID(req)
	if len(req.Pseudo) != 0 {
		t.Errorf("got %d options, want none", len(req.Pseudo))
	}
}

// TestEchoedNSID covers what a server is free to put in the one field of a
// reply whose bytes it alone chooses. It is drawn on a line of a tree, and
// --format ascii promises that line stays printable.
func TestEchoedNSID(t *testing.T) {
	long := strings.Repeat("a", transport.MaxNSID+8)

	for _, tt := range []struct {
		name  string
		given string
		want  string
	}{{
		name:  "a name is read as the name",
		given: hex.EncodeToString([]byte("fra2")),
		want:  "fra2",
	}, {
		name:  "bytes that spell no name stay the hex they came as",
		given: hex.EncodeToString([]byte{0x00, 0xff}),
		want:  "00ff",
	}, {
		name:  "a space would break the line into fields, so it is not a name",
		given: hex.EncodeToString([]byte("two words")),
		want:  hex.EncodeToString([]byte("two words")),
	}, {
		name:  "what is not hex at all is left as it came",
		given: "not hex",
		want:  "not hex",
	}, {
		name:  "more than a line can take is cut, and says so",
		given: hex.EncodeToString([]byte(long)),
		want:  long[:transport.MaxNSID] + "...",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			resp := new(dns.Msg)
			resp.Pseudo = []dns.RR{&dns.NSID{Nsid: tt.given}}

			if got := transport.EchoedNSID(resp); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEchoedNSIDAbsent covers the servers that name themselves nothing: one
// that carried no option at all, and one that echoed the empty option a query
// asks with.
func TestEchoedNSIDAbsent(t *testing.T) {
	empty := new(dns.Msg)
	empty.Pseudo = []dns.RR{&dns.NSID{}}

	for _, resp := range []*dns.Msg{new(dns.Msg), empty, nil} {
		if got := transport.EchoedNSID(resp); got != "" {
			t.Errorf("got %q, want nothing", got)
		}
	}
}
