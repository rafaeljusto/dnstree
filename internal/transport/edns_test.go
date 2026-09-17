package transport_test

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/internal/transport"
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
