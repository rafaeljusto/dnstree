package asn

import (
	"net/netip"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

func TestQueryName(t *testing.T) {
	tests := map[string]struct {
		addr string
		want string
	}{
		"ipv4": {
			addr: "1.2.3.4",
			want: "4.3.2.1.origin.asn.cymru.com.",
		},
		"ipv6": {
			addr: "2001:db8::1",
			want: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com.",
		},
		"an IPv4 address wearing IPv6 clothes": {
			addr: "::ffff:1.2.3.4",
			want: "4.3.2.1.origin.asn.cymru.com.",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := queryName(netip.MustParseAddr(test.addr))
			if err != nil {
				t.Fatalf("queryName: %v", err)
			}
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}

	if _, err := queryName(netip.Addr{}); err == nil {
		t.Error("got no error for the zero address, want one")
	}
}

func TestParse(t *testing.T) {
	tests := map[string]struct {
		records []string
		want    *trace.ASNInfo
	}{
		"one prefix": {
			records: []string{"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"},
			want: &trace.ASNInfo{
				Number: 15169, Prefix: "8.8.8.0/24", CountryCode: "US",
				Registry: "arin", Allocated: "1992-12-01",
			},
		},
		"the most specific prefix wins": {
			records: []string{
				"64512 | 8.8.0.0/16 | US | arin | 1991-01-01",
				"15169 | 8.8.8.0/24 | US | arin | 1992-12-01",
				"64513 | 8.0.0.0/8 | US | arin | 1990-01-01",
			},
			want: &trace.ASNInfo{
				Number: 15169, Prefix: "8.8.8.0/24", CountryCode: "US",
				Registry: "arin", Allocated: "1992-12-01",
			},
		},
		"a prefix more than one AS announces": {
			records: []string{"23028 393950 | 216.90.108.0/24 | US | arin | 1998-09-25"},
			want: &trace.ASNInfo{
				Number: 23028, Prefix: "216.90.108.0/24", CountryCode: "US",
				Registry: "arin", Allocated: "1998-09-25",
			},
		},
		"the fields after the prefix are optional": {
			records: []string{"15169 | 8.8.8.0/24"},
			want:    &trace.ASNInfo{Number: 15169, Prefix: "8.8.8.0/24"},
		},
		"ipv6": {
			records: []string{"15169 | 2001:4860::/32 | US | arin | 2005-03-14"},
			want: &trace.ASNInfo{
				Number: 15169, Prefix: "2001:4860::/32", CountryCode: "US",
				Registry: "arin", Allocated: "2005-03-14",
			},
		},
		"no records":       {},
		"not a record":     {records: []string{"v=spf1 -all"}},
		"not a number":     {records: []string{"AS15169 | 8.8.8.0/24 | US | arin | 1992-12-01"}},
		"nothing but bars": {records: []string{" | | | | "}},
		"one good record among the noise": {
			records: []string{"v=spf1 -all", "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"},
			want: &trace.ASNInfo{
				Number: 15169, Prefix: "8.8.8.0/24", CountryCode: "US",
				Registry: "arin", Allocated: "1992-12-01",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := parse(test.records)
			switch {
			case test.want == nil && got != nil:
				t.Fatalf("got %+v, want nothing", got)
			case test.want == nil:
				return
			case got == nil:
				t.Fatalf("got nothing, want %+v", test.want)
			case *got != *test.want:
				t.Errorf("got %+v, want %+v", got, test.want)
			}
		})
	}
}
