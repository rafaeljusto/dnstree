package resolver

import (
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns/dnsutil"
)

// FuzzReportHosts reads the hosts out of any rua a zone could write: each a
// lowercased name below the root that fits the wire, none twice, and every
// one the host of a mailto URI in the tag.
func FuzzReportHosts(f *testing.F) {
	f.Add("mailto:d@vendor.net")
	f.Add("mailto:D@Vendor.NET!10m, mailto:d@vendor.net?subject=x,https://x.example")
	f.Add("mailto:a@[192.0.2.1],mailto:@,mailto:d@.,mailto:d@b\xc3\xbccher.example")
	f.Fuzz(func(t *testing.T, rua string) {
		hosts := reportHosts(rua)
		for i, host := range hosts {
			switch {
			case host != dnsutil.Canonical(host) || !dnsutil.IsName(host) || dnsutil.Labels(host) == 0:
				t.Fatalf("%q gave %q, which is no lowercased name below the root", rua, host)
			case slices.Contains(hosts[:i], host):
				t.Fatalf("%q gave %q twice", rua, host)
			}
		}
		if len(hosts) > 0 && !strings.Contains(strings.ToLower(rua), "mailto:") {
			t.Fatalf("%q gave hosts %q without a mailto URI", rua, hosts)
		}
	})
}
