package jsonout_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/golden"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// resolution carries one of everything the schema has to be able to say.
func resolution() *trace.Trace {
	answer := &trace.Step{
		Zone: "example.com.",
		Server: trace.Server{
			Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53"), Port: 53,
			ASN: &trace.ASNInfo{
				Number: 10745, Prefix: "199.43.132.0/22", CountryCode: "US",
				Registry: "arin", Allocated: "2010-03-30",
			},
		},
		Asked: trace.Question{Name: "www.example.com.", Type: "A"},
		Proto: "udp",
		RTT:   9*time.Millisecond + 400*time.Microsecond,
		Size:  1187,
		Limit: 1232,
		Rcode: "NOERROR",
		Flags: trace.Flags{AA: true, DO: true, EDNS: true},
		Kind:  trace.KindAnswer,
		DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.", KeyTags: []uint16{31589},
			Algorithm: "ECDSAP256SHA256", Signatures: []trace.Lifetime{{
				Inception:  time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
				Expiration: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
			}}},
		Records: []trace.RR{{Name: "www.example.com.", TTL: 3600, Type: "A", Data: "93.184.216.34"}},
		Children: []*trace.Step{{
			Zone:   "example.com.",
			Server: trace.Server{Name: "a.iana-servers.net.", IP: netip.MustParseAddr("199.43.135.53"), Port: 53},
			Proto:  "udp",
			RTT:    8 * time.Millisecond,
			Rcode:  "NOERROR",
			Flags:  trace.Flags{AA: true},
			Kind:   trace.KindAnswer,
			Aside:  true,
			Asked:  trace.Question{Name: "example.com.", Type: "DNSKEY"},
			Notes:  []string{"DNSKEY of example.com."},
		}},
	}
	skipped := &trace.Step{
		Zone:   "example.com.",
		Server: trace.Server{Name: "b.iana-servers.net.", IP: netip.MustParseAddr("199.43.133.53"), Port: 53},
		Kind:   trace.KindSkipped,
	}
	tld := &trace.Step{
		Zone:   "com.",
		Server: trace.Server{Name: "a.gtld-servers.net.", IP: netip.MustParseAddr("192.5.6.30"), Port: 53},
		Asked:  trace.Question{Name: "www.example.com.", Type: "A"},
		Proto:  "tcp",
		RTT:    18 * time.Millisecond,
		// Refetched over TCP, where a single answer is bounded by nothing.
		Size:  1840,
		Rcode: "NOERROR",
		Kind:  trace.KindReferral,
		Notes: []string{"truncated over udp"},
		Delegation: &trace.Delegation{
			Zone: "example.com.",
			TTL:  172800,
			NS:   []string{"a.iana-servers.net.", "ns.outside.example."},
			Glue: map[string][]netip.Addr{
				"a.iana-servers.net.": {netip.MustParseAddr("199.43.135.53")},
			},
			OutOfBailiwick: []string{"ns.outside.example."},
			DSPresent:      true,
		},
		DNSSEC: &trace.DNSSECStatus{
			State: trace.Secure, Algorithm: "ECDSAP256SHA256", Digest: "SHA256",
			Keys: []trace.Key{
				{Tag: 31589, Algorithm: "ECDSAP256SHA256", SEP: true, Pointed: true, Signs: true},
				{Tag: 20757, Algorithm: "RSASHA256", Bits: 2048},
			},
			DS:      []trace.DS{{Tag: 31589, Algorithm: "ECDSAP256SHA256", Digest: "SHA256", Match: trace.DSMatched}},
			KeysTTL: 3600, DSTTL: 86400,
		},
		Children: []*trace.Step{answer, skipped},
	}
	timeout := &trace.Step{
		Zone:   "com.",
		Server: trace.Server{Name: "b.gtld-servers.net.", IP: netip.MustParseAddr("192.33.14.30"), Port: 53},
		Proto:  "udp",
		Asked:  trace.Question{Name: "www.example.com.", Type: "A"},
		RTT:    2 * time.Second,
		Kind:   trace.KindTimeout,
		Err:    "udp 192.33.14.30:53: i/o timeout",
	}
	root := &trace.Step{
		Zone:       ".",
		Server:     trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("198.41.0.4"), Port: 53},
		Proto:      "udp",
		Asked:      trace.Question{Name: "www.example.com.", Type: "A"},
		RTT:        12 * time.Millisecond,
		Size:       745,
		Limit:      1232,
		Rcode:      "NOERROR",
		Kind:       trace.KindReferral,
		NSID:       "fra2",
		Cookie:     trace.CookieSupported,
		Delegation: &trace.Delegation{Zone: "com.", TTL: 172800, NS: []string{"a.gtld-servers.net."}, DSPresent: true},
		DNSSEC:     &trace.DNSSECStatus{State: trace.Insecure, Reason: "the parent published no DS"},
		Children:   []*trace.Step{timeout, tld},
	}

	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{root}},
		Elapsed:  41*time.Millisecond + 500*time.Microsecond,
		Started:  time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
		Resolvers: []*trace.Resolver{{
			Server:  trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
			Elapsed: 23 * time.Millisecond,
			Rcode:   "NOERROR",
		}},
		Warnings: []string{"the delegation to example.com. lists a nameserver the zone does not"},
		Without:  []string{"ns1.example.com.", "192.0.2.0/24"},
		CAA: &trace.CAA{
			Asked: []trace.CAALookup{
				{Name: "www.example.com.", Found: trace.CAANone},
				{Name: "example.com.", Found: trace.CAASet},
			},
			Owner: "example.com.",
			Records: []trace.CAARecord{
				{Tag: "issue", Value: "letsencrypt.org", Known: true},
				{Tag: "issuewild", Value: ";", Known: true},
			},
			Issue:    &trace.Issuers{CAs: []string{"letsencrypt.org"}},
			Wildcard: &trace.Issuers{CAs: []string{}},
			DNSSEC:   &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.", Algorithm: "ECDSAP256SHA256"},
		},
		SPF: &trace.SPF{
			Name:   "www.example.com.",
			Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
			Record: "v=spf1 include:_spf.example.net mx exists:%{i}.x.example.com a:gone.example.com ptr -all",
			Terms: []trace.SPFTerm{
				{Term: "include:_spf.example.net", Kind: "include", Lookup: 1, Target: "_spf.example.net.", Record: "v=spf1 ip4:192.0.2.0/24 ~all",
					Terms: []trace.SPFTerm{{Term: "ip4:192.0.2.0/24", Kind: "ip4"}, {Term: "~all", Kind: "all"}}},
				{Term: "mx", Kind: "mx", Lookup: 2, Target: "www.example.com.", Found: []string{"mail.example.com."}},
				{Term: "exists:%{i}.x.example.com", Kind: "exists", Lookup: 3, Target: "%{i}.x.example.com", Sender: true},
				{Term: "a:gone.example.com", Kind: "a", Lookup: 4, Target: "gone.example.com.", Void: true, Problem: "lookup 3 to find nothing, past the limit of 2", Fatal: true},
				{Term: "ptr", Kind: "ptr", Lookup: 5, Sender: true, Problem: "it rests on the sender's reverse zone"},
				{Term: "-all", Kind: "all"},
				{Term: "redirect=never.example.net", Kind: "redirect", Unreached: true},
			},
			Lookups: 5,
			Void:    1,
			Cut:     true,
			Result:  trace.SPFUndecided,
			Why:     "the budget ran out",
		},
		Mail: &trace.Mail{
			Name: "www.example.com.",
			MX: trace.Lookup{Name: "www.example.com.", Alias: "example.com.",
				DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.", Algorithm: "ECDSAP256SHA256"}},
			Hosts: []trace.MailHost{
				{Name: "mx.example.com.", Preference: 10,
					Address: &trace.Lookup{Name: "mx.example.com.", DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com."}},
					TLSA:    &trace.Lookup{Name: "_25._tcp.mx.example.com.", DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com."}},
					Records: []trace.TLSARecord{{Usage: 3, Selector: 1, Matching: 1, Data: "e41cc763", Usable: true}},
					DANE:    trace.DANEVerified, Why: "a sender has to see a certificate that matches"},
				{Name: "backup.example.net.", Preference: 20,
					Address: &trace.Lookup{Name: "backup.example.net.", Err: "SERVFAIL"},
					DANE:    trace.DANEUnreachable, Why: "its addresses could not be looked up: SERVFAIL"},
			},
			MTASTS: &trace.MailPolicy{Name: "_mta-sts.www.example.com.", Lookup: trace.Lookup{Name: "_mta-sts.www.example.com."},
				Found: trace.PolicyPublished, Record: "v=STSv1; id=20240101",
				Tags: []trace.PolicyTag{{Name: "v", Value: "STSv1"}, {Name: "id", Value: "20240101"}}},
			TLSRPT: &trace.MailPolicy{Name: "_smtp._tls.www.example.com.", Lookup: trace.Lookup{Name: "_smtp._tls.www.example.com."},
				Found: trace.PolicyNone},
			DMARC: &trace.MailPolicy{Name: "_dmarc.example.com.", Lookup: trace.Lookup{Name: "_dmarc.example.com."},
				Found: trace.PolicyInvalid, Why: "2 records begin v=DMARC1, and a sender reads that as none"},
			Stopped: "the budget ran out before every lookup was made",
		},
		ServicePath: &trace.ServicePath{
			Name: "www.example.com.", Type: "HTTPS",
			Chain: []trace.ServiceSet{
				{Lookup: trace.Lookup{Name: "www.example.com.", DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com."}},
					Records: []trace.RR{{Name: "www.example.com.", TTL: 300, Type: "HTTPS", Data: "0 cdn.example.net.",
						Service: &trace.Service{Target: "cdn.example.net."}}}},
				{Lookup: trace.Lookup{Name: "cdn.example.net.", DNSSEC: &trace.DNSSECStatus{State: trace.Insecure, Zone: "example.net."}},
					Records: []trace.RR{{Name: "cdn.example.net.", TTL: 300, Type: "HTTPS",
						Data: `1 edge.example.net. alpn="h3" port="8443" ipv4hint="192.0.2.1" ech="AEX+DQBBAAA="`,
						Service: &trace.Service{Priority: 1, Target: "edge.example.net.", ALPN: []string{"h3"}, Port: 8443,
							Hints: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ECH: true}}}},
			},
			Targets: []trace.ServiceTarget{{Name: "edge.example.net.", Priority: 1,
				IPv4:  &trace.Lookup{Name: "edge.example.net.", DNSSEC: &trace.DNSSECStatus{State: trace.Insecure, Zone: "example.net."}},
				IPv6:  &trace.Lookup{Name: "edge.example.net.", Err: "SERVFAIL"},
				Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
				Hints: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Stray: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}},
		},
		Registration: &trace.Registration{
			Domain: "example.com.", Server: "https://rdap.verisign.com/com/v1/", State: trace.Registered,
			Registered: time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC), Expires: time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC),
			Status: []string{"client delete prohibited", "client transfer prohibited"},
			NS:     []string{"a.iana-servers.net.", "b.iana-servers.net."}, DS: []uint16{370}, Signed: true, Parent: "com.",
			NSOnlyRegistry: []string{"b.iana-servers.net."}, NSOnlyParent: []string{"c.iana-servers.net."},
			DSChecked: true, DSOnlyRegistry: []uint16{370}, DSOnlyParent: []uint16{2371}, DSDiffer: false,
		},
		Check: &trace.Check{Zone: "example.com.", Areas: []trace.Graded{
			{Area: trace.AreaAnswer, Grade: trace.GradePassed, Text: "www.example.com. A is 93.184.216.34"},
			{Area: trace.AreaDelegation, Grade: trace.GradeLook, Text: "example.com. lists c.iana-servers.net., which the delegation does not carry", More: 1},
			{Area: trace.AreaDNSSEC, Grade: trace.GradeBroken, Text: "the chain of trust breaks at example.com."},
			{Area: trace.AreaStrangers, Grade: trace.GradeSkipped, Text: "not asked; --check-axfr and --check-recursion probe the nameservers"},
		}},
		Propagation: &trace.Propagation{Zone: "example.com.", Waits: []trace.Wait{
			{Change: trace.ChangeAnswer, Seconds: 300, Type: "A", Held: []trace.Held{{Zone: "example.com.", TTL: 300}}},
			{Change: trace.ChangeDenial, Seconds: 900, Type: "SOA", Held: []trace.Held{
				{Zone: "example.com.", TTL: 3600}, {Zone: "example.com.", TTL: 900, Field: "minimum"}}},
			{Change: trace.ChangeNameservers, Seconds: 172800, Type: "NS", Held: []trace.Held{
				{Zone: "com.", TTL: 172800}, {Zone: "example.com.", TTL: 3600}}},
		}},
	}
}

func TestRender(t *testing.T) {
	var got bytes.Buffer
	if err := jsonout.Render(&got, resolution()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	golden.Compare(t, "resolution", got.String())
}

// TestRenderShape checks the promises the schema makes, rather than the exact
// bytes the golden file holds.
func TestRenderShape(t *testing.T) {
	var out bytes.Buffer
	if err := jsonout.Render(&out, resolution()); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("the output is not JSON: %v", err)
	}

	if version, _ := got["schema_version"].(float64); int(version) != jsonout.SchemaVersion {
		t.Errorf("got schema_version %v, want %d", got["schema_version"], jsonout.SchemaVersion)
	}
	if elapsed, _ := got["elapsed_ms"].(float64); elapsed != 41.5 {
		t.Errorf("got elapsed_ms %v, want it in milliseconds", got["elapsed_ms"])
	}

	// An address is a string, not an array of bytes, and a duration is a number
	// of milliseconds.
	step := got["root"].(map[string]any)["children"].([]any)[0].(map[string]any)
	if ip, _ := step["server"].(map[string]any)["ip"].(string); ip != "198.41.0.4" {
		t.Errorf("got ip %v, want it written out", step["server"])
	}
	if rtt, _ := step["rtt_ms"].(float64); rtt != 12 {
		t.Errorf("got rtt_ms %v, want 12", step["rtt_ms"])
	}
}

func TestRenderNothing(t *testing.T) {
	var got bytes.Buffer
	if err := jsonout.Render(&got, nil); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(got.Bytes(), &document); err != nil {
		t.Fatalf("the output is not JSON: %v", err)
	}
	if _, ok := document["schema_version"]; !ok {
		t.Errorf("got %v, want a document that still says what schema it is", document)
	}
}

// TestRenderEscapesNames covers the fields a script reads with jq -r. data is
// escaped by the codec already; names, ALPN ids and EXTRA-TEXT are not, and
// written as they arrived they would put a server's escapes on the reader's
// screen.
func TestRenderEscapesNames(t *testing.T) {
	const forged = "x\x1b[2J.example."
	tr := &trace.Trace{Root: &trace.Step{Kind: trace.KindZone, Children: []*trace.Step{{
		Zone: forged, Kind: trace.KindAnswer, Server: trace.Server{Name: forged},
		Records: []trace.RR{{Name: forged, Type: "HTTPS", Data: `1 . alpn="\027[2J"`,
			Service: &trace.Service{Priority: 1, Target: forged, ALPN: []string{"\x1b[2J"}}}},
		Extended: []trace.ExtendedError{{Code: 18, Reason: "Prohibited", Text: "ok\x1b[1A\x1b[2Kforged line"}},
	}}}, Resolvers: []*trace.Resolver{{
		Extended: []trace.ExtendedError{{Code: 18, Text: "\x1b[2J"}},
	}}}

	var got bytes.Buffer
	if err := jsonout.Render(&got, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if bytes.Contains(got.Bytes(), []byte(`\u001b`)) {
		t.Errorf("got %s, want every name, ALPN id and EXTRA-TEXT escaped the way data is", got.String())
	}
}

// TestRenderKeepsExtraTextWhole covers EXTRA-TEXT longer than the tree draws.
// The document is the server's copy, escaped rather than clipped.
func TestRenderKeepsExtraTextWhole(t *testing.T) {
	text := strings.Repeat("\x1b", trace.MaxExtraText) + `\`
	tr := &trace.Trace{Root: &trace.Step{Kind: trace.KindZone, Children: []*trace.Step{{
		Zone: "example.", Kind: trace.KindError, Rcode: "REFUSED",
		Extended: []trace.ExtendedError{{Code: 18, Text: text}},
	}}}}

	var got bytes.Buffer
	if err := jsonout.Render(&got, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var document struct {
		Root struct {
			Children []struct {
				Extended []struct {
					Text string `json:"text"`
				} `json:"extended"`
			} `json:"children"`
		} `json:"root"`
	}
	if err := json.Unmarshal(got.Bytes(), &document); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := strings.Repeat(`\027`, trace.MaxExtraText) + `\\`
	if children := document.Root.Children; len(children) != 1 || len(children[0].Extended) != 1 ||
		children[0].Extended[0].Text != want {
		t.Errorf("got %s, want text %q", got.String(), want)
	}
}
