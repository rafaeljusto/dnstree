package jsonout_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

var update = flag.Bool("update", false, "rewrite the golden files")

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
		Asked:   trace.Question{Name: "www.example.com.", Type: "A"},
		Proto:   "udp",
		RTT:     9*time.Millisecond + 400*time.Microsecond,
		Rcode:   "NOERROR",
		Flags:   trace.Flags{AA: true, DO: true, EDNS: true},
		Kind:    trace.KindAnswer,
		DNSSEC:  &trace.DNSSECStatus{State: trace.Secure, KeyTags: []uint16{31589}, Algorithm: "ECDSAP256SHA256"},
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
		Rcode:  "NOERROR",
		Kind:   trace.KindReferral,
		Notes:  []string{"truncated over udp"},
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
		DNSSEC:   &trace.DNSSECStatus{State: trace.Secure, Algorithm: "ECDSAP256SHA256", Digest: "SHA256"},
		Children: []*trace.Step{answer, skipped},
	}
	timeout := &trace.Step{
		Zone:   "com.",
		Server: trace.Server{Name: "b.gtld-servers.net.", IP: netip.MustParseAddr("192.33.14.30"), Port: 53},
		Proto:  "udp",
		RTT:    2 * time.Second,
		Kind:   trace.KindTimeout,
		Err:    "udp 192.33.14.30:53: i/o timeout",
	}
	root := &trace.Step{
		Zone:       ".",
		Server:     trace.Server{Name: "a.root-servers.net.", IP: netip.MustParseAddr("198.41.0.4"), Port: 53},
		Proto:      "udp",
		RTT:        12 * time.Millisecond,
		Rcode:      "NOERROR",
		Kind:       trace.KindReferral,
		NSID:       "fra2",
		Delegation: &trace.Delegation{Zone: "com.", TTL: 172800, NS: []string{"a.gtld-servers.net."}, DSPresent: true},
		DNSSEC:     &trace.DNSSECStatus{State: trace.Insecure, Reason: "the parent published no DS"},
		Children:   []*trace.Step{timeout, tld},
	}

	return &trace.Trace{
		Question: trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{root}},
		Elapsed:  41*time.Millisecond + 500*time.Microsecond,
		Resolvers: []*trace.Resolver{{
			Server:  trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
			Elapsed: 23 * time.Millisecond,
			Rcode:   "NOERROR",
		}},
		Warnings: []string{"the delegation to example.com. lists a nameserver the zone does not"},
	}
}

func TestRender(t *testing.T) {
	var got bytes.Buffer
	if err := jsonout.Render(&got, resolution()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	compare(t, "resolution", got.String())
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

func compare(tb testing.TB, name, got string) {
	tb.Helper()

	golden := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			tb.Fatalf("writing %s: %v", golden, err)
		}
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		tb.Fatalf("%v (run go test -update to create it)", err)
	}
	if got != string(want) {
		tb.Errorf("output does not match %s, run go test -update to see the change\n--- got ---\n%s", golden, got)
	}
}
