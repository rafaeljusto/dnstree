package jsonout_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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
