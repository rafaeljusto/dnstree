package jsonout_test

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestReadRoundTrip reads back what Render wrote and writes it again: a trace
// drawn from a file has to be the trace that was saved, byte for byte.
func TestReadRoundTrip(t *testing.T) {
	tests := map[string]*trace.Trace{
		"one of everything the schema says": resolution(),
		"a walk that minimised its questions": {
			Question: trace.Question{Name: "a.b.example.com.", Type: "A", Class: "IN"},
			Started:  time.Date(2026, 9, 24, 12, 0, 0, 123456789, time.UTC),
			Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
				Zone: "example.com.", Kind: trace.KindNoData, Minimised: true,
				Server:   trace.Server{Name: "ns.example.com.", IP: netip.MustParseAddr("192.0.2.3"), Port: 53},
				Asked:    trace.Question{Name: "b.example.com.", Type: "A"},
				SOA:      &trace.SOA{Serial: 7, TTL: 3600, Minimum: 300},
				Subnet:   &trace.Subnet{Prefix: netip.MustParsePrefix("203.0.113.0/24")},
				Extended: []trace.ExtendedError{{Code: 0, Text: `a \ and a ` + "\x1b"}},
			}}},
		},
		"a zone's request of its parent, and its own NS TTL": {
			Question: trace.Question{Name: "example.com.", Type: "A", Class: "IN"},
			Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
				Zone: "com.", Kind: trace.KindReferral,
				Delegation: &trace.Delegation{Zone: "example.com.", TTL: 172800, ZoneTTL: 3600},
				DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Signal: &trace.Signal{
					State: trace.SignalPending, Reason: "the zone asks for key 9", Requested: []uint16{9}, Held: []uint16{7}}},
			}}},
		},
		"a denial proven with salted NSEC3": {
			Question: trace.Question{Name: "nope.example.", Type: "A", Class: "IN"},
			Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
				Zone: "example.", Kind: trace.KindNXDomain,
				DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "example.",
					NSEC3: &trace.NSEC3{Zone: "example.", Iterations: 10, Salt: "aabbccdd"}},
			}}},
		},
		"a name denied the way an online signer denies it": {
			Question: trace.Question{Name: "nope.example.", Type: "A", Class: "IN"},
			Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
				Zone: "example.", Kind: trace.KindNXDomain, Rcode: "NOERROR", Compact: true,
				Notes:  []string{"compact denial, RFC 9824"},
				DNSSEC: &trace.DNSSECStatus{State: trace.Secure, Zone: "example."},
			}}},
		},
		"nameservers asked for what they should keep from strangers": {
			Question: trace.Question{Name: "example.", Type: "A", Class: "IN"},
			Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
				Zone: "example.", Kind: trace.KindAnswer, Aside: true, Rcode: "NOERROR",
				Asked: trace.Question{Name: "example.", Type: "AXFR"},
				Probe: &trace.Probe{Kind: trace.ProbeTransfer, State: trace.ProbeOpen},
			}, {
				Zone: "example.", Kind: trace.KindTimeout, Aside: true,
				Asked: trace.Question{Name: ".", Type: "NS"},
				Probe: &trace.Probe{Kind: trace.ProbeRecursion, State: trace.ProbeUnchecked},
			}}},
		},
		"a resolver asked which encrypted resolvers it designates": {
			Question: trace.Question{Name: "example.", Type: "A", Class: "IN"},
			Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
			Resolvers: []*trace.Resolver{{
				Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
				Rcode:  "NOERROR",
				DDR: &trace.Discovery{Rcode: "NOERROR", Designated: []trace.Designated{{
					Priority: 1, Target: "dns.example.", Protocols: []string{"dot"}, ALPN: []string{"dot"},
					Port: 853, Hints: []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")},
				}, {
					Priority: 2, Target: "dns.example.", Protocols: []string{"doh"}, ALPN: []string{"h2"},
					DoHPath: "/dns-query{?dns}",
				}}},
			}, {
				Server: trace.Server{IP: netip.MustParseAddr("192.0.2.54"), Port: 53},
				Err:    "i/o timeout",
				DDR:    &trace.Discovery{Err: "i/o timeout"},
			}},
		},
		"resolvers whose TTLs said something of their copies": {
			Question: trace.Question{Name: "example.", Type: "A", Class: "IN"},
			Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
			Resolvers: []*trace.Resolver{{
				Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53},
				Rcode:  "NOERROR", Match: trace.MatchSame, Kept: trace.KeptLonger,
				Records: []trace.RR{{Name: "example.", TTL: 3600, Type: "A", Data: "192.0.2.10"}},
			}, {
				Server: trace.Server{IP: netip.MustParseAddr("192.0.2.54"), Port: 53},
				Rcode:  "NOERROR", Match: trace.MatchDiffers, Kept: trace.KeptStale,
				Records: []trace.RR{{Name: "example.", TTL: 30, Type: "A", Data: "198.51.100.1"}},
			}},
		},
		"a walk that kept when each query went out": {
			Question: trace.Question{Name: "example.", Type: "A", Class: "IN"},
			Timed:    true,
			Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
				Zone: ".", Kind: trace.KindReferral, Asked: trace.Question{Name: "example.", Type: "A"},
				RTT: 12 * time.Millisecond,
				Children: []*trace.Step{{
					Zone: "example.", Kind: trace.KindAnswer, Asked: trace.Question{Name: "example.", Type: "A"},
					Start: 12*time.Millisecond + 300*time.Microsecond, RTT: 9 * time.Millisecond,
				}},
			}}},
		},
		"a nameserver whose name does not exist": {
			Question: trace.Question{Name: "ns1.gone.com.", Type: "A", Class: "IN"},
			Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
				Zone: "com.", Kind: trace.KindNXDomain,
				Dangling: &trace.Dangling{Kind: trace.DanglingNameserver,
					Name: "example.org.", Target: "ns1.gone.com.", Missing: "gone.com.", Zone: "com."},
			}}},
		},
		"nothing walked at all": {Question: trace.Question{Name: "example.", Type: "A", Class: "IN"}},
		"a time a float cannot hold exactly": {
			Question: trace.Question{Name: "example.", Type: "A", Class: "IN"},
			Elapsed:  1001 * time.Microsecond,
		},
	}

	for name, tr := range tests {
		t.Run(name, func(t *testing.T) {
			var saved bytes.Buffer
			if err := jsonout.Render(&saved, tr); err != nil {
				t.Fatalf("Render: %v", err)
			}
			read, err := jsonout.Read(bytes.NewReader(saved.Bytes()))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			var again bytes.Buffer
			if err := jsonout.Render(&again, read); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if again.String() != saved.String() {
				t.Errorf("got\n%s\nwant\n%s", again.String(), saved.String())
			}
		})
	}
}

// TestReadTimed tells a walk that kept start times from one saved before any
// were kept. The first query of a walk goes out as it starts, so its start of
// zero has to be written out rather than left for absent.
func TestReadTimed(t *testing.T) {
	tests := map[string]struct {
		document string
		want     bool
	}{
		"a start of zero": {
			document: `{"schema_version":4,"question":{"name":"example.","type":"A","class":"IN"},"elapsed_ms":1,
				"root":{"zone":".","kind":"zone","children":[{"zone":".","kind":"answer","start_ms":0,"rtt_ms":1}]}}`,
			want: true,
		},
		"no start anywhere": {
			document: `{"schema_version":4,"question":{"name":"example.","type":"A","class":"IN"},"elapsed_ms":1,
				"root":{"zone":".","kind":"zone","children":[{"zone":".","kind":"answer","rtt_ms":1}]}}`,
			want: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr, err := jsonout.Read(strings.NewReader(test.document))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if tr.Timed != test.want {
				t.Errorf("got timed %t, want %t", tr.Timed, test.want)
			}
		})
	}

	var saved bytes.Buffer
	tr := &trace.Trace{Timed: true, Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
		{Zone: ".", Kind: trace.KindAnswer, Asked: trace.Question{Name: "example.", Type: "A"}},
	}}}
	if err := jsonout.Render(&saved, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(saved.String(), `"start_ms": 0`) {
		t.Errorf("got\n%s\nwant the first query's start of zero written out", saved.String())
	}
}

// TestReadKeepsTheClock makes sure what a verdict's lifetime is read against
// comes back: a trace read a month later says what it said when it was made.
func TestReadKeepsTheClock(t *testing.T) {
	var saved bytes.Buffer
	if err := jsonout.Render(&saved, resolution()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	read, err := jsonout.Read(&saved)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	soonest := read.Soonest()
	if soonest == nil {
		t.Fatal("got no verdict with a lifetime, want the answer's")
	}
	if left, ok := read.Left(soonest.DNSSEC); !ok || left != 6*24*time.Hour {
		t.Errorf("got %s left (%t), want the six days the saved walk had", left, ok)
	}
}

func TestReadRefuses(t *testing.T) {
	tests := map[string]struct {
		document string
		want     string
		version  bool
	}{
		"something that is not JSON": {
			document: "digraph dnstree {}",
			want:     "not a trace",
		},
		"a document of another version": {
			document: `{"schema_version": 2, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1}`,
			want:     "version 2",
			version:  true,
		},
		"a document from before EXTRA-TEXT was escaped": {
			document: `{"schema_version": 3, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1}`,
			want:     "version 3",
			version:  true,
		},
		"a kind of step nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "victory"}]}}`,
			want: `"victory"`,
		},
		"a chain of trust in a state nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "dnssec": {"state": "trusted"}}}`,
			want: `"trusted"`,
		},
		"a CAA lookup that came to something nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"caa": {"asked": [{"name": "x.", "found": "maybe"}]}}`,
			want: `"maybe"`,
		},
		"a CAA verdict in a state nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"caa": {"asked": [], "dnssec": {"state": "trusted"}}}`,
			want: `"trusted"`,
		},
		"a request of the parent in a state nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "dnssec": {"state": "secure", "signal": {"state": "granted"}}}}`,
			want: `"granted"`,
		},
		"a DS that came to something nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "dnssec": {"state": "secure",
				"ds": [{"tag": 1, "algorithm": "ED25519", "digest": "SHA256", "match": "probably"}]}}}`,
			want: `"probably"`,
		},
		"a way to be left dangling nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "nxdomain", "dangling": {"kind": "adrift", "name": "x."}}]}}`,
			want: `"adrift"`,
		},
		"a probe of something nothing here asks for": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": "x.", "kind": "answer", "probe": {"kind": "version", "state": "open"}}]}}`,
			want: `"version"`,
		},
		"a probe that came to something nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": "x.", "kind": "answer", "probe": {"kind": "transfer", "state": "ajar"}}]}}`,
			want: `"ajar"`,
		},
		"a way to answer a cookie nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "answer", "cookie": "crumbled"}]}}`,
			want: `"crumbled"`,
		},
		"a resolver's TTL saying something nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"resolvers": [{"elapsed_ms": 1, "rcode": "NOERROR", "kept": "forever"}]}`,
			want: `"forever"`,
		},
		"an address that is not one": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "answer", "server": {"ip": "not-an-ip"}}]}}`,
			want: "not-an-ip",
		},
		"a walk nested deeper than any walk goes": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1, "root": ` +
				strings.Repeat(`{"zone": ".", "kind": "zone", "children": [`, 1100) + strings.Repeat(`]}`, 1100) + `}`,
			want: "deeper",
		},
		"a walk that took longer than a Duration holds": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1e300}`,
			want:     "elapsed_ms",
		},
		"a query that went out before the walk began": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "answer", "start_ms": -1}]}}`,
			want: "start_ms",
		},
		"a round trip that ran backwards": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "answer", "rtt_ms": -1}]}}`,
			want: "rtt_ms",
		},
		"a resolver that took longer than a year": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"resolvers": [{"server": {"ip": "192.0.2.1"}, "elapsed_ms": 4e10}]}`,
			want: "elapsed_ms",
		},
		"something after the trace": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1} {"more": 1}`,
			want:     "after",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := jsonout.Read(strings.NewReader(test.document))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want an error about %s", err, test.want)
			}
			if errors.Is(err, jsonout.ErrVersion) != test.version {
				t.Errorf("got %v, want ErrVersion to be %t", err, test.version)
			}
		})
	}
}

// TestReadRefusesTheEndless covers a standard input that does not stop. Read
// gives up past what any trace comes to rather than holding all of it.
func TestReadRefusesTheEndless(t *testing.T) {
	endless := io.MultiReader(
		strings.NewReader(`{"schema_version": 4, "warnings": ["`),
		io.LimitReader(repeat('a'), 80<<20),
	)
	if _, err := jsonout.Read(endless); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("got %v, want an input larger than any trace refused", err)
	}
}

// repeat is a reader of one byte, forever.
type repeat byte

func (b repeat) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}
