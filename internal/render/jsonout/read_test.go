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
		"a request of the parent in a state nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "dnssec": {"state": "secure", "signal": {"state": "granted"}}}}`,
			want: `"granted"`,
		},
		"a way to answer a cookie nothing here knows": {
			document: `{"schema_version": 4, "question": {"name": "x.", "type": "A", "class": "IN"}, "elapsed_ms": 1,
				"root": {"zone": ".", "kind": "zone", "children": [{"zone": ".", "kind": "answer", "cookie": "crumbled"}]}}`,
			want: `"crumbled"`,
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
