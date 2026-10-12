package main

import (
	"bytes"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/cli"
	"github.com/rafaeljusto/dnstree/v2/internal/history"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// keyed is a secure walk into example.com. whose parent holds these DS.
func keyed(ds ...uint16) *trace.Trace {
	verdict := &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.", DSTTL: 86400, KeysTTL: 3600,
		Keys: []trace.Key{{Tag: 1, Algorithm: "ED25519", SEP: true, Pointed: true, Signs: true}}}
	for _, tag := range ds {
		match := trace.DSUnmatched
		if tag == 1 {
			match = trace.DSMatched
		}
		verdict.DS = append(verdict.DS, trace.DS{Tag: tag, Algorithm: "ED25519", Digest: "SHA256", Match: match})
	}
	referral := &trace.Step{Zone: "com.", Kind: trace.KindReferral, DNSSEC: verdict,
		Delegation: &trace.Delegation{Zone: "example.com.", NS: []string{"ns.example.com."}},
		Children: []*trace.Step{{Zone: "example.com.", Kind: trace.KindAnswer,
			Records: []trace.RR{{Name: "example.com.", TTL: 300, Type: "A", Data: "192.0.2.1"}}}}}
	return &trace.Trace{
		Question: trace.Question{Name: "example.com.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{referral}},
	}
}

// TestChangedTimesTheRollover covers what --rollover takes from --diff: the
// walk remembered before says which DS came first, and when the new one was
// first seen, before anything is drawn.
func TestChangedTimesTheRollover(t *testing.T) {
	t.Setenv(history.DirEnv, t.TempDir())
	cfg := &cli.Config{Diff: true, Rollover: true}

	var stderr bytes.Buffer
	first := keyed(1)
	changed(cfg, first, &stderr)
	if first.Rollover == nil || first.Rollover.State != trace.RolloverNone {
		t.Fatalf("got %+v, want nothing in flight the first time", first.Rollover)
	}

	second := keyed(1, 2)
	changed(cfg, second, &stderr)
	if stderr.Len() > 0 {
		t.Fatalf("got %q on stderr, want the walks remembered", stderr.String())
	}
	got := second.Rollover
	if got == nil || len(got.Readings) != 1 {
		t.Fatalf("got %+v, want one reading once the DS that came later is known", got)
	}
	reading := got.Readings[0]
	if reading.Next != trace.NextSwapKey || reading.New != 2 || len(reading.Waits) != 1 || reading.Waits[0].Since.IsZero() {
		t.Errorf("got %+v, want the key swapped for DS 2, timed from when it was first seen", reading)
	}
}

func TestChangedWithoutDiff(t *testing.T) {
	tr := keyed(1, 2)
	var stderr bytes.Buffer
	if findings := changed(&cli.Config{Rollover: true}, tr, &stderr); findings != nil || tr.Rollover != nil {
		t.Errorf("got %v and %+v, want nothing remembered or worked out without --diff", findings, tr.Rollover)
	}
}
