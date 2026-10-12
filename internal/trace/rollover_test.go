package trace_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// keyed is a secure entry into example.com. with these keys and DS, and an
// answer signed by the key tagged signer.
func keyed(keys []trace.Key, ds []trace.DS, signal *trace.Signal, signer uint16) *trace.Trace {
	verdict := &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.", Keys: keys, DS: ds,
		DSTTL: 86400, KeysTTL: 3600, Signal: signal}
	answer := answered(300)
	answer.DNSSEC = &trace.DNSSECStatus{State: trace.Secure, Zone: "example.com.",
		Algorithm: "ECDSAP256SHA256", KeyTags: []uint16{signer}}
	tr := walked(&trace.Delegation{Zone: "example.com.", TTL: 172800}, verdict, answer)
	tr.Started = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	return tr
}

func ksk(tag uint16, pointed, signs bool) trace.Key {
	return trace.Key{Tag: tag, Algorithm: "ECDSAP256SHA256", SEP: true, Pointed: pointed, Signs: signs}
}

func zsk(tag uint16) trace.Key {
	return trace.Key{Tag: tag, Algorithm: "ECDSAP256SHA256"}
}

func ds(tag uint16, match trace.DSMatch) trace.DS {
	return trace.DS{Tag: tag, Algorithm: "ECDSAP256SHA256", Digest: "SHA256", Match: match}
}

// read is each reading in one line, the way the tests below want them.
func read(r *trace.Rollover) []string {
	var lines []string
	for _, reading := range r.Readings {
		line := fmt.Sprintf("%s %s %s %d>%d", reading.Kind, reading.Method, reading.Next, reading.Old, reading.New)
		for _, wait := range reading.Waits {
			line += fmt.Sprintf(" %s/%d", wait.Type, wait.TTL)
			if !wait.Since.IsZero() {
				line += "@" + wait.Since.Format("01-02")
			}
		}
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

func TestRolled(t *testing.T) {
	early := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	firstSeen := func(when map[string]time.Time) trace.Seen {
		return func(zone, rrtype string, tag uint16, algorithm string) time.Time {
			if zone != "example.com." || algorithm != "ECDSAP256SHA256" {
				return time.Time{}
			}
			return when[fmt.Sprintf("%s %d", rrtype, tag)]
		}
	}

	tests := map[string]struct {
		tr    *trace.Trace
		seen  trace.Seen
		state trace.RolloverState
		want  []string
	}{
		"one key signing key and one zone signing key": {
			tr:    keyed([]trace.Key{ksk(1, true, true), zsk(2)}, []trace.DS{ds(1, trace.DSMatched)}, nil, 2),
			state: trace.RolloverNone,
		},
		"a DS for a key not published, which way it goes unknown": {
			tr: keyed([]trace.Key{ksk(1, true, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(2, trace.DSUnmatched)}, nil, 9),
			state: trace.RolloverRolling,
			want: []string{
				"ksk double-ds swap-key 1>2 DS/86400",
				"ksk double-ds remove-ds 2>1 DNSKEY/3600",
			},
		},
		"a DS first seen after the key, so it is coming in": {
			tr: keyed([]trace.Key{ksk(1, true, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(2, trace.DSUnmatched)}, nil, 9),
			seen:  firstSeen(map[string]time.Time{"DS 1": early, "DNSKEY 1": early, "DS 2": late}),
			state: trace.RolloverRolling,
			want:  []string{"ksk double-ds swap-key 1>2 DS/86400@10-08"},
		},
		"a DS first seen before the key, so it is left over": {
			tr: keyed([]trace.Key{ksk(1, true, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(2, trace.DSUnmatched)}, nil, 9),
			seen:  firstSeen(map[string]time.Time{"DS 1": late, "DNSKEY 1": late, "DS 2": early}),
			state: trace.RolloverRolling,
			want:  []string{"ksk double-ds remove-ds 2>1 DNSKEY/3600@10-08"},
		},
		"a second key signing key with no DS, and a CDS asking for it": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, false, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched)},
				&trace.Signal{State: trace.SignalPending, Requested: []uint16{2}, Held: []uint16{1}}, 9),
			state: trace.RolloverRolling,
			want:  []string{"ksk double-ksk swap-ds 1>2 DNSKEY/3600"},
		},
		"a second key signing key with no DS, and a CDS for the key in use, which a signer keeps until it swaps": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, false, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched)},
				&trace.Signal{State: trace.SignalMatch, Requested: []uint16{1}, Held: []uint16{1}}, 9),
			state: trace.RolloverRolling,
			want: []string{
				"ksk double-ksk swap-ds 1>2 DNSKEY/3600",
				"ksk double-ksk remove-key 2>1 DS/86400",
			},
		},
		"a second key signing key with no DS, which way it goes unknown": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, false, false), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			state: trace.RolloverRolling,
			want: []string{
				"ksk double-ksk swap-ds 1>2 DNSKEY/3600",
				"ksk double-ksk remove-key 2>1 DS/86400",
			},
		},
		"two keys each with a DS, the newer signing": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, true, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(2, trace.DSMatched)}, nil, 9),
			seen: firstSeen(map[string]time.Time{"DS 1": early, "DNSKEY 1": early,
				"DS 2": late, "DNSKEY 2": late}),
			state: trace.RolloverRolling,
			want:  []string{"ksk double-rrset remove-old 1>2 DS/86400@10-08 DNSKEY/3600@10-08"},
		},
		"two keys each with a DS, the newer not signing yet": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, true, false), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(2, trace.DSMatched)}, nil, 9),
			seen: firstSeen(map[string]time.Time{"DS 1": early, "DNSKEY 1": early,
				"DS 2": late, "DNSKEY 2": late}),
			state: trace.RolloverRolling,
			want:  []string{"ksk double-rrset swap-key 1>2 DS/86400@10-08 DNSKEY/3600@10-08"},
		},
		"a second zone signing key, first seen after the one signing": {
			tr:    keyed([]trace.Key{ksk(1, true, true), zsk(8), zsk(9)}, []trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			seen:  firstSeen(map[string]time.Time{"DNSKEY 9": early, "DNSKEY 8": late}),
			state: trace.RolloverRolling,
			want:  []string{"zsk pre-publish sign-with 9>8 DNSKEY/3600@10-08"},
		},
		"a second zone signing key, first seen before the one signing": {
			tr:    keyed([]trace.Key{ksk(1, true, true), zsk(8), zsk(9)}, []trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			seen:  firstSeen(map[string]time.Time{"DNSKEY 9": late, "DNSKEY 8": early}),
			state: trace.RolloverRolling,
			want:  []string{"zsk pre-publish remove-key 8>9"},
		},
		"a second zone signing key, which way it goes unknown": {
			tr:    keyed([]trace.Key{ksk(1, true, true), zsk(8), zsk(9)}, []trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			state: trace.RolloverRolling,
			want: []string{
				"zsk pre-publish sign-with 9>8 DNSKEY/3600",
				"zsk pre-publish remove-key 8>9",
			},
		},
		"two zone signing keys and neither signed the answer": {
			tr:    keyed([]trace.Key{ksk(1, true, true), zsk(8), zsk(9)}, []trace.DS{ds(1, trace.DSMatched)}, nil, 1),
			state: trace.RolloverRolling,
			want:  []string{"zsk   0>0"},
		},
		"keys of two algorithms": {
			tr: keyed([]trace.Key{ksk(1, true, true), zsk(9),
				{Tag: 3, Algorithm: "ED25519", SEP: true, Pointed: true, Signs: true}},
				[]trace.DS{ds(1, trace.DSMatched), {Tag: 3, Algorithm: "ED25519", Digest: "SHA256", Match: trace.DSMatched}}, nil, 9),
			state: trace.RolloverRolling,
			want:  []string{"algorithm algorithm  0>0"},
		},
		"a revoked key leaves nothing in flight": {
			tr: keyed([]trace.Key{ksk(1, true, true), {Tag: 129, Algorithm: "ECDSAP256SHA256", SEP: true, Revoked: true}, zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			state: trace.RolloverNone,
		},
		"three key signing keys": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, false, true), ksk(3, false, false), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			state: trace.RolloverUnrecognised,
		},
		"a DS of a digest this build cannot compute, alone": {
			tr: keyed([]trace.Key{ksk(1, true, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(2, trace.DSUnchecked)}, nil, 9),
			state: trace.RolloverIndeterminate,
		},
		"a DS of a digest this build cannot compute, beside one that matched": {
			tr: keyed([]trace.Key{ksk(1, true, true), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(1, trace.DSUnchecked)}, nil, 9),
			state: trace.RolloverNone,
		},
		"a DS that does not digest the key of its tag": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, false, false), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched), ds(2, trace.DSUnmatched)}, nil, 9),
			state: trace.RolloverUnrecognised,
		},
		"three zone signing keys beside a key signing key rollover": {
			tr: keyed([]trace.Key{ksk(1, true, true), ksk(2, false, true), zsk(7), zsk(8), zsk(9)},
				[]trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			state: trace.RolloverRolling,
			want: []string{
				"ksk double-ksk swap-ds 1>2 DNSKEY/3600",
				"ksk double-ksk remove-key 2>1 DS/86400",
			},
		},
		"three zone signing keys, one signing the answer": {
			tr:    keyed([]trace.Key{ksk(1, true, true), zsk(7), zsk(8), zsk(9)}, []trace.DS{ds(1, trace.DSMatched)}, nil, 9),
			state: trace.RolloverUnrecognised,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := test.tr.Rolled(test.seen)
			if got.Zone != "example.com." || got.Parent != "com." {
				t.Fatalf("got zone %q under %q, want example.com. under com.", got.Zone, got.Parent)
			}
			if got.State != test.state {
				t.Errorf("got state %q (%s), want %q", got.State, got.Reason, test.state)
			}
			if name == "three zone signing keys beside a key signing key rollover" && !strings.Contains(got.Reason, "3 zone signing keys") {
				t.Errorf("got reason %q, want the zone signing keys said", got.Reason)
			}
			if lines := read(got); !reflect.DeepEqual(lines, test.want) {
				t.Errorf("got readings\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(test.want, "\n"))
			}
		})
	}
}

func TestRolledWithoutTheKeys(t *testing.T) {
	tests := map[string]struct {
		tr     *trace.Trace
		reason string
	}{
		"a walk that followed no chain": {
			tr:     walked(nil, nil, answered(300)),
			reason: "followed no chain of trust",
		},
		"an insecure delegation": {
			tr:     walked(nil, &trace.DNSSECStatus{State: trace.Insecure, Zone: "example.com."}, answered(300)),
			reason: "holds no DS",
		},
		"a chain that broke": {
			tr:     walked(nil, &trace.DNSSECStatus{State: trace.Bogus, Zone: "example.com."}, answered(300)),
			reason: "did not hold",
		},
		"a walk that reached no zone": {
			tr:     &trace.Trace{},
			reason: "reached no zone",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := test.tr.Rolled(nil)
			if got.State != trace.RolloverUnchecked || !strings.Contains(got.Reason, test.reason) {
				t.Errorf("got %q (%s), want unchecked saying %q", got.State, got.Reason, test.reason)
			}
		})
	}
}

func TestWaitingReady(t *testing.T) {
	since := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	if ready, ok := (trace.Waiting{TTL: 86400, Since: since}).Ready(); !ok || !ready.Equal(since.Add(24*time.Hour)) {
		t.Errorf("got %v %v, want a day after it was first seen", ready, ok)
	}
	if _, ok := (trace.Waiting{TTL: 86400}).Ready(); ok {
		t.Error("got a time for a record no walk saw, want none")
	}
}
