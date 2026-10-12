package history_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/history"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// keyed is a walk into test., secure, with these keys and DS.
func keyed(keys []trace.Key, ds []trace.DS) *trace.Trace {
	tr := resolution()
	tr.Root.Children[0].DNSSEC = &trace.DNSSECStatus{State: trace.Secure, Zone: "test.", Keys: keys, DS: ds}
	return tr
}

// unchecked is the same walk with no chain of trust followed.
func unchecked() *trace.Trace {
	tr := resolution()
	tr.Root.DNSSEC, tr.Root.Children[0].DNSSEC = nil, nil
	return tr
}

func TestOfKeepsTheKeys(t *testing.T) {
	got := history.Of(keyed(
		[]trace.Key{{Tag: 1, Algorithm: "ED25519"}, {Tag: 2, Algorithm: "ED25519"}},
		// The same key in two digests is one record.
		[]trace.DS{{Tag: 1, Algorithm: "ED25519", Digest: "SHA256"}, {Tag: 1, Algorithm: "ED25519", Digest: "SHA384"}},
	), seen)

	zone := got.Zones[1]
	wantKeys := []history.Record{{Tag: 1, Algorithm: "ED25519", Since: seen}, {Tag: 2, Algorithm: "ED25519", Since: seen}}
	wantDS := []history.Record{{Tag: 1, Algorithm: "ED25519", Since: seen}}
	if !reflect.DeepEqual(zone.Keys, wantKeys) || !reflect.DeepEqual(zone.DS, wantDS) {
		t.Errorf("got keys %+v and DS %+v, want %+v and %+v", zone.Keys, zone.DS, wantKeys, wantDS)
	}
}

func TestCarry(t *testing.T) {
	earlier, later := seen, seen.Add(48*time.Hour)
	key := func(tag uint16) trace.Key { return trace.Key{Tag: tag, Algorithm: "ED25519"} }
	ds := func(tag uint16) trace.DS { return trace.DS{Tag: tag, Algorithm: "ED25519"} }

	tests := map[string]struct {
		before *history.Walk
		now    *trace.Trace
		key    map[uint16]time.Time
		ds     map[uint16]time.Time
	}{
		"a key still there keeps when it was first seen, and a new one is seen now": {
			before: history.Of(keyed([]trace.Key{key(1)}, []trace.DS{ds(1)}), earlier),
			now:    keyed([]trace.Key{key(1), key(2)}, []trace.DS{ds(1), ds(2)}),
			key:    map[uint16]time.Time{1: earlier, 2: later},
			ds:     map[uint16]time.Time{1: earlier, 2: later},
		},
		"a key of the same tag and another algorithm is a new key": {
			before: history.Of(keyed([]trace.Key{{Tag: 1, Algorithm: "RSASHA256"}}, nil), earlier),
			now:    keyed([]trace.Key{key(1)}, nil),
			key:    map[uint16]time.Time{1: later},
		},
		"a walk that checked no signatures forgets nothing": {
			before: history.Of(keyed([]trace.Key{key(1)}, []trace.DS{ds(1)}), earlier),
			now:    unchecked(),
			key:    map[uint16]time.Time{1: earlier},
			ds:     map[uint16]time.Time{1: earlier},
		},
		"nothing remembered": {
			now: keyed([]trace.Key{key(1)}, []trace.DS{ds(1)}),
			key: map[uint16]time.Time{1: later},
			ds:  map[uint16]time.Time{1: later},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			walk := history.Of(test.now, later)
			walk.Carry(test.before)
			first := walk.FirstSeen()
			for tag, want := range test.key {
				if got := first("test.", "DNSKEY", tag, "ED25519"); !got.Equal(want) {
					t.Errorf("key %d first seen %v, want %v", tag, got, want)
				}
			}
			for tag, want := range test.ds {
				if got := first("TEST.", "DS", tag, "ED25519"); !got.Equal(want) {
					t.Errorf("DS %d first seen %v, want %v", tag, got, want)
				}
			}
			if got := first("other.", "DS", 1, "ED25519"); !got.IsZero() {
				t.Errorf("got %v for a zone the walk did not cross, want nothing", got)
			}
		})
	}
}
