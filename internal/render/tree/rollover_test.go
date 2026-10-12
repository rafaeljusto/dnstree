package tree_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/render/tree"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRenderRollover(t *testing.T) {
	started := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	seen := time.Date(2026, 10, 7, 9, 12, 0, 0, time.UTC)
	inUse := trace.RolloverKey{Tag: 12345, Algorithm: "ECDSAP256SHA256", SEP: true, Published: true, DS: true, SignsKeys: true}
	incoming := trace.RolloverKey{Tag: 23456, Algorithm: "ECDSAP256SHA256", DS: true, DSSeen: seen}
	rolling := func(readings ...trace.Reading) *trace.Rollover {
		return &trace.Rollover{Zone: "example.com.", Parent: "com.", State: trace.RolloverRolling,
			Keys: []trace.RolloverKey{inUse, incoming}, KeysTTL: 3600, DSTTL: 86400, Readings: readings}
	}
	swap := func(since time.Time) trace.Reading {
		return trace.Reading{Kind: trace.KindKSK, Method: trace.MethodDoubleDS, New: 23456, Old: 12345, Next: trace.NextSwapKey,
			Waits: []trace.Waiting{{Type: "DS", Tag: 23456, TTL: 86400, Since: since}}}
	}
	keys := []string{
		"rollover: the keys of example.com., and the DS com. holds for them",
		"rollover:   12345  key signing key   published, DS at com., signs the keys",
		"rollover:   23456  key signing key   not published, DS at com.; first seen 2026-10-07 09:12 UTC",
	}

	tests := map[string]struct {
		rollover *trace.Rollover
		started  time.Time
		want     []string
	}{
		"a step whose wait is over": {
			rollover: rolling(swap(seen)),
			started:  started,
			want: append(keys,
				"rollover: example.com. is changing its key signing key by double DS, from 12345 to 23456",
				"rollover:   next: publish key 23456 and sign the keys with it in place of key 12345",
				"rollover:   waited: the DS TTL at com. of 1d has run out since DS 23456 was first seen, 2d2h ago",
				"rollover:   counted from the first server that served it: one that picked it up later, a TTL lowered for the rollover, or a record withdrawn between remembered walks makes the wait longer (RFC 7583)",
			),
		},
		"a step whose wait is not over": {
			rollover: rolling(swap(seen)),
			started:  seen.Add(time.Hour),
			want: append(keys,
				"rollover: example.com. is changing its key signing key by double DS, from 12345 to 23456",
				"rollover:   next: publish key 23456 and sign the keys with it in place of key 12345",
				"rollover:   wait: the DS TTL at com. runs out at 2026-10-08 09:12 UTC, 1d after DS 23456 was first seen",
				"rollover:   counted from the first server that served it: one that picked it up later, a TTL lowered for the rollover, or a record withdrawn between remembered walks makes the wait longer (RFC 7583)",
			),
		},
		"a step no walk saw the start of": {
			rollover: rolling(swap(time.Time{})),
			started:  started,
			want: append(keys,
				"rollover: example.com. is changing its key signing key by double DS, from 12345 to 23456",
				"rollover:   next: publish key 23456 and sign the keys with it in place of key 12345",
				"rollover:   wait: 1d after DS 23456 was published, the DS TTL at com.",
				"rollover: --diff remembers when each key was first seen, and times the next step from it",
			),
		},
		"two readings the walk cannot choose between": {
			rollover: rolling(swap(time.Time{}), trace.Reading{Kind: trace.KindKSK, Method: trace.MethodDoubleDS,
				New: 12345, Old: 23456, Next: trace.NextRemoveDS, Waits: []trace.Waiting{{Type: "DNSKEY", Tag: 12345, TTL: 3600}}}),
			started: started,
			want: append(keys,
				"rollover: example.com. is changing its key signing key, and one walk cannot tell which key is the new one",
				"rollover:   if 23456 is new, by double DS: next publish key 23456 and sign the keys with it in place of key 12345",
				"rollover:     wait: 1d after DS 23456 was published, the DS TTL at com.",
				"rollover:   if 12345 is new, by double DS: next remove DS 23456 from com.",
				"rollover:     wait: 1h after key 12345 was published, the DNSKEY TTL",
				"rollover: --check-ds reads the CDS, which names the key coming in",
				"rollover: --diff remembers when each key is first seen, so a key that appears after a remembered walk is known to be the new one",
			),
		},
		"a zone signing key going out, which is not timed": {
			rollover: &trace.Rollover{Zone: "example.com.", Parent: "com.", State: trace.RolloverRolling,
				Readings: []trace.Reading{{Kind: trace.KindZSK, Method: trace.MethodPrePublish, New: 2, Old: 1, Next: trace.NextRemoveKey}}},
			want: []string{
				"rollover: the keys of example.com., and the DS com. holds for them",
				"rollover: example.com. is changing its zone signing key by pre-publish, from 1 to 2",
				"rollover:   next: stop publishing key 1",
				"rollover:   wait: the longest TTL of what key 1 signed, after it stopped; a walk does not read every TTL in the zone, so this is not timed",
				"rollover:   a key that signs nothing may instead be another operator's, in a zone signed by several (RFC 8901)",
			},
		},
		"two keys each with a DS, which two operators also publish": {
			rollover: &trace.Rollover{Zone: "example.com.", Parent: "com.", State: trace.RolloverRolling, DSTTL: 86400, KeysTTL: 3600,
				Readings: []trace.Reading{{Kind: trace.KindKSK, Method: trace.MethodDoubleRRset, New: 2, Old: 1, Next: trace.NextRemoveOld,
					Waits: []trace.Waiting{{Type: "DS", Tag: 2, TTL: 86400}}}}},
			want: []string{
				"rollover: the keys of example.com., and the DS com. holds for them",
				"rollover: example.com. is changing its key signing key by double RRset, from 1 to 2",
				"rollover:   next: stop publishing key 1, and remove DS 1 from com.",
				"rollover:   wait: 1d after DS 2 was published, the DS TTL at com.",
				"rollover:   two keys each with a DS may instead be two operators', in a zone signed by several (RFC 8901)",
				"rollover: --diff remembers when each key was first seen, and times the next step from it",
			},
		},
		"keys of two algorithms": {
			rollover: &trace.Rollover{Zone: "example.com.", Parent: "com.", State: trace.RolloverRolling,
				Readings: []trace.Reading{{Kind: trace.KindAlgorithm, Method: trace.MethodAlgorithm}}},
			want: []string{
				"rollover: the keys of example.com., and the DS com. holds for them",
				"rollover: example.com. publishes keys of more than one algorithm: an algorithm rollover, whose steps are not timed here",
			},
		},
		"a zone with nothing in flight": {
			rollover: &trace.Rollover{Zone: "example.com.", Parent: "com.", State: trace.RolloverNone,
				Keys: []trace.RolloverKey{inUse}},
			want: []string{
				"rollover: example.com. is not rolling its keys",
				"rollover:   12345  key signing key   published, DS at com., signs the keys",
			},
		},
		"a zone with zone signing keys standing by": {
			rollover: &trace.Rollover{Zone: "example.com.", Parent: "com.", State: trace.RolloverUnrecognised,
				Reason: "3 zone signing keys are published and 1 signed the answer: the others stand by for a rollover, or are another operator's (RFC 8901)",
				Keys: []trace.RolloverKey{inUse,
					{Tag: 1, Algorithm: "ECDSAP256SHA256", Published: true},
					{Tag: 2, Algorithm: "ECDSAP256SHA256", Published: true, SignsData: true},
					{Tag: 3, Algorithm: "ECDSAP256SHA256", Published: true}}},
			want: []string{
				"rollover: the keys of example.com. fit no one rollover: 3 zone signing keys are published and 1 signed the answer: the others stand by for a rollover, or are another operator's (RFC 8901)",
				"rollover:   12345  key signing key   published, DS at com., signs the keys",
				"rollover:   1      zone signing key  published",
				"rollover:   2      zone signing key  published, signs the answer",
				"rollover:   3      zone signing key  published",
			},
		},
		"a zone whose keys were not read": {
			rollover: &trace.Rollover{Zone: "example.com.", State: trace.RolloverUnchecked,
				Reason: "the chain of trust did not hold into example.com."},
			want: []string{"rollover: nothing to read: the chain of trust did not hold into example.com."},
		},
		"more in flight than one rollover": {
			rollover: &trace.Rollover{Zone: "example.com.", Parent: "com.", State: trace.RolloverUnrecognised,
				Reason: "3 key signing keys and DS records are in play, more than any one rollover has"},
			want: []string{"rollover: the keys of example.com. fit no one rollover: 3 key signing keys and DS records are in play, more than any one rollover has"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var got bytes.Buffer
			tr := &trace.Trace{Started: test.started, Rollover: test.rollover}
			if err := tree.Render(&got, tr, tree.Options{}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if lines := strings.Split(strings.TrimSuffix(got.String(), "\n"), "\n"); !reflect.DeepEqual(lines, test.want) {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(test.want, "\n"))
			}
		})
	}
}
