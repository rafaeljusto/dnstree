package jsonout

import "github.com/rafaeljusto/dnstree/v2/internal/trace"

// rollover is where a change of keys in the zone the walk ended in stands.
// Like propagation it is worked out from the rest of the document, so it is
// written and never read back. When each key was first seen comes only from
// --diff, which no format read by a program takes, so it is not written.
type rollover struct {
	Zone     string            `json:"zone"`
	State    string            `json:"state"`
	Reason   string            `json:"reason,omitempty"`
	Parent   string            `json:"parent,omitempty"`
	KeysTTL  uint32            `json:"keys_ttl,omitempty"`
	DSTTL    uint32            `json:"ds_ttl,omitempty"`
	Keys     []rolloverKey     `json:"keys,omitempty"`
	Readings []rolloverReading `json:"readings,omitempty"`
}

type rolloverKey struct {
	Tag       uint16 `json:"tag"`
	Algorithm string `json:"algorithm"`
	SEP       bool   `json:"sep,omitempty"`
	Published bool   `json:"published"`
	DS        bool   `json:"ds"`
	SignsKeys bool   `json:"signs_keys,omitempty"`
	SignsData bool   `json:"signs_data,omitempty"`
}

type rolloverReading struct {
	Kind   string         `json:"kind"`
	Method string         `json:"method,omitempty"`
	New    *uint16        `json:"new,omitempty"`
	Old    *uint16        `json:"old,omitempty"`
	Next   string         `json:"next,omitempty"`
	Waits  []rolloverWait `json:"waits,omitempty"`
}

type rolloverWait struct {
	Type string `json:"type"`
	Tag  uint16 `json:"tag"`
	TTL  uint32 `json:"ttl"`
}

func convertRollover(from *trace.Rollover) *rollover {
	if from == nil {
		return nil
	}
	to := &rollover{Zone: from.Zone, State: string(from.State), Reason: from.Reason, Parent: from.Parent,
		KeysTTL: from.KeysTTL, DSTTL: from.DSTTL}
	for _, k := range from.Keys {
		to.Keys = append(to.Keys, rolloverKey{Tag: k.Tag, Algorithm: k.Algorithm, SEP: k.SEP, Published: k.Published,
			DS: k.DS, SignsKeys: k.SignsKeys, SignsData: k.SignsData})
	}
	for _, r := range from.Readings {
		reading := rolloverReading{Kind: string(r.Kind), Method: string(r.Method), Next: string(r.Next)}
		// Only a next step pairs a key coming in with one going out.
		if r.Next != "" {
			reading.New, reading.Old = new(r.New), new(r.Old)
		}
		for _, w := range r.Waits {
			reading.Waits = append(reading.Waits, rolloverWait{Type: w.Type, Tag: w.Tag, TTL: w.TTL})
		}
		to.Readings = append(to.Readings, reading)
	}
	return to
}
