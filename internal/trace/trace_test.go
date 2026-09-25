package trace_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// tree is a walk that tried two servers at the root before getting anywhere.
func tree() *trace.Trace {
	answer := &trace.Step{Zone: "example.com.", Kind: trace.KindAnswer}
	referral := &trace.Step{Zone: ".", Kind: trace.KindReferral, Children: []*trace.Step{answer}}
	return &trace.Trace{
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
			{Zone: ".", Kind: trace.KindLame},
			referral,
		}},
	}
}

func TestSteps(t *testing.T) {
	var kinds []trace.StepKind
	for step := range tree().Steps() {
		kinds = append(kinds, step.Kind)
	}

	want := []trace.StepKind{trace.KindZone, trace.KindLame, trace.KindReferral, trace.KindAnswer}
	if len(kinds) != len(want) {
		t.Fatalf("got %v, want %v", kinds, want)
	}
	for i, kind := range kinds {
		if kind != want[i] {
			t.Fatalf("got %v, want parents before children: %v", kinds, want)
		}
	}
}

func TestStepsStop(t *testing.T) {
	seen := 0
	for range tree().Steps() {
		seen++
		break
	}
	if seen != 1 {
		t.Errorf("got %d steps, want the walk to stop when the caller does", seen)
	}

	if steps := (&trace.Trace{}).Steps(); steps == nil {
		t.Fatal("got no iterator for an empty trace, want an empty one")
	}
	for range (&trace.Trace{}).Steps() {
		t.Error("got a step from an empty trace, want none")
	}
}

func TestResult(t *testing.T) {
	if got := tree().Result(); got == nil || got.Kind != trace.KindAnswer {
		t.Errorf("got %+v, want the answering step", got)
	}

	unanswered := &trace.Trace{Root: &trace.Step{Kind: trace.KindZone, Children: []*trace.Step{
		{Kind: trace.KindTimeout},
	}}}
	if got := unanswered.Result(); got != nil {
		t.Errorf("got %+v, want no result when nothing answered", got)
	}
}

// TestTight covers the one reading the recorded size is there for: whether an
// answer had room left. It is a judgement the trace makes once, so that the
// tree, the sentences under it and the JSON cannot come to disagree.
func TestTight(t *testing.T) {
	tests := map[string]struct {
		step trace.Step
		want bool
	}{
		"an answer that all but filled the datagram it came in":    {step: trace.Step{Size: 1200, Limit: 1232}, want: true},
		"an answer that filled it exactly":                         {step: trace.Step{Size: 1232, Limit: 1232}, want: true},
		"an answer with a record's worth of room left":             {step: trace.Step{Size: 900, Limit: 1232}, want: false},
		"a small answer in the 512 a query without EDNS0 is given": {step: trace.Step{Size: 60, Limit: 512}, want: false},
		"an answer that all but filled that 512":                   {step: trace.Step{Size: 500, Limit: 512}, want: true},
		"a large answer over TCP, which no datagram bounded":       {step: trace.Step{Size: 4096}, want: false},
		"a hop that received nothing":                              {step: trace.Step{Limit: 1232}, want: false},
		"a server that was listed and never queried":               {step: trace.Step{Kind: trace.KindSkipped}, want: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := test.step.Tight(); got != test.want {
				t.Errorf("got %v for %d of %d bytes, want %v", got, test.step.Size, test.step.Limit, test.want)
			}
		})
	}
}

// TestExtendedErrorIsDrawable covers EXTRA-TEXT, the one field of a reply a
// server writes in words of its own choosing. Drawn raw it could move the
// cursor, split a line or break --format ascii.
func TestExtendedErrorIsDrawable(t *testing.T) {
	tests := map[string]struct {
		text string
		want string
	}{
		"plain words stay as they are":  {"on the list", "Blocked (15): on the list"},
		"escapes cannot reach a screen": {"x\x1b[2K\r\n[secure]", `Blocked (15): x\027[2K\013\010[secure]`},
		"bytes above 127 are escaped":   {"café", `Blocked (15): caf\195\169`},
		"a backslash is escaped too":    {`a\b`, `Blocked (15): a\\b`},
		"a long text is clipped": {strings.Repeat("a", trace.MaxExtraText+10),
			"Blocked (15): " + strings.Repeat("a", trace.MaxExtraText) + "..."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ede := trace.ExtendedError{Code: 15, Reason: "Blocked", Text: test.text}
			if got := ede.String(); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestShown covers names, which the codec hands over as the octets the server
// sent rather than escaped as text rdata is.
func TestShown(t *testing.T) {
	tests := map[string]struct {
		text string
		want string
	}{
		"a plain name stays as it is":           {"www.example.com.", "www.example.com."},
		"an escape cannot reach a screen":       {"x\x1b[1A\r.example.", `x\027[1A\013.example.`},
		"bytes above 127 are escaped":           {"café.example.", `caf\195\169.example.`},
		"rdata the codec escaped is left alone": {`"\027[2J"`, `"\027[2J"`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := trace.Shown(test.text); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestTraceShown covers the copy the renderers draw: every string that came
// off the wire escaped, and the walk's own trace left holding the octets it
// queries with.
func TestTraceShown(t *testing.T) {
	const raw = "ns\x1b[2K.example."
	step := &trace.Step{
		Zone:       raw,
		Server:     trace.Server{Name: raw, ASN: &trace.ASNInfo{Registry: raw}},
		Asked:      trace.Question{Name: raw},
		Records:    []trace.RR{{Name: raw, Data: raw, Service: &trace.Service{Target: raw, ALPN: []string{raw}}}},
		Notes:      []string{raw},
		Delegation: &trace.Delegation{Zone: raw, NS: []string{raw}, GlueLess: []string{raw}, OutOfBailiwick: []string{raw}},
		DNSSEC:     &trace.DNSSECStatus{Zone: raw, Reason: raw},
	}
	tr := &trace.Trace{
		Question:  trace.Question{Name: raw},
		Root:      &trace.Step{Kind: trace.KindZone, Children: []*trace.Step{step}},
		Warnings:  []string{raw},
		Resolvers: []*trace.Resolver{{Server: trace.Server{Name: raw}, Err: raw, Records: []trace.RR{{Name: raw}}}},
	}

	shown := tr.Shown()
	got := shown.Root.Children[0]
	for field, value := range map[string]string{
		"question":         shown.Question.Name,
		"zone":             got.Zone,
		"server":           got.Server.Name,
		"registry":         got.Server.ASN.Registry,
		"asked":            got.Asked.Name,
		"owner":            got.Records[0].Name,
		"data":             got.Records[0].Data,
		"target":           got.Records[0].Service.Target,
		"alpn":             got.Records[0].Service.ALPN[0],
		"note":             got.Notes[0],
		"delegation":       got.Delegation.Zone,
		"ns":               got.Delegation.NS[0],
		"glueless":         got.Delegation.GlueLess[0],
		"out of bailiwick": got.Delegation.OutOfBailiwick[0],
		"dnssec zone":      got.DNSSEC.Zone,
		"reason":           got.DNSSEC.Reason,
		"warning":          shown.Warnings[0],
		"resolver":         shown.Resolvers[0].Server.Name,
		"resolver error":   shown.Resolvers[0].Err,
		"resolver owner":   shown.Resolvers[0].Records[0].Name,
	} {
		if strings.Contains(value, "\x1b") {
			t.Errorf("%s drawn raw: %q", field, value)
		}
	}
	if step.Delegation.NS[0] != raw || step.Server.Name != raw || step.Records[0].Service.ALPN[0] != raw {
		t.Errorf("the walk's own trace was escaped too: %+v", step)
	}
}

// TestExpiringLongLife covers a signature made to last longer than five times
// what a Duration holds a fifth of. RRSIG times reach 68 years either side of
// now, and one an hour into sixty years of life is nowhere near its end.
func TestExpiringLongLife(t *testing.T) {
	const year = 365 * 24 * time.Hour
	started := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	tr := &trace.Trace{Started: started}

	for name, test := range map[string]struct {
		life, left time.Duration
		stale      bool
	}{
		"an hour into sixty years is fresh":        {life: 60*year + time.Hour, left: 60 * year},
		"a year left of sixty is stale":            {life: 60 * year, left: year, stale: true},
		"an hour left of a day is stale":           {life: 24 * time.Hour, left: time.Hour, stale: true},
		"a fifth of the life left is not yet late": {life: 5 * time.Hour, left: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			expiration := started.Add(test.left)
			status := &trace.DNSSECStatus{Signatures: []trace.Lifetime{
				{Inception: expiration.Add(-test.life), Expiration: expiration},
			}}
			if _, stale := tr.Expiring(status); stale != test.stale {
				t.Errorf("got stale %v, want %v", stale, test.stale)
			}
		})
	}
}
