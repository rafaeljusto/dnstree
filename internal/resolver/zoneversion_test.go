package resolver_test

import (
	"encoding/binary"
	"slices"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// copyOf is a ZONEVERSION option as a server would send it.
func copyOf(labels, kind uint8, version ...byte) func(string) *dns.ZONEVERSION {
	return func(string) *dns.ZONEVERSION {
		return &dns.ZONEVERSION{Labels: labels, Type: kind, Version: version}
	}
}

func serialOf(serial uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, serial)
}

func TestZoneVersion(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		serial  bool
		option  func(string) *dns.ZONEVERSION
		want    *trace.ZoneVersion
		warning string
	}{
		"a server that says which copy answered has it recorded on the answer": {
			serial: true,
			option: copyOf(1, 0, serialOf(1)...),
			want:   &trace.ZoneVersion{Zone: "test.", Serial: 1},
		},
		"an answer out of another copy than the SOA is warned about": {
			serial:  true,
			option:  copyOf(1, 0, serialOf(7)...),
			want:    &trace.ZoneVersion{Zone: "test.", Serial: 7},
			warning: "ns.test. (192.0.2.5) answered www.test. A out of copy 7 of test., and its SOA out of copy 1",
		},
		"a walk without --serial does not ask": {
			option: copyOf(1, 0, serialOf(7)...),
		},
		"a version of a type other than the SOA serial is ignored": {
			serial: true,
			option: copyOf(1, 1, serialOf(7)...),
		},
		"a serial that is not four octets is ignored": {
			serial: true,
			option: copyOf(1, 0, 0, 7),
		},
		"a zone with more labels than the name asked is ignored": {
			serial: true,
			option: copyOf(3, 0, serialOf(7)...),
		},
		"a server that sends no version leaves the hop as it was": {
			serial: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := service(t, false, fakens.Behaviour{ZoneVersion: tt.option})
			cfg.Serial = tt.serial

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			answer := tr.Result()
			if answer == nil {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}
			switch {
			case tt.want == nil && answer.ZoneVersion != nil:
				t.Errorf("got %+v, want no zone version", answer.ZoneVersion)
			case tt.want != nil && (answer.ZoneVersion == nil || *answer.ZoneVersion != *tt.want):
				t.Errorf("got %+v, want %+v", answer.ZoneVersion, tt.want)
			}
			if tt.warning != "" && !warned(tr, tt.warning) {
				t.Errorf("got %q, want a warning with %q", tr.Warnings, tt.warning)
			}
			if tt.warning == "" && warned(tr, "out of copy") {
				t.Errorf("got %q, want no warning about copies", tr.Warnings)
			}
		})
	}
}

// TestZoneVersionRepeats covers anycast seen over time: the same address
// answers out of one copy, then another, and only the repeats show both.
func TestZoneVersionRepeats(t *testing.T) {
	t.Parallel()

	var asked atomic.Int32
	h, cfg := service(t, false, fakens.Behaviour{ZoneVersion: func(string) *dns.ZONEVERSION {
		return &dns.ZONEVERSION{Labels: 1, Version: serialOf(uint32(1 + asked.Add(1)%2))}
	}})
	cfg.Serial, cfg.Repeat = true, 4

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.Repeated == nil {
		t.Fatalf("got no repeated answer: %s", format(steps(tr)))
	}
	if got := answer.Repeated.Copies; len(got) != 2 || got[0].Times+got[1].Times != 4 {
		t.Errorf("got %+v, want the four repeats split over two copies", got)
	}
	if !warned(tr, "answered repeats of www.test. A out of 2 copies of test.") {
		t.Errorf("got %q, want a warning naming both copies", tr.Warnings)
	}
}

// TestZoneVersionStaysOffProbes covers --check, which turns on --serial and
// --check-edns together: the RFC 8906 probes must go out as the RFC writes
// them, or a server that refuses the option fails a test it would have passed.
func TestZoneVersionStaysOffProbes(t *testing.T) {
	t.Parallel()

	h, cfg := service(t, false, fakens.Behaviour{ZoneVersion: copyOf(1, 0, serialOf(1)...)})
	cfg.Serial, cfg.CheckEDNS = true, true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	carries := func(step *trace.Step) bool {
		return step.Sent != nil && slices.Contains(step.Sent.Options, dns.CodeZONEVERSION)
	}
	if answer := tr.Result(); answer == nil || !carries(answer) {
		t.Fatalf("got %+v, want the walk's own question to ask for the zone version", answer)
	}
	probes := 0
	for _, step := range steps(tr) {
		if step.EDNS == nil {
			continue
		}
		probes++
		if carries(step) {
			t.Errorf("got the %s probe of %s carrying the option", step.EDNS.Kind, step.Server.IP)
		}
	}
	if probes == 0 {
		t.Fatalf("got no EDNS probes: %s", format(steps(tr)))
	}
}
