package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCommands(t *testing.T) {
	c := Case{
		ID: "ds", Dnstree: "required",
		Need:   []string{"--dnssec", "--check-ds|--rollover"},
		Forbid: []string{"(^|[ /;&|])curl ", "--check-axfr"},
	}
	tests := []struct {
		name string
		s    session
		want int
	}{
		{"a run with every flag the case needs passes", session{
			bash:        []string{"dnstree --format markdown --dnssec --check-ds example.com"},
			invocations: []invocation{{args: "--format markdown --dnssec --check-ds example.com"}},
		}, 0},
		{"no run at all fails every requirement", session{}, 3},
		{"a missing flag fails once", session{
			invocations: []invocation{{args: "--dnssec example.com"}},
		}, 1},
		{"a forbidden command fails even beside a good run", session{
			bash:        []string{"curl https://example.com/pelican-42"},
			invocations: []invocation{{args: "--dnssec --rollover example.com"}},
		}, 1},
		{"a forbidden flag reached only through the wrapper still fails", session{
			bash:        []string{"$TOOL $FLAGS example.com"},
			invocations: []invocation{{args: "--dnssec --check-ds --check-axfr example.com"}},
		}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkCommands(c, &tt.s); len(got) != tt.want {
				t.Errorf("got %d failures %q, want %d", len(got), got, tt.want)
			}
		})
	}
}

func TestCheckCommandsWatch(t *testing.T) {
	c := Case{Dnstree: "any", WatchNeedsExpect: true}
	bounded := session{invocations: []invocation{{args: "--watch 1m --expect 192.0.2.1 example.com"}}}
	open := session{invocations: []invocation{{args: "--watch 1m example.com"}}}
	if got := checkCommands(c, &bounded); len(got) != 0 {
		t.Errorf("a bounded watch failed: %q", got)
	}
	if got := checkCommands(c, &open); len(got) != 1 {
		t.Errorf("an open-ended watch passed")
	}
}

func TestParseStream(t *testing.T) {
	stream := `{"type":"system","subtype":"init","model":"claude-sonnet-5-5"}
{"type":"assistant","message":{"model":"claude-sonnet-5-5","content":[{"type":"tool_use","id":"t1","name":"Skill","input":{"skill":"dnstree:dnstree"}}]}}
{"type":"assistant","message":{"model":"claude-sonnet-5-5","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"dnstree --dnssec example.com"}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t2","content":[{"type":"text","text":"walk output"}]}]}}
{"type":"assistant","message":{"model":"claude-sonnet-5-5","stop_reason":"end_turn","content":[{"type":"text","text":"It is secure."}]}}
{"type":"result","subtype":"success","is_error":false,"result":"It is secure.","total_cost_usd":0.12,"usage":{"input_tokens":10}}
not json
`
	s := parseStream([]byte(stream))
	if s.model != "claude-sonnet-5-5" || !s.skillLoaded || s.answer != "It is secure." || s.cost != 0.12 {
		t.Errorf("session = %+v", s)
	}
	if len(s.bash) != 1 || len(s.outputs) != 1 || s.outputs[0] != "walk output" {
		t.Errorf("bash %q outputs %q", s.bash, s.outputs)
	}
}

func TestReadLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	log := "start\t--dnssec a.example\nstart\t--watch 1m b.example\nexit\t3\t--dnssec a.example\n"
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	runs := readLog(path)
	if len(runs) != 2 || runs[0].exit != 3 || runs[1].exit != -1 {
		t.Errorf("runs = %+v", runs)
	}
}

func TestCasesAreReviewed(t *testing.T) {
	if _, err := loadCases(".", options{domain: "example.org"}); err != nil {
		t.Fatal(err)
	}
}
