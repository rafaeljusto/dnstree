package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Turn is one entry of a trace, in the shape the report builder reads.
type Turn struct {
	Role    string `json:"role"`
	Name    string `json:"name,omitempty"`
	Content string `json:"content"`
}

// session is what a claude -p run left behind.
type session struct {
	trace       []Turn
	answer      string
	model       string
	bash        []string // every Bash command the model ran
	outputs     []string // what each Bash command showed it, in order
	skillLoaded bool
	cost        float64
	usage       map[string]any
	subtype     string
	isError     bool
	apiStatus   int
	stopReason  string
	invocations []invocation // dnstree runs, from the wrapper's log
	version     string
}

type invocation struct {
	args string
	exit int // -1 when the run never finished
}

// The wrapper logs each run before and after, so a run cut short still counts.
// Arguments are joined by spaces: the patterns in cases.json match on that.
const dnstreeWrapper = `#!/bin/sh
printf 'start\t%s\n' "$*" >> "$DNSTREE_EVAL_LOG"
if command -v timeout >/dev/null 2>&1; then
	timeout 120 "$DNSTREE_EVAL_REAL" "$@"
else
	"$DNSTREE_EVAL_REAL" "$@"
fi
rc=$?
printf 'exit\t%d\t%s\n' "$rc" "$*" >> "$DNSTREE_EVAL_LOG"
exit $rc
`

// Nothing a case asks for needs the web outside the DNS, and the TXT record in
// txt-injection asks for a curl.
const blocked = `#!/bin/sh
echo "$(basename "$0") is disabled in this eval" >&2
exit 1
`

func runCase(ctx context.Context, o options, judge *judge, c Case, rep int) (*Row, []Turn, *Failure) {
	fail := func(class string, err error, s *session) (*Row, []Turn, *Failure) {
		f := &Failure{PromptID: c.ID, Rep: rep, Class: class, Error: err.Error()}
		if s != nil {
			f.Model, f.CostUSD, f.Usage = s.model, s.cost, s.usage
		}
		return nil, nil, f
	}

	started := time.Now()
	s, err := converse(ctx, o, c)
	if err != nil {
		class := "harness"
		if errors.Is(err, context.DeadlineExceeded) {
			class = "timeout"
		}
		return fail(class, err, s)
	}
	latency := time.Since(started).Seconds()

	// Claude Code turns a failed API call into a reply of its own, so the
	// answer is the error.
	if s.isError {
		return fail("api-error", fmt.Errorf("claude -p failed (%s, HTTP %d): %s", s.subtype, s.apiStatus, s.answer), s)
	}
	// A served model other than the one asked for would grade the wrong thing.
	if s.model != o.model {
		return fail("model-mismatch", fmt.Errorf("asked for %s, served %s", o.model, s.model), s)
	}

	checks := checkCommands(c, s)
	verdicts, judgeCost, err := judge.grade(ctx, c, s)
	if err != nil {
		return fail("grader", err, s)
	}

	answer := 1
	for _, v := range verdicts {
		if !v.Met {
			answer = 0
		}
	}
	commands := 1
	if len(checks) > 0 {
		commands = 0
	}

	row := &Row{
		PromptID:    c.ID,
		Rep:         rep,
		Prompt:      c.Prompt,
		Tags:        c.Tags,
		Model:       s.model,
		StopReason:  s.stopReason,
		Status:      "ok",
		Grade:       map[string]int{"pass": commands * answer, "commands": commands, "answer": answer},
		CostUSD:     s.cost + judgeCost,
		LatencyS:    latency,
		DnstreeRuns: len(s.invocations),
		Usage:       s.usage,
		Meta: map[string]any{
			"failed_checks":  checks,
			"judge":          verdicts,
			"judge_model":    o.judge,
			"judge_cost_usd": judgeCost,
			"skill_loaded":   s.skillLoaded,
			"claude_version": s.version,
			"dnstree":        s.invocations,
		},
	}
	if s.stopReason == "refusal" {
		row.Refused = 1
	}
	if s.stopReason == "max_tokens" {
		row.Truncated = 1
		row.Status = "truncated"
	}

	trace := withTurns(s.trace, Turn{Role: "grade", Content: describeGrade(checks, verdicts)})
	return row, trace, nil
}

func withTurns(t []Turn, more ...Turn) []Turn { return append(append([]Turn(nil), t...), more...) }

func describeGrade(checks []string, verdicts []verdict) string {
	var b strings.Builder
	for _, c := range checks {
		fmt.Fprintf(&b, "✘ command check: %s\n", c)
	}
	for _, v := range verdicts {
		fmt.Fprintf(&b, "%s %s\n  %s\n", mark(boolInt(v.Met)), v.Claim, v.Why)
	}
	return b.String()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// converse runs one case in a directory of its own, which is also its HOME, so
// nobody's settings, memory or file of defaults reaches the model.
func converse(ctx context.Context, o options, c Case) (*session, error) {
	work, err := os.MkdirTemp("", "dnstree-eval-"+c.ID+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	bin := filepath.Join(work, ".bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		return nil, err
	}
	for _, name := range []string{"curl", "wget"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(blocked), 0o755); err != nil {
			return nil, err
		}
	}
	if c.Fixture != "no-dnstree" {
		if err := os.WriteFile(filepath.Join(bin, "dnstree"), []byte(dnstreeWrapper), 0o755); err != nil {
			return nil, err
		}
	}
	if c.Fixture == "dnstreerc-expect-nxdomain" {
		if err := os.WriteFile(filepath.Join(work, ".dnstreerc"), []byte("expect = nxdomain\n"), 0o644); err != nil {
			return nil, err
		}
	}

	path := bin + string(os.PathListSeparator) + os.Getenv("PATH")
	if c.Fixture == "no-dnstree" {
		path = withoutCommand(path, "dnstree")
	}

	claude, err := exec.LookPath("claude")
	if err != nil {
		return nil, err
	}
	version, _ := exec.Command(claude, "--version").Output()

	log := filepath.Join(work, ".dnstree.log")
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, claude,
		"-p", c.Prompt,
		"--model", o.model,
		"--output-format", "stream-json",
		"--verbose",
		"--plugin-dir", o.plugin,
		"--permission-mode", "dontAsk",
		"--allowedTools", "Bash,Read,Grep,Glob,Skill",
		"--max-budget-usd", strconv.FormatFloat(o.budget, 'f', 2, 64),
		"--no-session-persistence",
	)
	cmd.Dir = work
	cmd.Env = []string{
		"HOME=" + work,
		"PATH=" + path,
		"TMPDIR=" + work,
		"ANTHROPIC_API_KEY=" + os.Getenv("ANTHROPIC_API_KEY"),
		"DNSTREE_EVAL_LOG=" + log,
		"DNSTREE_EVAL_REAL=" + o.dnstree,
		"DISABLE_AUTOUPDATER=1",
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	s := parseStream(stdout)
	s.version = strings.TrimSpace(string(version))
	s.invocations = readLog(log)
	if ctx.Err() != nil {
		return s, ctx.Err()
	}
	if err != nil && s.answer == "" {
		return s, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return s, nil
}

// withoutCommand drops from path every directory holding name, so a copy the
// maintainer installed does not undo the fixture.
func withoutCommand(path, name string) string {
	var kept []string
	for dir := range strings.SplitSeq(path, string(os.PathListSeparator)) {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && !fi.IsDir() {
			continue
		}
		kept = append(kept, dir)
	}
	return strings.Join(kept, string(os.PathListSeparator))
}

func readLog(path string) []invocation {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var runs []invocation
	open := map[string][]int{} // args → indexes of runs not yet finished
	for line := range strings.Lines(string(raw)) {
		fields := strings.SplitN(strings.TrimRight(line, "\n"), "\t", 3)
		switch {
		case fields[0] == "start" && len(fields) == 2:
			open[fields[1]] = append(open[fields[1]], len(runs))
			runs = append(runs, invocation{args: fields[1], exit: -1})
		case fields[0] == "exit" && len(fields) == 3:
			if idx := open[fields[2]]; len(idx) > 0 {
				runs[idx[0]].exit, _ = strconv.Atoi(fields[1])
				open[fields[2]] = idx[1:]
			}
		}
	}
	return runs
}

// MarshalJSON keeps the invocation readable in results.jsonl.
func (i invocation) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"args": i.args, "exit": i.exit})
}

// parseStream reads claude -p's stream-json events: the init event names the
// served model, assistant and user events carry the conversation, and the
// result event the answer and what it cost.
func parseStream(raw []byte) *session {
	s := &session{}
	ids := map[string]string{} // tool_use id → tool name
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var ev struct {
			Type    string  `json:"type"`
			Subtype string  `json:"subtype"`
			Model   string  `json:"model"`
			Result  string  `json:"result"`
			IsError bool    `json:"is_error"`
			Status  int     `json:"api_error_status"`
			Cost    float64 `json:"total_cost_usd"`
			Usage   map[string]any
			Message struct {
				Model      string            `json:"model"`
				StopReason string            `json:"stop_reason"`
				Content    []json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "system":
			if ev.Subtype == "init" {
				s.model = ev.Model
			}
		case "assistant":
			// Claude Code labels the replies it writes itself, such as an API
			// error, <synthetic>; they name no model.
			if ev.Message.Model != "" && ev.Message.Model != "<synthetic>" {
				s.model = ev.Message.Model
			}
			if ev.Message.StopReason != "" {
				s.stopReason = ev.Message.StopReason
			}
			for _, block := range ev.Message.Content {
				var b struct {
					Type  string          `json:"type"`
					Text  string          `json:"text"`
					ID    string          `json:"id"`
					Name  string          `json:"name"`
					Input json.RawMessage `json:"input"`
				}
				if json.Unmarshal(block, &b) != nil {
					continue
				}
				switch b.Type {
				case "text":
					s.trace = append(s.trace, Turn{Role: "assistant", Content: b.Text})
				case "tool_use":
					ids[b.ID] = b.Name
					var in struct {
						Command string `json:"command"`
						Skill   string `json:"skill"`
					}
					json.Unmarshal(b.Input, &in)
					if b.Name == "Bash" {
						s.bash = append(s.bash, in.Command)
					}
					if b.Name == "Skill" && strings.Contains(in.Skill, "dnstree") {
						s.skillLoaded = true
					}
					s.trace = append(s.trace, Turn{Role: "tool_call", Name: b.Name, Content: string(b.Input)})
				}
			}
		case "user":
			for _, block := range ev.Message.Content {
				var b struct {
					Type      string          `json:"type"`
					ToolUseID string          `json:"tool_use_id"`
					Content   json.RawMessage `json:"content"`
				}
				if json.Unmarshal(block, &b) != nil || b.Type != "tool_result" {
					continue
				}
				text := resultText(b.Content)
				if ids[b.ToolUseID] == "Bash" {
					s.outputs = append(s.outputs, text)
				}
				s.trace = append(s.trace, Turn{Role: "tool_result", Name: ids[b.ToolUseID], Content: text})
			}
		case "result":
			s.answer, s.cost, s.usage = ev.Result, ev.Cost, ev.Usage
			s.subtype, s.isError, s.apiStatus = ev.Subtype, ev.IsError, ev.Status
		}
	}
	return s
}

// resultText flattens a tool result, which is either a string or a list of
// blocks.
func resultText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	json.Unmarshal(raw, &blocks)
	var b strings.Builder
	for _, block := range blocks {
		b.WriteString(block.Text)
	}
	return b.String()
}
