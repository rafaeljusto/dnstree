// Command dnstree-skill-eval runs the shipped dnstree skill through claude -p
// against cases.json and grades each transcript: code checks on the commands
// it ran, and a judge model on the answer it gave.
//
//	go run . -repo ../../.. -dnstree /path/to/dnstree -only bogus-dnssec,caa
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Case is one entry of cases.json.
type Case struct {
	ID     string   `json:"id"`
	Tags   []string `json:"tags"`
	Prompt string   `json:"prompt"`
	// Fixture prepares the case's HOME and PATH: "no-dnstree" leaves the binary
	// off PATH, "dnstreerc-expect-nxdomain" writes a file of defaults.
	Fixture string `json:"fixture,omitempty"`
	// Dnstree is "required" (the default), "any" or "forbidden".
	Dnstree string `json:"dnstree,omitempty"`
	// Need holds patterns that must each match some dnstree invocation's
	// arguments, joined by spaces.
	Need []string `json:"need,omitempty"`
	// Forbid holds patterns that no Bash command and no dnstree invocation may
	// match.
	Forbid           []string `json:"forbid,omitempty"`
	WatchNeedsExpect bool     `json:"watch_needs_expect,omitempty"`
	Rubric           []string `json:"rubric"`
}

// fidelity is judged on every case that has to run dnstree, so a right-looking
// answer that contradicts the walk still fails.
const fidelity = "No record, verdict, server, exit code or other finding the answer reports about the zone is missing from the dnstree output shown or contradicts it. Background about a domain or a standard is fine, as long as it does not stand in for what the walk found."

type options struct {
	repo, dnstree, plugin, flow, variant string
	model, judge, domain, only           string
	reps, workers                        int
	timeout                              time.Duration
	budget                               float64
	approve                              bool
}

func main() {
	var o options
	flag.StringVar(&o.repo, "repo", "../../..", "the dnstree checkout")
	flag.StringVar(&o.dnstree, "dnstree", "", "the dnstree binary the skill runs (required)")
	flag.StringVar(&o.plugin, "plugin", "", "the plugin directory under test (default REPO/packaging/plugin)")
	flag.StringVar(&o.flow, "flow", "", "where results go (default REPO/.claude/hillclimb/dnstree-skill)")
	flag.StringVar(&o.variant, "variant", "baseline", "baseline, or vN")
	flag.StringVar(&o.model, "model", "claude-sonnet-5-5", "the model running the skill")
	flag.StringVar(&o.judge, "judge", "claude-opus-5-5", "the model grading the answers")
	flag.StringVar(&o.domain, "domain", "", "the domain holding the dnstree-eval TXT record; cases naming DOMAIN are skipped without it")
	flag.StringVar(&o.only, "only", "", "comma-separated case ids to run")
	flag.IntVar(&o.reps, "reps", 1, "runs per case")
	flag.IntVar(&o.workers, "workers", 4, "cases run at once")
	flag.DurationVar(&o.timeout, "timeout", 10*time.Minute, "wall-clock ceiling per case")
	flag.Float64Var(&o.budget, "budget", 1, "claude -p spend ceiling per case, in USD")
	flag.BoolVar(&o.approve, "approve-harness", false, "record the harness digest as reviewed, then exit")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		var exit exitError
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		os.Exit(1)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func run(o options) error {
	repo, err := filepath.Abs(o.repo)
	if err != nil {
		return err
	}
	if o.plugin == "" {
		o.plugin = filepath.Join(repo, "packaging", "plugin")
	}
	if o.flow == "" {
		o.flow = filepath.Join(repo, ".claude", "hillclimb", "dnstree-skill")
	}
	if !regexp.MustCompile(`^(baseline|v[0-9]+)$`).MatchString(o.variant) {
		return fmt.Errorf("variant %q: want baseline or vN", o.variant)
	}

	here, err := os.Getwd()
	if err != nil {
		return err
	}
	sha, err := harnessDigest(here)
	if err != nil {
		return err
	}
	state, err := readState(o.flow)
	if err != nil {
		return err
	}
	if o.approve {
		state["harness_sha"] = sha
		return writeState(o.flow, state)
	}
	if state["harness_sha"] != sha {
		fmt.Fprintln(os.Stderr, "eval: the runner or its cases changed since they were last reviewed; read the diff, then run with -approve-harness")
		return exitError(2)
	}

	if o.judge != "claude-opus-5-5" {
		return fmt.Errorf("-judge %s: judgeCost carries only claude-opus-5-5's rates", o.judge)
	}
	if o.dnstree == "" {
		return errors.New("-dnstree is required")
	}
	if o.dnstree, err = filepath.Abs(o.dnstree); err != nil {
		return err
	}
	// Without a binary that runs, every case falls back to dig and is graded
	// on something the skill never did.
	if out, err := exec.Command(o.dnstree, "--version").CombinedOutput(); err != nil {
		return fmt.Errorf("-dnstree %s does not run: %v %s", o.dnstree, err, strings.TrimSpace(string(out)))
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		return errors.New("ANTHROPIC_API_KEY is not set; the cases run with a HOME of their own, where no login is stored")
	}

	cases, err := loadCases(here, o)
	if err != nil {
		return err
	}

	dir := filepath.Join(o.flow, o.variant)
	if err := os.MkdirAll(filepath.Join(dir, "traces"), 0o755); err != nil {
		return err
	}
	done, err := finished(filepath.Join(dir, "results.jsonl"))
	if err != nil {
		return err
	}
	out, err := newWriter(dir)
	if err != nil {
		return err
	}
	defer out.close()

	type job struct {
		c   Case
		rep int
	}
	jobs := make(chan job)
	ctx := context.Background()
	judge := newJudge(o.judge)
	var wg sync.WaitGroup
	for range max(o.workers, 1) {
		wg.Go(func() {
			for j := range jobs {
				row, trace, failure := runCase(ctx, o, judge, j.c, j.rep)
				if failure != nil {
					out.fail(failure)
					fmt.Fprintf(os.Stderr, "✘ %s rep %d: %s: %s\n", j.c.ID, j.rep, failure.Class, failure.Error)
					continue
				}
				out.row(row, trace)
				fmt.Fprintf(os.Stderr, "%s %s rep %d  $%.3f  %.0fs\n", mark(row.Grade["pass"]), j.c.ID, j.rep, row.CostUSD, row.LatencyS)
			}
		})
	}
	for _, c := range cases {
		for rep := range o.reps {
			if !done[key(c.ID, rep)] {
				jobs <- job{c, rep}
			}
		}
	}
	close(jobs)
	wg.Wait()

	if err := summarise(filepath.Join(dir, "results.jsonl"), o.variant); err != nil {
		return err
	}
	// A run where cases could not be scored is not a result, whatever the
	// rest scored.
	if out.failed > 0 {
		return fmt.Errorf("%d attempts could not be scored; see errors.jsonl", out.failed)
	}
	return nil
}

func mark(pass int) string {
	if pass == 1 {
		return "✔"
	}
	return "✘"
}

func key(id string, rep int) string { return fmt.Sprintf("%s#%d", id, rep) }

func loadCases(here string, o options) ([]Case, error) {
	raw, err := os.ReadFile(filepath.Join(here, "cases.json"))
	if err != nil {
		return nil, err
	}
	var all []Case
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("cases.json: %w", err)
	}

	// cases.md is what was reviewed; a case missing from either side has not
	// been.
	doc, err := os.ReadFile(filepath.Join(here, "cases.md"))
	if err != nil {
		return nil, err
	}
	reviewed := map[string]bool{}
	for line := range strings.Lines(string(doc)) {
		if id, ok := strings.CutPrefix(strings.TrimSpace(line), "### "); ok {
			reviewed[id] = true
		}
	}

	wanted := map[string]bool{}
	for id := range strings.SplitSeq(o.only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			wanted[id] = true
		}
	}

	var picked []Case
	seen := map[string]bool{}
	for _, c := range all {
		if !reviewed[c.ID] {
			return nil, fmt.Errorf("case %s is not in cases.md", c.ID)
		}
		seen[c.ID] = true
		for _, p := range slices.Concat(c.Need, c.Forbid) {
			if _, err := regexp.Compile(p); err != nil {
				return nil, fmt.Errorf("case %s: %w", c.ID, err)
			}
		}
		if len(wanted) > 0 && !wanted[c.ID] {
			continue
		}
		if strings.Contains(c.Prompt, "DOMAIN") {
			if o.domain == "" {
				fmt.Fprintf(os.Stderr, "eval: skipping %s: no -domain\n", c.ID)
				continue
			}
			c.Prompt = strings.ReplaceAll(c.Prompt, "DOMAIN", o.domain)
		}
		if c.Dnstree == "" {
			c.Dnstree = "required"
		}
		picked = append(picked, c)
	}
	for id := range reviewed {
		if !seen[id] {
			return nil, fmt.Errorf("case %s is in cases.md but not cases.json", id)
		}
	}
	for id := range wanted {
		if !seen[id] {
			return nil, fmt.Errorf("-only names %s, which is not a case", id)
		}
	}
	if len(picked) == 0 {
		return nil, errors.New("no cases to run")
	}
	return picked, nil
}

// harnessDigest covers what decides a grade: the runner, its module and the
// cases. The skill under test is left out on purpose; changing it is what the
// eval is for.
func harnessDigest(here string) (string, error) {
	h := sha256.New()
	for _, name := range []string{"main.go", "claude.go", "grade.go", "go.mod", "go.sum", "cases.json", "cases.md"} {
		raw, err := os.ReadFile(filepath.Join(here, name))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %d\n", name, len(raw))
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readState(flow string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(flow, "_state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return defaultState(), nil
	}
	if err != nil {
		return nil, err
	}
	state := map[string]any{}
	return state, json.Unmarshal(raw, &state)
}

func defaultState() map[string]any {
	return map[string]any{
		"metrics": []map[string]any{
			{"id": "pass", "label": "pass", "kind": "binary"},
			{"id": "commands", "label": "commands", "kind": "binary"},
			{"id": "answer", "label": "answer", "kind": "binary"},
		},
		"perf_fields": []map[string]any{
			{"id": "cost_usd", "label": "cost", "unit": "$"},
			{"id": "latency_s", "label": "latency", "unit": "s"},
			{"id": "dnstree_runs", "label": "dnstree runs"},
			{"id": "refused", "label": "refused"},
			{"id": "truncated", "label": "truncated"},
		},
	}
}

func writeState(flow string, state map[string]any) error {
	if err := os.MkdirAll(flow, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(flow, "_state.json"), append(raw, '\n'), 0o644)
}

// Row is one line of results.jsonl.
type Row struct {
	PromptID    string         `json:"prompt_id"`
	Rep         int            `json:"rep"`
	Prompt      string         `json:"prompt"`
	Tags        []string       `json:"tags"`
	Model       string         `json:"model"`
	StopReason  string         `json:"stop_reason"`
	Status      string         `json:"status"`
	Grade       map[string]int `json:"grade"`
	CostUSD     float64        `json:"cost_usd"`
	LatencyS    float64        `json:"latency_s"`
	DnstreeRuns int            `json:"dnstree_runs"`
	Refused     int            `json:"refused"`
	Truncated   int            `json:"truncated"`
	Usage       map[string]any `json:"usage"`
	Meta        map[string]any `json:"meta"`
}

// Failure is one line of errors.jsonl: an attempt that produced nothing to
// score, kept apart so a rerun tries it again.
type Failure struct {
	PromptID string         `json:"prompt_id"`
	Rep      int            `json:"rep"`
	Class    string         `json:"class"`
	Error    string         `json:"error"`
	Model    string         `json:"model,omitempty"`
	CostUSD  float64        `json:"cost_usd,omitempty"`
	Usage    map[string]any `json:"usage,omitempty"`
	At       string         `json:"at"`
}

type writer struct {
	mu            sync.Mutex
	failed        int
	dir           string
	results, errs *os.File
}

func newWriter(dir string) (*writer, error) {
	results, err := os.OpenFile(filepath.Join(dir, "results.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	errs, err := os.OpenFile(filepath.Join(dir, "errors.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		results.Close()
		return nil, err
	}
	return &writer{dir: dir, results: results, errs: errs}, nil
}

func (w *writer) row(r *Row, trace []Turn) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// The trace goes first: a row whose trace is missing could not be audited.
	raw, _ := json.MarshalIndent(trace, "", "  ")
	name := filepath.Join(w.dir, "traces", fmt.Sprintf("%s_rep%d.json", r.PromptID, r.Rep))
	if err := os.WriteFile(name, raw, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		return
	}
	line, _ := json.Marshal(r)
	w.results.Write(append(line, '\n'))
}

func (w *writer) fail(f *Failure) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failed++
	f.At = time.Now().UTC().Format(time.RFC3339)
	line, _ := json.Marshal(f)
	w.errs.Write(append(line, '\n'))
}

func (w *writer) close() {
	w.results.Close()
	w.errs.Close()
}

func finished(path string) (map[string]bool, error) {
	done := map[string]bool{}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return done, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return done, eachRow(f, func(r Row) { done[key(r.PromptID, r.Rep)] = true })
}

func eachRow(r io.Reader, fn func(Row)) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 1<<20), 16<<20)
	for s.Scan() {
		if len(strings.TrimSpace(s.Text())) == 0 {
			continue
		}
		var row Row
		if err := json.Unmarshal(s.Bytes(), &row); err != nil {
			return err
		}
		fn(row)
	}
	return s.Err()
}

// summarise prints the headline with a Wilson interval, and writes it to the
// job summary when there is one.
func summarise(path, variant string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var n, pass, commands, answer int
	var cost float64
	var failed []string
	err = eachRow(f, func(r Row) {
		n++
		pass += r.Grade["pass"]
		commands += r.Grade["commands"]
		answer += r.Grade["answer"]
		cost += r.CostUSD
		if r.Grade["pass"] == 0 {
			failed = append(failed, r.PromptID)
		}
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no case was scored")
	}
	lo, hi := wilson(pass, n)
	slices.Sort(failed)
	text := fmt.Sprintf("%s: %d/%d pass (95%% CI %.0f–%.0f%%) · commands %d/%d · answer %d/%d · $%.2f\n",
		variant, pass, n, lo*100, hi*100, commands, n, answer, n, cost)
	if len(failed) > 0 {
		text += "failed: " + strings.Join(failed, ", ") + "\n"
	}
	fmt.Print(text)
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if s, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(s, "### dnstree skill eval\n\n%s", strings.ReplaceAll(text, "\n", "\n\n"))
			s.Close()
		}
	}
	return nil
}

func wilson(k, n int) (float64, float64) {
	const z = 1.96
	p, nf := float64(k)/float64(n), float64(n)
	mid := (p + z*z/(2*nf)) / (1 + z*z/nf)
	half := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf)) / (1 + z*z/nf)
	return max(0, mid-half), min(1, mid+half)
}
