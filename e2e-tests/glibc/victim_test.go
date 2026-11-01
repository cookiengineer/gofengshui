//go:build victim

package glibc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gofengshui/core"
	"gofengshui/e2e/internal/agentrun"
	"gofengshui/e2e/internal/checks"
)

func fixture(r *agentrun.Runner, name string) string {
	return filepath.Join(r.Testdata, name)
}

func runFind(t *testing.T, r *agentrun.Runner, name, fixtureName, id string, extra ...string) *agentrun.Result {
	t.Helper()
	args := append([]string{}, extra...)
	args = append(args, "--expect-findings", id)
	res := r.Run(t, name, agentrun.Options{
		Args:         args,
		Target:       []string{fixture(r, fixtureName)},
		Timeout:      30 * time.Second,
		AllowFailure: true,
	})
	res.RequireSuccess(t)
	return res
}

func runClean(t *testing.T, r *agentrun.Runner, name, fixtureName string, extra ...string) *agentrun.Result {
	t.Helper()
	args := append([]string{}, extra...)
	args = append(args, "--expect-no-findings")
	res := r.Run(t, name, agentrun.Options{
		Args:         args,
		Target:       []string{fixture(r, fixtureName)},
		Timeout:      30 * time.Second,
		AllowFailure: true,
	})
	res.RequireSuccess(t)
	return res
}

func requireFinding(t *testing.T, res *agentrun.Result, id string) core.Finding {
	t.Helper()
	return checks.RequireFinding(t, checks.LoadFrames(t, res.EventsPath), id)
}

func requireFindingMessage(t *testing.T, res *agentrun.Result, id, needle string) core.Finding {
	t.Helper()
	for _, f := range checks.Findings(checks.LoadFrames(t, res.EventsPath)) {
		if f.ID == id && strings.Contains(f.Message, needle) {
			return f
		}
	}
	t.Fatalf("finding %s with %q missing", id, needle)
	return core.Finding{}
}

func TestGlibcDetectors(t *testing.T) {
	r := agentrun.NewRunner(t)

	t.Run("double_free", func(t *testing.T) {
		res := runFind(t, r, "double_free", "double_free", "D1")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "**D1**", "double-free report")
	})

	t.Run("uaf", func(t *testing.T) {
		res := runFind(t, r, "uaf", "uaf", "D2")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "use-after-free", "UAF report")
	})

	t.Run("syscall_uaf", func(t *testing.T) {
		res := runFind(t, r, "syscall_uaf", "syscall_uaf", "D2")
		seen := make(map[uint64]bool)
		for _, f := range checks.Findings(checks.LoadFrames(t, res.EventsPath)) {
			if f.ID == "D2" && f.Event != nil {
				seen[f.Event.Arg1] = true
			}
		}
		for _, nr := range []uint64{257, 59, 40, 275} {
			if !seen[nr] {
				t.Fatalf("D2 syscall %d missing; got %v", nr, seen)
			}
		}
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "use-after-free", "syscall UAF report")
	})

	t.Run("uaf_direct", func(t *testing.T) {
		res := runFind(t, r, "uaf_direct", "uaf_direct", "D2", "--watch-freed")
		f := requireFinding(t, res, "D2")
		if got := fmt.Sprint(f.Details["source"]); got != "hardware-watchpoint" {
			t.Fatalf("D2 source: got %q want hardware-watchpoint", got)
		}
	})

	t.Run("overflow", func(t *testing.T) {
		res := runFind(t, r, "overflow", "overflow", "D3")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "heap overflow", "overflow report")
	})

	t.Run("poison", func(t *testing.T) {
		res := runFind(t, r, "poison", "poison", "D7")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "tcache", "tcache report")
		report := res.Heap(t)
		if report.Profile.Source != "libc-string" {
			t.Fatalf("profile source: got %q want libc-string", report.Profile.Source)
		}
		if !report.Profile.Tcache {
			t.Fatal("detected profile does not enable tcache")
		}
	})

	t.Run("metadata", func(t *testing.T) {
		res := runFind(t, r, "metadata", "metadata", "D8")
		requireFindingMessage(t, res, "D8", "invalid chunk size")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "**D8**", "D8 report")
	})

	t.Run("size_swap", func(t *testing.T) {
		res := runFind(t, r, "size_swap", "size_swap", "D9")
		requireFindingMessage(t, res, "D9", "chunk size changed while allocated")
	})

	t.Run("alloc_fail", func(t *testing.T) {
		res := runFind(t, r, "alloc_fail", "alloc_fail", "D4")
		requireFindingMessage(t, res, "D4", "allocation failed: request=18446744073709551615")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "mmap/mremap failed: errno=", "mmap failure report")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "**D4**", "D4 report")
	})

	t.Run("crash", func(t *testing.T) {
		res := runFind(t, r, "crash", "crash", "D6")
		f := requireFinding(t, res, "D6")
		if got := fmt.Sprint(f.Details["fault_region"]); got != "null" {
			t.Fatalf("fault_region: got %q want null", got)
		}
		if got := fmt.Sprint(f.Details["fault_access"]); got != "not-mapped" {
			t.Fatalf("fault_access: got %q want not-mapped", got)
		}
		if f.Details["stack_hits"] == nil {
			t.Fatal("D6 stack_hits missing")
		}
		checks.RequireTextContains(t, res.EventsPath, "signal 11 at RIP", "crash events")
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "**D6**", "D6 report")
	})

	t.Run("clean", func(t *testing.T) {
		res := runClean(t, r, "clean", "alloc_loop", "--sample-stacks", "4")
		checks.RequireNoFindings(t, checks.LoadFrames(t, res.EventsPath))
		checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "No findings recorded", "clean report")
		report := res.Heap(t)
		if len(report.Analysis.SizeClasses) == 0 {
			t.Fatal("heap analysis has no size classes")
		}
	})

	t.Run("realloc_churn", func(t *testing.T) {
		res := runClean(t, r, "realloc", "realloc_churn")
		checks.RequireNoFindings(t, checks.LoadFrames(t, res.EventsPath))
		report := res.Heap(t)
		if len(report.Analysis.SizeClasses) == 0 {
			t.Fatal("heap analysis has no size classes")
		}
	})

	t.Run("cxx_labels", func(t *testing.T) {
		res := runClean(t, r, "cxx", "cxx_alloc")
		frames := checks.LoadFrames(t, res.EventsPath)
		if !hasEvent(frames, core.EventAlloc, 2, 6) {
			t.Fatal("C++ new allocation label missing")
		}
		if !hasEvent(frames, core.EventFree, 1, 7) {
			t.Fatal("C++ delete label missing")
		}
	})
}

func TestGlibcAnomaly(t *testing.T) {
	r := agentrun.NewRunner(t)

	res := runFind(t, r, "anomaly", "anomaly_groom", "D10",
		"--anomaly",
		"--anomaly-warmup", "4",
		"--anomaly-window-events", "64",
		"--content-sample",
		"--content-sample-ms", "50",
		"--content-sample-chunks", "16",
	)
	checks.RequireFinding(t, checks.LoadFrames(t, res.EventsPath), "D10")
	for _, name := range []string{"timeline.jsonl", "anomalies.json", "baseline-model.json"} {
		if _, err := os.Stat(filepath.Join(res.ReportDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	checks.RequireBaselineContent(t, filepath.Join(res.ReportDir, "baseline-model.json"))
}

func anomalyMatrixConfigDefault() anomalyMatrixConfig {
	return anomalyMatrixConfig{
		Warmup:          8,
		WindowEvents:    256,
		WindowMS:        250,
		ContentSample:   true,
		ContentSampleMS: 250,
		ContentChunks:   16,
	}
}

func (c anomalyMatrixConfig) args() []string {
	args := []string{
		"--anomaly",
		"--anomaly-warmup", strconv.Itoa(c.Warmup),
		"--anomaly-window-events", strconv.Itoa(c.WindowEvents),
		"--anomaly-window-ms", strconv.Itoa(c.WindowMS),
	}
	if c.ContentSample {
		args = append(args,
			"--content-sample",
			"--content-sample-ms", strconv.Itoa(c.ContentSampleMS),
			"--content-sample-chunks", strconv.Itoa(c.ContentChunks),
		)
	}
	return args
}

func summarizeAnomalyMatrix(runs []anomalyRun) anomalyMatrixSummary {
	var summary anomalyMatrixSummary
	for _, run := range runs {
		if run.Scorable {
			summary.Scorable++
			if run.D10 > 0 || run.D11 > 0 {
				summary.FalsePositive++
			}
		}
		if run.D10 > 0 || run.D11 > 0 {
			summary.Detected++
		}
	}
	if summary.Scorable > 0 {
		summary.FPR = float64(summary.FalsePositive) / float64(summary.Scorable)
	}
	return summary
}

func medianInt64(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func parseBenchOutput(path string) (int64, uint64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	var elapsed int64
	var iterations uint64
	_, _ = fmt.Sscanf(string(data), "elapsed_ms=%d iterations=%d", &elapsed, &iterations)
	return elapsed, iterations
}

func TestGlibcAnomalyMatrix(t *testing.T) {
	r := agentrun.NewRunner(t)
	cfg := anomalyMatrixConfigDefault()

	t.Run("benign", func(t *testing.T) {
		_ = os.Remove(anomalyMarkerPath)
		cases := []struct {
			name    string
			fixture string
			mode    string
		}{
			{name: "benign-steady", fixture: "anomaly_benign", mode: "steady"},
			{name: "benign-churn", fixture: "anomaly_benign", mode: "churn"},
			{name: "benign-threads", fixture: "anomaly_benign", mode: "threads"},
			{name: "benign-realloc", fixture: "anomaly_benign", mode: "realloc"},
			{name: "benign-burst", fixture: "anomaly_benign", mode: "burst"},
			{name: "alloc_loop", fixture: "alloc_loop"},
			{name: "realloc_churn", fixture: "realloc_churn"},
			{name: "threads", fixture: "threads"},
			{name: "attach_threads", fixture: "attach_threads"},
			{name: "arena_backfill", fixture: "arena_backfill"},
			{name: "dlopen_alloc", fixture: "dlopen_alloc"},
			{name: "cxx_alloc", fixture: "cxx_alloc"},
		}
		runs := make([]anomalyRun, 0, len(cases))
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				target := []string{fixture(r, c.fixture)}
				if c.mode != "" {
					target = append(target, c.mode)
				}
				res := r.Run(t, "anomaly-"+c.name, agentrun.Options{
					Args:         cfg.args(),
					Target:       target,
					Timeout:      120 * time.Second,
					AllowFailure: true,
				})
				run := summarizeAnomalyRun(t, "benign", c.fixture, c.mode, res, "")
				t.Logf("benign %s: scorable=%v windows=%d scored=%d d10=%d d11=%d max=%.2f",
					c.name, run.Scorable, run.Windows, run.Scored, run.D10, run.D11, run.MaxScore)
				runs = append(runs, run)
			})
		}
		matrix := anomalyMatrix{
			Generated: time.Now(),
			Config:    cfg,
			Runs:      runs,
			Summary:   summarizeAnomalyMatrix(runs),
		}
		writeMatrix(t, filepath.Join(r.Reports, anomalyBenignFile), matrix)
		t.Logf("benign FPR: %d/%d (%.3f)", matrix.Summary.FalsePositive, matrix.Summary.Scorable, matrix.Summary.FPR)
	})

	t.Run("exploit", func(t *testing.T) {
		cases := []struct {
			name       string
			mode       string
			structural string
			extra      []string
		}{
			{name: "groom", mode: "groom"},
			{name: "poison", mode: "poison", structural: "D7"},
			{name: "metadata", mode: "metadata", structural: "D8"},
			{name: "size_swap", mode: "size_swap", structural: "D9"},
			{name: "double_free", mode: "double_free", structural: "D1"},
			{name: "crash", mode: "crash", structural: "D6"},
			{name: "control", mode: "control", structural: "D6"},
		}
		runs := make([]anomalyRun, 0, len(cases))
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				_ = os.Remove(anomalyMarkerPath)
				args := append(cfg.args(), c.extra...)
				if c.structural != "" {
					args = append(args, "--expect-findings", c.structural)
				}
				res := r.Run(t, "anomaly-exploit-"+c.name, agentrun.Options{
					Args:         args,
					Target:       []string{fixture(r, "anomaly_exploit"), c.mode},
					Timeout:      120 * time.Second,
					AllowFailure: true,
				})
				run := summarizeAnomalyRun(t, "exploit", "anomaly_exploit", c.mode, res, c.structural)
				t.Logf("exploit %s: exit=%d scorable=%v windows=%d d10=%d d11=%d measured=%v latency=%d windows/%d ms",
					c.name, run.ExitCode, run.Scorable, run.Windows, run.D10, run.D11,
					run.LatencyMeasured, run.LatencyWindows, run.LatencyMS)
				runs = append(runs, run)
			})
		}
		summary := anomalyMatrixSummary{}
		for _, run := range runs {
			if run.D10 > 0 || run.D11 > 0 {
				summary.Detected++
			}
		}
		matrix := anomalyMatrix{
			Generated: time.Now(),
			Config:    cfg,
			Runs:      runs,
			Summary:   summary,
		}
		writeMatrix(t, filepath.Join(r.Reports, anomalyExploitFile), matrix)
	})

	t.Run("overhead", func(t *testing.T) {
		scoringCfg := cfg
		scoringCfg.ContentSample = false
		profiles := []struct {
			name string
			args []string
		}{
			{name: "collector"},
			{name: "scoring", args: scoringCfg.args()},
			{name: "content", args: cfg.args()},
		}
		report := anomalyOverheadReport{
			Generated: time.Now(),
			Medians:   make(map[string]int64, len(profiles)),
		}
		for _, profile := range profiles {
			var durations []int64
			for i := 0; i < 3; i++ {
				name := fmt.Sprintf("anomaly-overhead-%s-%d", profile.name, i)
				res := r.Run(t, name, agentrun.Options{
					Args:         profile.args,
					Target:       []string{fixture(r, "anomaly_bench")},
					Timeout:      120 * time.Second,
					AllowFailure: true,
				})
				elapsed, iterations := parseBenchOutput(filepath.Join(res.ReportDir, "target.stdout"))
				sample := anomalyOverheadSample{
					Profile:         profile.name,
					DurationMS:      res.Duration.Milliseconds(),
					TargetElapsedMS: elapsed,
					Iterations:      iterations,
				}
				report.Runs = append(report.Runs, sample)
				durations = append(durations, sample.DurationMS)
			}
			report.Medians[profile.name] = medianInt64(durations)
			t.Logf("overhead %s median=%d ms", profile.name, report.Medians[profile.name])
		}
		writeMatrix(t, filepath.Join(r.Reports, anomalyOverheadFile), report)
	})
}

func TestGlibcProfiles(t *testing.T) {
	r := agentrun.NewRunner(t)

	t.Run("override", func(t *testing.T) {
		res := runClean(t, r, "profile-override", "alloc_once", "--glibc-version", "2.31")
		report := res.Heap(t)
		checks.RequireProfileVersion(t, report, "2.31")
		checks.RequireProfileSource(t, report, "override")
		if report.Profile.SafeLinking {
			t.Fatal("2.31 override should disable safe-linking")
		}
		if !report.Profile.Tcache {
			t.Fatal("2.31 override should enable tcache")
		}
	})
}

func TestGlibcConcurrency(t *testing.T) {
	r := agentrun.NewRunner(t)

	t.Run("threads", func(t *testing.T) {
		res := runClean(t, r, "threads", "threads", "--follow")
		frames := checks.LoadFrames(t, res.EventsPath)
		if n := uniqueAllocField(frames, "tid"); n < 2 {
			t.Fatalf("allocator events from %d thread(s), want at least 2", n)
		}
		report := res.Heap(t)
		if len(report.Analysis.SizeClasses) == 0 {
			t.Fatal("heap analysis has no size classes")
		}
	})

	t.Run("fork_exec", func(t *testing.T) {
		res := runClean(t, r, "fork_exec", "fork_exec", "--follow")
		frames := checks.LoadFrames(t, res.EventsPath)
		if n := uniqueAllocField(frames, "pid"); n < 2 {
			t.Fatalf("allocator events from %d process(es), want at least 2", n)
		}
	})

	t.Run("attach", func(t *testing.T) {
		p := r.StartTarget(t, "attach-target", []string{fixture(r, "attach_threads")}, agentrun.Options{Timeout: 30 * time.Second})
		time.Sleep(100 * time.Millisecond)
		res := r.Attach(t, "attach", agentrun.Options{
			Args:         []string{"--pid", strconv.Itoa(p.PID), "--expect-no-findings"},
			Timeout:      30 * time.Second,
			AllowFailure: true,
		})
		res.RequireSuccess(t)
		p.Wait(t, 30*time.Second)
		frames := checks.LoadFrames(t, res.EventsPath)
		if n := uniqueAllocField(frames, "tid"); n < 2 {
			t.Fatalf("attach captured %d thread(s), want at least 2", n)
		}
	})

	t.Run("backfill", func(t *testing.T) {
		_ = os.Remove("/tmp/backfill.addrs")
		p := r.StartTarget(t, "backfill-target", []string{fixture(r, "backfill")}, agentrun.Options{Timeout: 30 * time.Second})
		checks.WaitForFile(t, "/tmp/backfill.addrs", 10*time.Second)
		res := r.Attach(t, "backfill", agentrun.Options{
			Args:         []string{"--pid", strconv.Itoa(p.PID), "--backfill", "--expect-no-findings"},
			Timeout:      30 * time.Second,
			AllowFailure: true,
		})
		res.RequireSuccess(t)
		p.Wait(t, 30*time.Second)
		addrs := readAddresses(t, "/tmp/backfill.addrs")
		report := res.Heap(t)
		for _, addr := range addrs {
			if !hasAllocation(report, addr) {
				t.Fatalf("backfill missing allocation %#x", addr)
			}
		}
		if report.Backfill == nil {
			t.Fatal("backfill stats missing")
		}
	})

	t.Run("arena_backfill", func(t *testing.T) {
		matches, _ := filepath.Glob("/tmp/arena_backfill.*.addrs")
		for _, path := range matches {
			_ = os.Remove(path)
		}
		p := r.StartTarget(t, "arena-target", []string{fixture(r, "arena_backfill")}, agentrun.Options{Timeout: 30 * time.Second})
		checks.Eventually(t, 10*time.Second, 25*time.Millisecond, func() bool {
			files, _ := filepath.Glob("/tmp/arena_backfill.*.addrs")
			return len(files) >= 2
		}, "thread arena address files")
		res := r.Attach(t, "arena_backfill", agentrun.Options{
			Args:         []string{"--pid", strconv.Itoa(p.PID), "--backfill", "--expect-no-findings"},
			Timeout:      30 * time.Second,
			AllowFailure: true,
		})
		res.RequireSuccess(t)
		p.Wait(t, 30*time.Second)
		report := res.Heap(t)
		files, _ := filepath.Glob("/tmp/arena_backfill.*.addrs")
		for _, path := range files {
			for _, addr := range readAddresses(t, path) {
				if !hasAllocation(report, addr) {
					t.Fatalf("arena backfill missing allocation %#x", addr)
				}
			}
		}
		if report.Backfill == nil || report.Backfill.Arenas < 1 {
			t.Fatalf("arena backfill count: %+v", report.Backfill)
		}
	})
}

func TestGlibcProtocol(t *testing.T) {
	r := agentrun.NewRunner(t)

	t.Run("stdio", func(t *testing.T) {
		requests := []checks.Request{
			{Version: 1, Type: "request", ID: 1, Method: "events.subscribe", Params: map[string]any{"since": 0}},
			{Version: 1, Type: "request", ID: 2, Method: "resume", Params: map[string]any{}},
			{Version: 1, Type: "request", ID: 3, Method: "wait", Params: map[string]any{"type": "finding", "id": "D2", "timeout_ms": 10000}},
			{Version: 1, Type: "request", ID: 4, Method: "assert", Params: map[string]any{"assertions": []map[string]any{{"type": "finding", "id": "D2", "min_count": 1}}}},
			{Version: 1, Type: "request", ID: 5, Method: "session.status", Params: map[string]any{}},
			{Version: 1, Type: "request", ID: 6, Method: "heap.baseline", Params: map[string]any{"name": "check"}},
			{Version: 1, Type: "request", ID: 7, Method: "heap.diff", Params: map[string]any{"name": "check"}},
			{Version: 1, Type: "request", ID: 8, Method: "heap.recipe", Params: map[string]any{"size": 64, "count": 4}},
		}
		res := r.StdioRequests(t, "stdio", requests, agentrun.Options{
			Args:         []string{"--jsonl", "--pause"},
			Target:       []string{fixture(r, "uaf")},
			Timeout:      30 * time.Second,
			AllowFailure: true,
		})
		res.RequireSuccess(t)
		frames := checks.LoadFrames(t, res.EventsPath)
		checks.RequireFinding(t, frames, "D2")
		checks.RequireResult(t, frames, 3)
		assertResult := checks.RequireResult(t, frames, 4)
		var assertResultValue struct {
			OK bool `json:"ok"`
		}
		checks.DecodeResult(t, assertResult, &assertResultValue)
		if !assertResultValue.OK {
			t.Fatal("assert result ok=false")
		}
		status := checks.RequireResult(t, frames, 5)
		var statusValue struct {
			Profile map[string]any `json:"profile"`
			BPF     map[string]any `json:"bpf"`
		}
		checks.DecodeResult(t, status, &statusValue)
		if statusValue.Profile == nil {
			t.Fatal("session.status missing profile")
		}
		if statusValue.BPF == nil {
			t.Fatal("session.status missing bpf stats")
		}
		if drops, ok := statusValue.BPF["drops"].(float64); !ok || drops != 0 {
			t.Fatalf("unexpected ringbuf drops: %v", statusValue.BPF["drops"])
		}
		diff := checks.RequireResult(t, frames, 7)
		if !strings.Contains(string(diff.Result), "live_delta") {
			t.Fatalf("heap.diff missing live_delta: %s", diff.Result)
		}
		recipe := checks.RequireResult(t, frames, 8)
		if !strings.Contains(string(recipe.Result), "reclaim") {
			t.Fatalf("heap.recipe missing reclaim: %s", recipe.Result)
		}
	})

	t.Run("unix_socket", func(t *testing.T) {
		socket := filepath.Join(r.Temp, "agent.sock")
		_ = os.Remove(socket)
		p := r.StartAgent(t, "agent", socket, agentrun.Options{Timeout: 60 * time.Second})
		checks.WaitForSocket(t, socket, 10*time.Second)
		client := agentrun.Dial(t, socket, 10*time.Second)
		create := client.Call(t, "session.create", map[string]any{
			"mode": "spawn",
			"path": fixture(r, "uaf"),
			"args": []string{fixture(r, "uaf")},
		}, "", 20*time.Second)
		var created struct {
			Session string `json:"session"`
		}
		checks.DecodeResult(t, create, &created)
		if created.Session == "" {
			t.Fatal("session.create returned no session")
		}
		client.Send(t, "events.subscribe", map[string]any{"since": 0}, created.Session)
		frame := client.WaitFor(t, "D2 event", 20*time.Second, func(f checks.Frame) bool {
			return f.Event != nil && f.Event.Finding != nil && f.Event.Finding.ID == "D2"
		})
		agentrun.RequireEventFinding(t, frame, "D2")
		client.Call(t, "session.close", map[string]any{"kill": true}, created.Session, 10*time.Second)
		p.Kill()
	})

	t.Run("dlopen_refresh", func(t *testing.T) {
		socket := filepath.Join(r.Temp, "dlopen.sock")
		ready := "/tmp/dlopen_alloc.ready"
		release := "/tmp/dlopen_alloc.release"
		pointer := "/tmp/dlopen_alloc.ptr"
		for _, path := range []string{socket, ready, release, pointer} {
			_ = os.Remove(path)
		}
		t.Cleanup(func() {
			for _, path := range []string{socket, ready, release, pointer} {
				_ = os.Remove(path)
			}
		})
		p := r.StartAgent(t, "agent-dlopen", socket, agentrun.Options{Timeout: 60 * time.Second})
		checks.WaitForSocket(t, socket, 10*time.Second)
		client := agentrun.Dial(t, socket, 10*time.Second)
		create := client.Call(t, "session.create", map[string]any{
			"mode":  "spawn",
			"path":  fixture(r, "dlopen_alloc"),
			"args":  []string{fixture(r, "dlopen_alloc")},
			"pause": true,
		}, "", 20*time.Second)
		var created struct {
			Session string `json:"session"`
		}
		checks.DecodeResult(t, create, &created)
		if created.Session == "" {
			t.Fatal("session.create returned no session")
		}
		client.Call(t, "resume", map[string]any{}, created.Session, 10*time.Second)
		checks.WaitForFile(t, ready, 10*time.Second)
		refresh := client.Call(t, "maps.refresh", map[string]any{}, created.Session, 20*time.Second)
		_ = os.WriteFile(filepath.Join(r.Reports, "dlopen-refresh.json"), refresh.Result, 0o644)
		if !strings.Contains(string(refresh.Result), "libgfsplugin.so") {
			t.Fatalf("dlopen module missing from refresh: %s", refresh.Result)
		}
		if !strings.Contains(string(refresh.Result), "allocator_paths") {
			t.Fatalf("allocator paths missing from refresh: %s", refresh.Result)
		}
		if err := os.WriteFile(release, []byte("release\n"), 0o644); err != nil {
			t.Fatalf("write release file: %v", err)
		}
		checks.WaitForFile(t, pointer, 10*time.Second)
		data := checks.RequireFile(t, pointer)
		addr, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			t.Fatalf("parse dlopen pointer: %v", err)
		}
		query := client.Call(t, "heap.query", map[string]any{"addr": addr}, created.Session, 20*time.Second)
		var allocation struct {
			Addr uint64 `json:"addr"`
		}
		checks.DecodeResult(t, query, &allocation)
		if allocation.Addr != addr {
			t.Fatalf("heap.query addr: got %#x want %#x", allocation.Addr, addr)
		}
		client.Call(t, "session.close", map[string]any{"kill": true}, created.Session, 10*time.Second)
		p.Kill()
	})
}

func TestGlibcROP(t *testing.T) {
	r := agentrun.NewRunner(t)

	run := func(t *testing.T, name string, extra []string) {
		args := append([]string{
			"--expect-regs", "rdi=0x4141",
			"--sink", "gfs_sink",
			"--start", "gfs_pop_rdi_ret",
		}, extra...)
		res := r.Validate(t, name, agentrun.Options{
			Args:         args,
			Target:       []string{fixture(r, "rop_sink")},
			Timeout:      30 * time.Second,
			AllowFailure: true,
		})
		res.RequireSuccess(t)
		var result struct {
			Verified bool `json:"verified"`
			Sink     *struct {
				Regs map[string]uint64 `json:"regs"`
			} `json:"sink"`
		}
		if err := json.Unmarshal(res.Stdout, &result); err != nil {
			t.Fatalf("decode ROP result: %v\n%s", err, res.Stdout)
		}
		if !result.Verified {
			t.Fatal("ROP chain not verified")
		}
		if result.Sink == nil || result.Sink.Regs["rdi"] != 0x4141 {
			t.Fatalf("unexpected sink registers: %+v", result.Sink)
		}
	}

	t.Run("arm", func(t *testing.T) { run(t, "rop", nil) })
	t.Run("hijack", func(t *testing.T) {
		run(t, "rop-hijack", []string{"--hijack", "--hijack-func", "gfs_vuln"})
	})
}

func TestGlibcOOM(t *testing.T) {
	r := agentrun.NewRunner(t)
	dir := r.ReportDir("oom")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create oom report dir: %v", err)
	}
	agent := r.StartProcess(t, "oom-agent", []string{
		r.Bin, "run", "--oom",
		"--report", dir,
		"--stdout", filepath.Join(dir, "target.stdout"),
		"--stderr", filepath.Join(dir, "target.stderr"),
		"--expect-findings", "D4",
		"--", "/bin/sleep", "8",
	}, agentrun.Options{Timeout: 45 * time.Second})
	checks.WaitForText(t, agent.StderrPath, "gofengshui: session", 10*time.Second)
	victim := r.Program(t, "oom-victim", []string{fixture(r, "oom")}, agentrun.Options{
		Timeout:      30 * time.Second,
		AllowFailure: true,
	})
	t.Logf("OOM victim exit=%d", victim.ExitCode)
	agent.Wait(t, 40*time.Second)
	data := checks.RequireFile(t, agent.StdoutPath)
	_ = os.WriteFile(r.EventsPath("oom"), data, 0o644)
	frames := checks.LoadFrames(t, agent.StdoutPath)
	checks.RequireFinding(t, frames, "D4")
	found := false
	for _, f := range checks.Findings(frames) {
		if f.ID == "D4" && strings.Contains(f.Message, "kernel OOM kill") {
			found = true
		}
	}
	if !found {
		t.Fatal("kernel OOM finding missing")
	}
}

func hasEvent(frames []checks.Frame, typ core.EventType, field int, want uint64) bool {
	for _, f := range frames {
		if f.Event == nil || f.Event.Event == nil {
			continue
		}
		ev := f.Event.Event
		if ev.Type != typ {
			continue
		}
		value := ev.Arg1
		if field == 2 {
			value = ev.Arg2
		}
		if value == want {
			return true
		}
	}
	return false
}

func uniqueAllocField(frames []checks.Frame, field string) int {
	seen := make(map[uint64]bool)
	for _, f := range frames {
		if f.Event == nil || f.Event.Event == nil || f.Event.Event.Type != core.EventAlloc {
			continue
		}
		ev := f.Event.Event
		if field == "tid" {
			seen[uint64(ev.TID)] = true
		} else {
			seen[uint64(ev.PID)] = true
		}
	}
	return len(seen)
}

func readAddresses(t *testing.T, path string) []uint64 {
	t.Helper()
	data := checks.RequireFile(t, path)
	var out []uint64
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		value, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			t.Fatalf("parse address %q: %v", line, err)
		}
		out = append(out, value)
	}
	return out
}

func hasAllocation(report checks.HeapReport, addr uint64) bool {
	for _, allocation := range report.Allocations {
		if allocation.Addr == addr {
			return true
		}
	}
	return false
}
