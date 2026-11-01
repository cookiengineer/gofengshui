//go:build !victim

package glibc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gofengshui/core"
	"gofengshui/e2e/internal/checks"
	"gofengshui/e2e/internal/harness"
)

var agentOnce sync.Once

type caseSpec struct {
	name              string
	variant           string
	baseImage         string
	safeLinking       bool
	victimArgs        []string
	skipIfBaseMissing bool
	verify            func(*testing.T, string)
}

func ensureAgent(t *testing.T, c *harness.Case) {
	t.Helper()
	agentOnce.Do(c.BuildAgent)
}

func TestGlibc(t *testing.T) {
	harness.RequireRoot(t)
	run := harness.NewRun(t)
	runCase(t, run, caseSpec{
		name:      "glibc",
		variant:   "ubuntu-24.04",
		baseImage: "ubuntu:24.04",
		verify: func(t *testing.T, reports string) {
			verifyGlibcReports(t, reports, true)
		},
	})
}

func TestGlibcAnomaly(t *testing.T) {
	harness.RequireRoot(t)
	run := harness.NewRun(t)
	runCase(t, run, caseSpec{
		name:       "glibc-anomaly",
		variant:    "ubuntu-24.04",
		baseImage:  "ubuntu:24.04",
		victimArgs: []string{"-test.run", "^TestGlibcAnomaly$"},
		verify:     verifyGlibcAnomaly,
	})
}

func verifyGlibcAnomaly(t *testing.T, reports string) {
	t.Helper()
	frames := checks.LoadFrames(t, filepath.Join(reports, "anomaly.events.jsonl"))
	checks.RequireFinding(t, frames, "D10")
	checks.RequireTextContains(t, filepath.Join(reports, "anomaly", "report.md"), "**D10**", "D10 report")
	for _, name := range []string{"timeline.jsonl", "anomalies.json", "baseline-model.json"} {
		if _, err := os.Stat(filepath.Join(reports, "anomaly", name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	checks.RequireBaselineContent(t, filepath.Join(reports, "anomaly", "baseline-model.json"))
}

func TestGlibcAnomalyMatrix(t *testing.T) {
	harness.RequireRoot(t)
	run := harness.NewRun(t)
	runCase(t, run, caseSpec{
		name:       "glibc-anomaly-matrix",
		variant:    "ubuntu-24.04",
		baseImage:  "ubuntu:24.04",
		victimArgs: []string{"-test.run", "^TestGlibcAnomalyMatrix$"},
		verify:     verifyGlibcAnomalyMatrix,
	})
}

func verifyGlibcAnomalyMatrix(t *testing.T, reports string) {
	t.Helper()

	var benign anomalyMatrix
	readMatrix(t, filepath.Join(reports, anomalyBenignFile), &benign)
	if benign.Summary.Scorable < 4 {
		t.Fatalf("benign matrix has only %d scorable runs, want at least 4", benign.Summary.Scorable)
	}
	if benign.Summary.FalsePositive != 0 {
		for _, run := range benign.Runs {
			if run.Scorable && (run.D10 > 0 || run.D11 > 0) {
				t.Logf("false positive: fixture=%s mode=%s d10=%d d11=%d max_score=%.2f findings=%v",
					run.Fixture, run.Mode, run.D10, run.D11, run.MaxScore, run.Findings)
			}
		}
		t.Fatalf("benign false-positive rate: %d/%d (%.3f)",
			benign.Summary.FalsePositive, benign.Summary.Scorable, benign.Summary.FPR)
	}

	var exploit anomalyMatrix
	readMatrix(t, filepath.Join(reports, anomalyExploitFile), &exploit)
	groomDetected := false
	for _, run := range exploit.Runs {
		t.Logf("exploit %s: scorable=%v windows=%d d10=%d d11=%d latency_measured=%v latency=%dw/%dms max_score=%.2f",
			run.Mode, run.Scorable, run.Windows, run.D10, run.D11, run.LatencyMeasured,
			run.LatencyWindows, run.LatencyMS, run.MaxScore)
		if run.ExpectedStructural != "" && run.ExitCode != 0 {
			t.Fatalf("exploit %s did not emit %s (exit %d)", run.Mode, run.ExpectedStructural, run.ExitCode)
		}
		if run.Mode == "groom" && run.D10 > 0 {
			groomDetected = true
		}
	}
	if !groomDetected {
		t.Fatal("groom positive control did not emit D10")
	}

	var overhead anomalyOverheadReport
	readMatrix(t, filepath.Join(reports, anomalyOverheadFile), &overhead)
	if len(overhead.Medians) == 0 {
		t.Fatal("overhead matrix is empty")
	}
	t.Logf("overhead medians: %v", overhead.Medians)
}

func TestGlibcMatrix(t *testing.T) {
	harness.RequireRoot(t)
	if !harness.EnvBool("GFS_E2E_GLIBC_MATRIX") {
		t.Skip("set GFS_E2E_GLIBC_MATRIX=1 to run the old-glibc matrix (pulls debian:11-slim and debian:12-slim)")
	}
	run := harness.NewRun(t)
	cases := []caseSpec{
		{name: "glibc-debian-11", variant: "debian-11", baseImage: "debian:11-slim", safeLinking: false},
		{name: "glibc-debian-12", variant: "debian-12", baseImage: "debian:12-slim", safeLinking: true},
	}
	for _, spec := range cases {
		spec := spec
		spec.skipIfBaseMissing = true
		spec.verify = func(t *testing.T, reports string) {
			verifyGlibcReports(t, reports, spec.safeLinking)
		}
		t.Run(spec.name, func(t *testing.T) {
			runCase(t, run, spec)
		})
	}
}

func runCase(t *testing.T, run *harness.Run, spec caseSpec) {
	t.Helper()
	c := run.NewCaseFor(t, spec.name)
	c.Preflight()
	if spec.skipIfBaseMissing {
		c.RequireBaseImage(t, spec.baseImage)
	}
	ensureAgent(t, c)
	tag := harness.ImageTag("glibc", spec.variant)
	containerfile := filepath.Join(run.Root, "e2e-tests", "glibc", "Containerfile")
	image := c.BuildImage(tag, containerfile, map[string]string{"BASE_IMAGE": spec.baseImage})
	victim := c.BuildVictimTest("./glibc", "glibc.victim.test")
	container := c.StartContainer(t, harness.ContainerOptions{Image: image})
	container.CopyTo(victim, "/opt/gfs/e2e/gofengshui")

	t.Run("victim", func(t *testing.T) {
		args := []string{"-test.v", "-test.timeout=15m"}
		args = append(args, spec.victimArgs...)
		execArgs := append([]string{"/opt/gfs/e2e/gofengshui"}, args...)
		res := container.Exec("victim-tests", harness.ExecOptions{
			Timeout:      20 * time.Minute,
			AllowFailure: true,
		}, execArgs...)
		if res.ExitCode != 0 {
			t.Fatalf("victim tests failed with exit %d\nstdout:\n%s\nstderr:\n%s",
				res.ExitCode, tail(res.Stdout, 80), tail(res.Stderr, 80))
		}
	})

	t.Run("reports", func(t *testing.T) {
		spec.verify(t, c.Reports)
	})
}

func verifyGlibcReports(t *testing.T, reports string, safeLinking bool) {
	t.Helper()
	poison := checks.LoadHeap(t, filepath.Join(reports, "poison", "heap.json"))
	if poison.Profile.Source != "libc-string" {
		t.Fatalf("poison profile source: got %q", poison.Profile.Source)
	}
	if !poison.Profile.Tcache {
		t.Fatal("poison profile does not enable tcache")
	}
	if poison.Profile.SafeLinking != safeLinking {
		t.Fatalf("poison safe_linking: got %v want %v", poison.Profile.SafeLinking, safeLinking)
	}
	checks.RequireFindingID(t, poison.Findings, "D7")

	override := checks.LoadHeap(t, filepath.Join(reports, "profile-override", "heap.json"))
	checks.RequireProfileVersion(t, override, "2.31")
	checks.RequireProfileSource(t, override, "override")
	if override.Profile.SafeLinking {
		t.Fatal("2.31 override should disable safe-linking")
	}

	stdio := checks.LoadFrames(t, filepath.Join(reports, "stdio.events.jsonl"))
	checks.RequireFinding(t, stdio, "D2")
	status := checks.RequireResult(t, stdio, 5)
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
	checks.RequireResult(t, stdio, 6)
	diff := checks.RequireResult(t, stdio, 7)
	checks.RequireContains(t, string(diff.Result), "live_delta", "heap.diff result")
	recipe := checks.RequireResult(t, stdio, 8)
	checks.RequireContains(t, string(recipe.Result), "reclaim", "heap.recipe result")

	crash := checks.LoadFrames(t, filepath.Join(reports, "crash.events.jsonl"))
	crashFinding := checks.RequireFinding(t, crash, "D6")
	if got := fmt.Sprint(crashFinding.Details["fault_region"]); got != "null" {
		t.Fatalf("D6 fault_region: got %q", got)
	}
	if got := fmt.Sprint(crashFinding.Details["fault_access"]); got != "not-mapped" {
		t.Fatalf("D6 fault_access: got %q", got)
	}
	if crashFinding.Details["stack_hits"] == nil {
		t.Fatal("D6 stack_hits missing")
	}

	syscall := checks.LoadFrames(t, filepath.Join(reports, "syscall_uaf.events.jsonl"))
	checks.RequireFinding(t, syscall, "D2")
	seen := make(map[uint64]bool)
	for _, f := range checks.Findings(syscall) {
		if f.ID == "D2" && f.Event != nil {
			seen[f.Event.Arg1] = true
		}
	}
	for _, nr := range []uint64{257, 59, 40, 275} {
		if !seen[nr] {
			t.Fatalf("D2 syscall %d missing", nr)
		}
	}

	checks.RequireNoFindings(t, checks.LoadFrames(t, filepath.Join(reports, "realloc.events.jsonl")))
	checks.RequireNoFindings(t, checks.LoadFrames(t, filepath.Join(reports, "clean.events.jsonl")))
	checks.RequireFinding(t, checks.LoadFrames(t, filepath.Join(reports, "metadata.events.jsonl")), "D8")
	checks.RequireFinding(t, checks.LoadFrames(t, filepath.Join(reports, "size_swap.events.jsonl")), "D9")

	oom := checks.LoadFrames(t, filepath.Join(reports, "oom.events.jsonl"))
	checks.RequireFinding(t, oom, "D4")
	foundOOM := false
	for _, f := range checks.Findings(oom) {
		if f.ID == "D4" && strings.Contains(f.Message, "kernel OOM kill") {
			foundOOM = true
		}
	}
	if !foundOOM {
		t.Fatal("kernel OOM finding missing")
	}

	cxx := checks.LoadFrames(t, filepath.Join(reports, "cxx.events.jsonl"))
	if !hasEvent(cxx, core.EventAlloc, 2, 6) {
		t.Fatal("C++ new allocation label missing")
	}
	if !hasEvent(cxx, core.EventFree, 1, 7) {
		t.Fatal("C++ delete label missing")
	}

	direct := checks.LoadFrames(t, filepath.Join(reports, "uaf_direct.events.jsonl"))
	directFinding := checks.RequireFinding(t, direct, "D2")
	if got := fmt.Sprint(directFinding.Details["source"]); got != "hardware-watchpoint" {
		t.Fatalf("D2 source: got %q", got)
	}

	refresh := string(checks.RequireFile(t, filepath.Join(reports, "dlopen-refresh.json")))
	checks.RequireContains(t, refresh, "libgfsplugin.so", "dlopen module")
	checks.RequireContains(t, refresh, "allocator_paths", "dlopen allocator paths")

	arena := checks.LoadHeap(t, filepath.Join(reports, "arena_backfill", "heap.json"))
	if arena.Backfill == nil || arena.Backfill.Arenas < 1 {
		t.Fatalf("arena backfill stats: %+v", arena.Backfill)
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

func tail(data []byte, lines int) string {
	text := strings.TrimRight(string(data), "\n")
	if text == "" {
		return "(empty)"
	}
	parts := strings.Split(text, "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}
