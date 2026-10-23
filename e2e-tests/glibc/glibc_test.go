//go:build !victim

package glibc

import (
	"fmt"
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

func TestGlibcMatrix(t *testing.T) {
	harness.RequireRoot(t)
	if !harness.EnvBool("GFS_E2E_MATRIX") {
		t.Skip("set GFS_E2E_MATRIX=1 to run the glibc base-image matrix")
	}
	run := harness.NewRun(t)
	cases := []caseSpec{
		{name: "glibc-ubuntu-20.04", variant: "ubuntu-20.04", baseImage: "ubuntu:20.04", safeLinking: false},
		{name: "glibc-ubuntu-22.04", variant: "ubuntu-22.04", baseImage: "ubuntu:22.04", safeLinking: true},
		{name: "glibc-debian-12", variant: "debian-12", baseImage: "debian:12", safeLinking: true},
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
