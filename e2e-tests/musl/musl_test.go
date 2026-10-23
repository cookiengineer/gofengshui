//go:build !victim

package musl

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gofengshui/e2e/internal/checks"
	"gofengshui/e2e/internal/harness"
)

func TestMusl(t *testing.T) {
	harness.RequireRoot(t)
	run := harness.NewRun(t)
	c := run.NewCase("musl")
	c.Preflight()
	c.RequireBaseImage(t, "alpine:3.20")
	c.BuildAgent()
	tag := harness.ImageTag("musl", "alpine-3.20")
	image := c.BuildImage(tag, filepath.Join(run.Root, "e2e-tests", "musl", "Containerfile"), map[string]string{"ALPINE_VERSION": "3.20"})
	victim := c.BuildVictimTest("./musl", "musl.victim.test")
	container := c.StartContainer(t, harness.ContainerOptions{Image: image})
	container.CopyTo(victim, "/opt/gfs/e2e/gofengshui")

	t.Run("victim", func(t *testing.T) {
		res := container.Exec("victim-tests", harness.ExecOptions{
			Timeout:      15 * time.Minute,
			AllowFailure: true,
		}, "/opt/gfs/e2e/gofengshui", "-test.v", "-test.timeout=10m")
		if res.ExitCode != 0 {
			t.Fatalf("victim tests failed with exit %d\nstdout:\n%s\nstderr:\n%s",
				res.ExitCode, tail(res.Stdout, 80), tail(res.Stderr, 80))
		}
	})

	t.Run("reports", func(t *testing.T) {
		checks.RequireFinding(t, checks.LoadFrames(t, filepath.Join(c.Reports, "double_free.events.jsonl")), "D1")
		checks.RequireFinding(t, checks.LoadFrames(t, filepath.Join(c.Reports, "uaf.events.jsonl")), "D2")
		checks.RequireFinding(t, checks.LoadFrames(t, filepath.Join(c.Reports, "crash.events.jsonl")), "D6")
		checks.RequireFinding(t, checks.LoadFrames(t, filepath.Join(c.Reports, "alloc_fail.events.jsonl")), "D4")
		report := checks.LoadHeap(t, filepath.Join(c.Reports, "alloc_loop", "heap.json"))
		if len(report.Analysis.SizeClasses) == 0 {
			t.Fatal("heap analysis has no size classes")
		}
	})
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
