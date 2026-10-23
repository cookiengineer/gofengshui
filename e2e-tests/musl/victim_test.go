//go:build victim

package musl

import (
	"fmt"
	"os"
	"path/filepath"
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

func runTrace(t *testing.T, r *agentrun.Runner, name, fixtureName string, extra ...string) *agentrun.Result {
	t.Helper()
	res := r.Run(t, name, agentrun.Options{
		Args:         append([]string{}, extra...),
		Target:       []string{fixture(r, fixtureName)},
		Timeout:      30 * time.Second,
		AllowFailure: true,
	})
	res.RequireSuccess(t)
	return res
}

func TestMuslAllocTrace(t *testing.T) {
	r := agentrun.NewRunner(t)
	res := runTrace(t, r, "alloc_loop", "alloc_loop", "--sample-stacks", "4")
	report := res.Heap(t)
	if len(report.Analysis.SizeClasses) == 0 {
		t.Fatal("heap analysis has no size classes")
	}
}

func TestMuslDoubleFree(t *testing.T) {
	r := agentrun.NewRunner(t)
	res := runFind(t, r, "double_free", "double_free", "D1")
	checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "**D1**", "double-free report")
}

func TestMuslUAF(t *testing.T) {
	r := agentrun.NewRunner(t)
	res := runFind(t, r, "uaf", "uaf", "D2")
	checks.RequireTextContains(t, filepath.Join(res.ReportDir, "report.md"), "use-after-free", "UAF report")
}

func TestMuslCrash(t *testing.T) {
	r := agentrun.NewRunner(t)
	res := runFind(t, r, "crash", "crash", "D6")
	frames := checks.LoadFrames(t, res.EventsPath)
	f := checks.RequireFinding(t, frames, "D6")
	if got := fmt.Sprint(f.Details["fault_region"]); got != "null" {
		t.Fatalf("fault_region: got %q want null", got)
	}
	if f.Details["stack_hits"] == nil {
		t.Fatal("D6 stack_hits missing")
	}
	checks.RequireTextContains(t, res.StderrPath, "signal 11 at RIP", "crash stderr")
}

func TestMuslAllocFail(t *testing.T) {
	r := agentrun.NewRunner(t)
	res := runFind(t, r, "alloc_fail", "alloc_fail", "D4")
	found := false
	for _, f := range checks.Findings(checks.LoadFrames(t, res.EventsPath)) {
		if f.ID == "D4" && strings.Contains(f.Message, "allocation failed") {
			found = true
		}
	}
	if !found {
		t.Fatal("allocation failure finding missing")
	}
}

func TestMuslThreads(t *testing.T) {
	r := agentrun.NewRunner(t)
	res := runTrace(t, r, "threads", "threads", "--follow")
	frames := checks.LoadFrames(t, res.EventsPath)
	seen := make(map[uint32]bool)
	for _, f := range frames {
		if f.Event != nil && f.Event.Event != nil && f.Event.Event.Type == core.EventAlloc {
			seen[f.Event.Event.TID] = true
		}
	}
	if len(seen) < 2 {
		t.Fatalf("allocator events from %d thread(s), want at least 2", len(seen))
	}
}

func TestMuslForkExec(t *testing.T) {
	r := agentrun.NewRunner(t)
	res := runTrace(t, r, "fork_exec", "fork_exec", "--follow")
	frames := checks.LoadFrames(t, res.EventsPath)
	seen := make(map[uint32]bool)
	for _, f := range frames {
		if f.Event != nil && f.Event.Event != nil && f.Event.Event.Type == core.EventAlloc {
			seen[f.Event.Event.PID] = true
		}
	}
	if len(seen) < 2 {
		t.Fatalf("allocator events from %d process(es), want at least 2", len(seen))
	}
}

func TestMuslProtocol(t *testing.T) {
	r := agentrun.NewRunner(t)
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
}
