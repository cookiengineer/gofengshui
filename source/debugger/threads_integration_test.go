package debugger

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gofengshui/symbols"
)

func TestMultiThreadCloneAndPause(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "threads")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/threads is not built; run make test-c")
	}
	tr, err := Launch(LaunchOptions{Path: path, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close(true)
	if _, err := tr.NextStop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	entry, err := symbols.RuntimeEntry(tr.PID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.SetBreakpoint(entry, "_start", true); err != nil {
		t.Fatal(err)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.NextStop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tr.ClearBreakpoint(entry); err != nil {
		t.Fatal(err)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(tr.Threads()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(tr.Threads()); got < 2 {
		t.Fatalf("expected multiple traced threads, got %d", got)
	}
	root := tr.PID()
	if err := tr.PauseOthers(root); err != nil {
		t.Fatalf("pause others: %v", err)
	}
	if !tr.WaitStoppedExcept(root, 3*time.Second) {
		t.Fatalf("other threads did not stop; threads=%v", tr.Threads())
	}
	if err := tr.ContinueOthers(root); err != nil {
		t.Fatalf("continue others: %v", err)
	}
	if err := tr.Pause(); err != nil {
		t.Fatal(err)
	}
	if !tr.WaitStopped(3 * time.Second) {
		t.Fatalf("threads did not stop; all_stopped=%v threads=%v", tr.AllStopped(), tr.Threads())
	}
	if !tr.AllStopped() {
		t.Fatalf("AllStopped=false threads=%v", tr.Threads())
	}
	if got := len(tr.Threads()); got < 5 {
		t.Fatalf("threads exited during pause: got %d, want at least 5", got)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
	if !tr.WaitExit(4 * time.Second) {
		t.Fatalf("target did not exit after resume; threads=%v", tr.Threads())
	}
}

func TestAttachAllThreadsAndStopWorld(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "threads")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/threads is not built; run make test-c")
	}
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	tr, err := Attach(cmd.Process.Pid, true)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	defer tr.Close(true)
	if !tr.WaitStopped(3 * time.Second) {
		t.Fatalf("attached threads did not stop; threads=%v", tr.Threads())
	}
	if got := len(tr.Threads()); got < 2 {
		t.Fatalf("expected multiple attached threads, got %d", got)
	}
	if !tr.AllStopped() {
		t.Fatalf("not all attached threads stopped: %v", tr.Threads())
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
}
