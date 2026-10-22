package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gofengshui/source/core"
	"gofengshui/source/debugger"
)

func TestWatchAllocationByIDLive(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "watch_alloc")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/watch_alloc is not built; run make test-c")
	}
	os.Remove("/tmp/watch_alloc.addr")
	os.Remove("/tmp/watch_alloc.release")
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	var addr uint64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile("/tmp/watch_alloc.addr")
		if err == nil && len(b) > 0 {
			addr, err = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addr == 0 {
		t.Fatal("watch target did not publish its allocation address")
	}

	ag := New()
	s, err := ag.Start(CreateParams{
		Mode: "attach", PID: cmd.Process.Pid, Pause: true,
		Config: core.Config{NoEBPF: true, Backfill: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(true)

	a, ok := s.Model().Query(addr)
	if !ok {
		t.Fatalf("backfill did not recover allocation 0x%x", addr)
	}
	wp, err := s.WatchAllocation(a.ID, 8, debugger.WatchWrite)
	if err != nil {
		t.Fatal(err)
	}
	if wp.AllocID != a.ID || wp.Addr != a.Addr || wp.Size != 8 {
		t.Fatalf("unexpected watchpoint: %#v", wp)
	}
	if err := os.WriteFile("/tmp/watch_alloc.release", []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.ContinueAll(); err != nil {
		t.Fatal(err)
	}
	st, err := s.WaitStop(5*time.Second, func(st debugger.Stop) bool {
		return st.Watchpoint != nil && st.Watchpoint.ID == wp.ID
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Watchpoint.AllocID != a.ID || st.Address != a.Addr {
		t.Fatalf("watchpoint stop did not identify the allocation: %#v", st)
	}
}
