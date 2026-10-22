package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gofengshui/core"
)

func TestAutoWatchFreedChunk(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "uaf_direct")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/uaf_direct is not built; run make test-c")
	}
	os.Remove("/tmp/uaf_direct.addr")
	os.Remove("/tmp/uaf_direct.release")
	cmd := exec.Command(path, "wait")
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
		b, err := os.ReadFile("/tmp/uaf_direct.addr")
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
		t.Fatal("UAF target did not publish its allocation address")
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
	if err := s.ContinueAll(); err != nil {
		t.Fatal(err)
	}
	s.armFreedWatch(a.Addr, a.ID, 8)
	if err := os.WriteFile("/tmp/uaf_direct.release", []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range s.Engine().Recent() {
			if f.ID == "D2" && f.Details["source"] == "hardware-watchpoint" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no hardware-watchpoint D2 finding; recent=%#v", s.Engine().Recent())
}
