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
)

func TestAttachBackfill(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "backfill")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/backfill is not built; run make test-c")
	}
	os.Remove("/tmp/backfill.addrs")
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	var data []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile("/tmp/backfill.addrs")
		if err == nil && len(b) > 0 {
			data = b
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(data) == 0 {
		t.Fatal("backfill target did not write addresses")
	}
	var addrs []uint64
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		v, err := strconv.ParseUint(strings.TrimSpace(line), 10, 64)
		if err != nil {
			t.Fatalf("parse address %q: %v", line, err)
		}
		addrs = append(addrs, v)
	}

	ag := New()
	s, err := ag.Start(CreateParams{
		Mode: "attach", PID: cmd.Process.Pid,
		Config: core.Config{NoEBPF: true, Backfill: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(false)
	if s.backfill == nil || s.backfill.Live < len(addrs) {
		t.Fatalf("backfill stats = %#v, want at least %d live chunks", s.backfill, len(addrs))
	}
	for _, addr := range addrs {
		if _, ok := s.Model().Query(addr); !ok {
			t.Fatalf("backfill did not recover allocation 0x%x; stats=%#v", addr, s.backfill)
		}
	}
}
