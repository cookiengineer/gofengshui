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

func TestAttachArenaBackfill(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "arena_backfill")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/arena_backfill is not built; run make test-c")
	}
	old, _ := filepath.Glob("/tmp/arena_backfill.*.addrs")
	for _, f := range old {
		os.Remove(f)
	}
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	var addrs []uint64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := filepath.Glob("/tmp/arena_backfill.*.addrs")
		if len(files) < 2 {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		addrs = addrs[:0]
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				v, err := strconv.ParseUint(strings.TrimSpace(line), 10, 64)
				if err != nil {
					t.Fatalf("parse address %q: %v", line, err)
				}
				addrs = append(addrs, v)
			}
		}
		break
	}
	if len(addrs) == 0 {
		t.Fatal("arena backfill target did not write addresses")
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
		t.Fatalf("arena backfill stats = %#v, want at least %d live chunks", s.backfill, len(addrs))
	}
	if s.backfill.Arenas < 1 {
		t.Fatalf("expected at least one thread arena, stats=%#v", s.backfill)
	}
	for _, addr := range addrs {
		if _, ok := s.Model().Query(addr); !ok {
			t.Fatalf("arena backfill did not recover allocation 0x%x; stats=%#v", addr, s.backfill)
		}
	}
}
