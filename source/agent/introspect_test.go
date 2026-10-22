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
	"gofengshui/heap"
)

func expectedTcacheCount(t *testing.T, layout string) int {
	t.Helper()
	switch layout {
	case heap.TcacheLayoutModern:
		return 16
	case heap.TcacheLayoutLegacy:
		return 7
	default:
		t.Fatalf("unknown tcache layout %q", layout)
		return 0
	}
}

func TestTcacheIntrospectionLive(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "tcache_introspect")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/tcache_introspect is not built; run make test-c")
	}
	const addrFile = "/tmp/tcache_introspect.addrs"
	_ = os.Remove(addrFile)
	t.Cleanup(func() { _ = os.Remove(addrFile) })

	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	var ordered []uint64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(addrFile)
		if err == nil && len(data) > 0 {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				v, err := strconv.ParseUint(strings.TrimSpace(line), 10, 64)
				if err != nil {
					t.Fatalf("parse address %q: %v", line, err)
				}
				ordered = append(ordered, v)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(ordered) != 20 {
		t.Fatalf("fixture wrote %d addresses, want 20", len(ordered))
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

	snap, err := s.collectIntrospection(true, 0)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	expected := expectedTcacheCount(t, snap.Layout)
	var bin *heap.TcacheBin
	for i := range snap.Threads {
		if snap.Threads[i].TID != uint32(cmd.Process.Pid) {
			continue
		}
		for j := range snap.Threads[i].Bins {
			if snap.Threads[i].Bins[j].ChunkSize == 0x20 {
				bin = &snap.Threads[i].Bins[j]
				break
			}
		}
	}
	if bin == nil {
		t.Fatalf("no 0x20 tcache bin observed; snapshot=%#v", snap)
	}
	if bin.Count != expected || len(bin.Entries) != expected {
		t.Fatalf("tcache count = %d/%d, want %d; bin=%#v", bin.Count, len(bin.Entries), expected, bin)
	}
	for i := 0; i < expected; i++ {
		want := ordered[expected-1-i]
		if bin.Entries[i] != want {
			t.Fatalf("entry %d = 0x%x, want 0x%x; warnings=%v", i, bin.Entries[i], want, snap.Warnings)
		}
	}
	var mainArena *heap.ArenaSnapshot
	for i := range snap.Arenas {
		if snap.Arenas[i].Main {
			mainArena = &snap.Arenas[i]
			break
		}
	}
	if mainArena == nil || mainArena.Top == 0 {
		t.Fatalf("main arena not observed; snapshot=%#v", snap)
	}
	if len(mainArena.Bins) == 0 {
		t.Fatalf("main arena has no observed free bins; arena=%#v", mainArena)
	}

	pred := heap.PredictObserved(s.Model(), &snap, uint32(cmd.Process.Pid), 24, 8)
	if !pred.Observed || len(pred.Candidates) != 8 || pred.Candidates[0].Addr != ordered[expected-1] {
		t.Fatalf("observed prediction = %#v", pred)
	}
}

func TestTcacheIntrospectionLayoutMismatchOverride(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "tcache_introspect")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/tcache_introspect is not built; run make test-c")
	}
	const addrFile = "/tmp/tcache_introspect.addrs"
	_ = os.Remove(addrFile)
	t.Cleanup(func() { _ = os.Remove(addrFile) })

	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(addrFile); err == nil && st.Size() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	ag := New()
	// The override models pre-safe-linking glibc while the live libc is
	// modern. Introspection must still detect the real layout.
	s, err := ag.Start(CreateParams{
		Mode: "attach", PID: cmd.Process.Pid,
		Config: core.Config{NoEBPF: true, Backfill: true, GlibcVersion: "2.31"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(false)

	snap, err := s.collectIntrospection(true, 0)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	expected := expectedTcacheCount(t, snap.Layout)
	found := false
	for _, th := range snap.Threads {
		for _, bin := range th.Bins {
			if bin.ChunkSize == 0x20 && len(bin.Entries) == expected {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no %d-entry tcache bin after version override; layout=%s snapshot=%#v",
			expected, snap.Layout, snap)
	}
}

func TestTcacheIntrospectionThreads(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "tcache_threads")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/tcache_threads is not built; run make test-c")
	}
	old, _ := filepath.Glob("/tmp/tcache_threads.*.addrs")
	for _, f := range old {
		_ = os.Remove(f)
	}
	t.Cleanup(func() {
		files, _ := filepath.Glob("/tmp/tcache_threads.*.addrs")
		for _, f := range files {
			_ = os.Remove(f)
		}
	})

	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	var orders [][]uint64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := filepath.Glob("/tmp/tcache_threads.*.addrs")
		if len(files) < 2 {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		orders = orders[:0]
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var order []uint64
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				v, err := strconv.ParseUint(strings.TrimSpace(line), 10, 64)
				if err != nil {
					t.Fatalf("parse address %q: %v", line, err)
				}
				order = append(order, v)
			}
			orders = append(orders, order)
		}
		break
	}
	if len(orders) != 2 {
		t.Fatalf("fixture wrote %d thread address files, want 2", len(orders))
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

	snap, err := s.collectIntrospection(true, 0)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	expected := expectedTcacheCount(t, snap.Layout)
	if expected > 8 {
		expected = 8
	}
	matched := 0
	for _, order := range orders {
		for _, th := range snap.Threads {
			for _, bin := range th.Bins {
				if bin.ChunkSize != 0x20 || len(bin.Entries) != expected {
					continue
				}
				ok := true
				for i := 0; i < expected; i++ {
					if bin.Entries[i] != order[expected-1-i] {
						ok = false
						break
					}
				}
				if ok {
					matched++
				}
			}
		}
	}
	if matched < 2 {
		t.Fatalf("matched %d/2 per-thread tcache snapshots; snapshot=%#v", matched, snap)
	}
	if len(snap.Arenas) < 2 {
		t.Fatalf("observed %d arenas, want main plus a thread arena; warnings=%v",
			len(snap.Arenas), snap.Warnings)
	}
}
