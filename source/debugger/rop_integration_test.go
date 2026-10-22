package debugger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gofengshui/symbols"
)

// TestROPHardwareTrace exercises the same hardware-breakpoint/single-step
// path used by agent ROP validation, without requiring eBPF privileges.
func TestROPHardwareTrace(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "rop_sink")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/rop_sink is not built; run make test-c")
	}
	tr, err := Launch(LaunchOptions{Path: path})
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

	res, err := symbols.NewResolver(tr.PID())
	if err != nil {
		t.Fatal(err)
	}
	sinkSym, sinkMod, ok := res.Name("", "gfs_sink")
	if !ok {
		t.Fatal("gfs_sink not found")
	}
	startSym, startMod, ok := res.Name("", "gfs_pop_rdi_ret")
	if !ok {
		t.Fatal("gfs_pop_rdi_ret not found")
	}
	sink := sinkMod.RuntimeAddr(sinkSym)
	start := startMod.RuntimeAddr(startSym)

	if _, err := tr.SetBreakpoint(sink, "gfs_sink", true); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.SetBreakpoint(start, "gfs_pop_rdi_ret", true); err != nil {
		t.Fatal(err)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
	st, err := tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Address != start {
		t.Fatalf("expected start 0x%x, got %#v", start, st)
	}
	if err := tr.ClearBreakpoint(start); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		regs, err := tr.GetRegisters(0)
		if err != nil {
			t.Fatal(err)
		}
		if regs.RIP == sink {
			if regs.RDI != 0x4141 {
				t.Fatalf("RDI = 0x%x, want 0x4141", regs.RDI)
			}
			return
		}
		if err := tr.SingleStep(0); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.NextStop(5 * time.Second); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("did not reach sink")
}

func TestHardwareWatchpointTrigger(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "rop_sink")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/rop_sink is not built; run make test-c")
	}
	tr, err := Launch(LaunchOptions{Path: path})
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
	res, err := symbols.NewResolver(tr.PID())
	if err != nil {
		t.Fatal(err)
	}
	sym, mod, ok := res.Name("", "gfs_vuln")
	if !ok {
		t.Fatal("gfs_vuln not found")
	}
	addr := mod.RuntimeAddr(sym)
	if _, err := tr.SetBreakpoint(addr, "gfs_vuln", true); err != nil {
		t.Fatal(err)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
	st, err := tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Address != addr {
		t.Fatalf("expected gfs_vuln 0x%x, got %#v", addr, st)
	}
	if err := tr.ClearBreakpoint(addr); err != nil {
		t.Fatal(err)
	}
	// At function entry RSP points at the saved return address, which the
	// overflowing memcpy later overwrites.
	slot := st.Regs.RSP
	wp, err := tr.SetWatchpoint(slot, 8, WatchWrite, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
	st, err = tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Watchpoint == nil || st.Watchpoint.ID != wp.ID {
		t.Fatalf("expected watchpoint %d, got %#v", wp.ID, st)
	}
	if st.Address != slot {
		t.Fatalf("watchpoint address = 0x%x, want 0x%x", st.Address, slot)
	}
}
