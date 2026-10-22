package debugger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gofengshui/symbols"
)

func TestSoftwareBreakpointTrigger(t *testing.T) {
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
	sym, mod, ok := res.Name("", "gfs_sink")
	if !ok {
		t.Fatal("gfs_sink not found")
	}
	addr := mod.RuntimeAddr(sym)
	bp, err := tr.SetBreakpoint(addr, "gfs_sink", false)
	if err != nil {
		t.Fatal(err)
	}
	if bp.Hardware {
		t.Fatal("expected software breakpoint")
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
	st, err := tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Reason != "breakpoint" || st.Breakpoint == nil || st.Breakpoint.Addr != addr {
		t.Fatalf("unexpected software breakpoint stop: %#v", st)
	}
	if st.Breakpoint.Hardware {
		t.Fatal("hit reported as hardware breakpoint")
	}
	if st.Regs.RIP != addr {
		t.Fatalf("RIP = 0x%x, want 0x%x", st.Regs.RIP, addr)
	}
}
