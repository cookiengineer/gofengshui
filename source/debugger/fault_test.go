package debugger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSignalFaultInfo(t *testing.T) {
	path := filepath.Join("..", "..", "build", "testdata", "crash")
	if _, err := os.Stat(path); err != nil {
		t.Skip("build/testdata/crash is not built; run make test-c")
	}
	tr, err := Launch(LaunchOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close(true)

	if _, err := tr.NextStop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatal(err)
	}
	st, err := tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Reason != "signal" || st.Signal != int(unix.SIGSEGV) {
		t.Fatalf("unexpected stop: %#v", st)
	}
	if st.FaultAddr != 0 {
		t.Fatalf("fault address = 0x%x, want 0", st.FaultAddr)
	}
	if st.FaultCode != 1 {
		t.Fatalf("fault code = %d, want SEGV_MAPERR (1)", st.FaultCode)
	}
	if len(st.Stack) == 0 {
		t.Fatal("expected a captured stack window")
	}
}
