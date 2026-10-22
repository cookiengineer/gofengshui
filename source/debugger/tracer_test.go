package debugger

import (
	"testing"
	"time"
)

func TestLaunchAndExit(t *testing.T) {
	tr, err := Launch(LaunchOptions{Path: "/bin/true"})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer tr.Close(true)
	st, err := tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatalf("initial stop: %v", err)
	}
	if st.Reason != "exec" && st.Reason != "stopped" {
		t.Fatalf("unexpected initial stop: %#v", st)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatalf("continue: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case st, ok := <-tr.Stops():
			if !ok {
				return
			}
			if st.Reason == "exit" {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for target exit")
		}
	}
}

func TestWatchpointRegisterEncoding(t *testing.T) {
	if localEnable[0] != 1 || localEnable[1] != 4 || localEnable[3] != 64 {
		t.Fatalf("local enable bits wrong: %v", localEnable)
	}
	if rwShift[0] != 16 || lenShift[3] != 30 {
		t.Fatalf("DR7 shifts wrong: %v %v", rwShift, lenShift)
	}
}
