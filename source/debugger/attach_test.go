package debugger

import (
	"os/exec"
	"testing"
	"time"
)

func TestAttachGetRegsStep(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	tr, err := Attach(cmd.Process.Pid, false)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("attach: %v", err)
	}
	defer tr.Close(true)
	st, err := tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatalf("initial stop: %v", err)
	}
	if st.Reason != "stopped" {
		t.Fatalf("unexpected stop: %#v", st)
	}
	regs, err := tr.GetRegisters(0)
	if err != nil {
		t.Fatalf("regs: %v", err)
	}
	if regs.RIP == 0 {
		t.Fatal("RIP is zero")
	}
	if _, err := tr.ReadMemory(regs.RIP, 8); err != nil {
		t.Fatalf("read memory: %v", err)
	}
	wp, err := tr.SetWatchpoint(regs.RSP&^7, 8, WatchWrite, 0)
	if err != nil {
		t.Fatalf("set watchpoint: %v", err)
	}
	if err := tr.ClearWatchpoint(wp.ID); err != nil {
		t.Fatalf("clear watchpoint: %v", err)
	}
	if err := tr.SingleStep(0); err != nil {
		t.Fatalf("step: %v", err)
	}
	st, err = tr.NextStop(5 * time.Second)
	if err != nil {
		t.Fatalf("step stop: %v", err)
	}
	if st.Reason != "single_step" {
		t.Fatalf("expected single_step, got %#v", st)
	}
	if err := tr.Continue(0); err != nil {
		t.Fatalf("continue: %v", err)
	}
	if err := tr.Pause(); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if _, err := tr.NextStop(5 * time.Second); err != nil {
		t.Fatalf("pause stop: %v", err)
	}
}
