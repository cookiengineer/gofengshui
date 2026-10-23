package detect

import (
	"testing"
	"time"

	"gofengshui/core"
)

func TestDedup(t *testing.T) {
	e := New(nil)
	ev := core.Event{Timestamp: time.Now(), Type: core.EventInvalidFree, Addr: 0x10, TID: 1}
	first := e.Observe(ev)
	second := e.Observe(ev)
	if len(first) != 1 {
		t.Fatalf("first findings = %d", len(first))
	}
	if len(second) != 0 {
		t.Fatalf("duplicate findings = %d", len(second))
	}
	ok, _ := e.Check(Assertion{Type: "finding", ID: "D1"})
	if !ok {
		t.Fatal("expected D1 assertion to pass")
	}
}

func TestDedupIncludesSyscall(t *testing.T) {
	e := New(nil)
	now := time.Now()
	e.Observe(core.Event{Timestamp: now, Type: core.EventAlloc, Addr: 0x1000, Size: 0x40, ReqSize: 0x30, TID: 1, Arg2: uint64(core.OpMalloc)})
	e.Observe(core.Event{Timestamp: now, Type: core.EventFree, Addr: 0x1000, Size: 0x40, TID: 1})
	first := e.Observe(core.Event{Timestamp: now, Type: core.EventMemAccess, Addr: 0x1000, Size: 4, TID: 1, Arg1: core.SysOpenat, Arg2: 2})
	second := e.Observe(core.Event{Timestamp: now, Type: core.EventMemAccess, Addr: 0x1000, Size: 4, TID: 1, Arg1: core.SysExecve, Arg2: 2})
	if len(first) != 1 || first[0].ID != "D2" {
		t.Fatalf("first findings = %v", first)
	}
	if len(second) != 1 || second[0].ID != "D2" {
		t.Fatalf("second findings = %v", second)
	}
}
