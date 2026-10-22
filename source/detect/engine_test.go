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
