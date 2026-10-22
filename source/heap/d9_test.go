package heap

import (
	"testing"
	"time"

	"gofengshui/core"
)

func TestD9SizeMismatch(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1010, 0x40, 1))
	ev := core.Event{
		Timestamp: time.Unix(0, 2), Type: core.EventFree, PID: 1, TID: 1,
		Addr: 0x1010, Size: 0x40, Aux1: 0x51, Aux2: 0x31,
		Flags: core.EventFlagMetadata | core.EventFlagNextChunk,
	}
	fs := m.Apply(ev)
	if len(fs) != 1 || fs[0].ID != "D9" || fs[0].Severity != "high" {
		t.Fatalf("expected D9 size mismatch, got %#v", fs)
	}
	if fs[0].Details["expected_size"] != uint64(0x40) || fs[0].Details["actual_size"] != uint64(0x50) {
		t.Fatalf("unexpected D9 details: %#v", fs[0].Details)
	}
}

func TestD9MatchingSizeClean(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1010, 0x40, 1))
	ev := core.Event{
		Timestamp: time.Unix(0, 2), Type: core.EventFree, PID: 1, TID: 1,
		Addr: 0x1010, Size: 0x40, Aux1: 0x41, Aux2: 0x31,
		Flags: core.EventFlagMetadata | core.EventFlagNextChunk,
	}
	if fs := m.Apply(ev); len(fs) != 0 {
		t.Fatalf("unexpected findings for matching size: %#v", fs)
	}
}
