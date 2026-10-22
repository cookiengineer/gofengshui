package heap

import (
	"testing"
	"time"

	"gofengshui/source/core"
)

func freeMetaEvent(addr, rawSize, nextSize uint64, flags uint32) core.Event {
	return core.Event{
		Timestamp: time.Unix(0, 1), Type: core.EventFree, PID: 1, TID: 1,
		Addr: addr, Size: rawSize &^ 7, Aux1: rawSize, Aux2: nextSize, Flags: flags,
	}
}

func TestD8ValidMetadata(t *testing.T) {
	m := NewModel()
	ev := freeMetaEvent(0x1010, 0x31, 0x31, core.EventFlagMetadata|core.EventFlagNextChunk)
	if fs := m.Apply(ev); len(fs) != 0 {
		t.Fatalf("unexpected D8 on valid chunk: %#v", fs)
	}
}

func TestD8InvalidChunkSize(t *testing.T) {
	m := NewModel()
	ev := freeMetaEvent(0x1010, 0x39, 0x31, core.EventFlagMetadata|core.EventFlagNextChunk)
	fs := m.Apply(ev)
	if len(fs) != 1 || fs[0].ID != "D8" || fs[0].Severity != "high" {
		t.Fatalf("expected D8 for invalid size, got %#v", fs)
	}
}

func TestD8InvalidNextChunk(t *testing.T) {
	m := NewModel()
	ev := freeMetaEvent(0x1010, 0x31, 0x10, core.EventFlagMetadata|core.EventFlagNextChunk)
	fs := m.Apply(ev)
	if len(fs) != 1 || fs[0].ID != "D8" {
		t.Fatalf("expected D8 for invalid next size, got %#v", fs)
	}
}

func TestD8PrevInuseCleared(t *testing.T) {
	m := NewModel()
	ev := freeMetaEvent(0x1010, 0x31, 0x30, core.EventFlagMetadata|core.EventFlagNextChunk)
	fs := m.Apply(ev)
	if len(fs) != 1 || fs[0].ID != "D8" {
		t.Fatalf("expected D8 for cleared PREV_INUSE, got %#v", fs)
	}
}

func TestD8RequiresFlag(t *testing.T) {
	m := NewModel()
	ev := freeMetaEvent(0x1010, 0x4141, 0x10, 0)
	if fs := m.Apply(ev); len(fs) != 0 {
		t.Fatalf("unexpected D8 without metadata flag: %#v", fs)
	}
}
