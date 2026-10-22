package heap

import (
	"testing"
	"time"

	"gofengshui/core"
)

func TestReallocMovedFreesOldChunk(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))

	ev := evAt(core.EventAlloc, 1, 0x2000, 0x40, 2)
	ev.Arg1 = 0x1000
	ev.Arg2 = uint64(core.OpRealloc)
	if fs := m.Apply(ev); len(fs) != 0 {
		t.Fatalf("unexpected findings: %#v", fs)
	}

	old, ok := m.Query(0x1000)
	if !ok || old.State != core.StateFreed || old.FreeTS == 0 {
		t.Fatalf("old allocation was not freed: %#v", old)
	}
	fresh, ok := m.Query(0x2000)
	if !ok || fresh.State != core.StateLive {
		t.Fatalf("new allocation missing: %#v", fresh)
	}
	if len(m.Tombstones()) != 1 || m.Tombstones()[0].Addr != 0x1000 {
		t.Fatalf("expected old chunk tombstone: %#v", m.Tombstones())
	}
	p := m.Predict(1, 0x18, 4)
	if len(p.Candidates) != 1 || p.Candidates[0].Addr != 0x1000 {
		t.Fatalf("reallocated chunk missing from prediction: %#v", p)
	}
}

func TestReallocInPlaceKeepsAllocationID(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))
	before, _ := m.Query(0x1000)

	ev := evAt(core.EventAlloc, 1, 0x1000, 0x40, 2)
	ev.Arg1 = 0x1000
	ev.Arg2 = uint64(core.OpRealloc)
	if fs := m.Apply(ev); len(fs) != 0 {
		t.Fatalf("unexpected findings: %#v", fs)
	}

	after, ok := m.Query(0x1000)
	if !ok {
		t.Fatal("in-place realloc lost the allocation")
	}
	if after.ID != before.ID || after.ChunkSize != 0x40 || after.ReqSize != 0x38 {
		t.Fatalf("unexpected in-place result: %#v", after)
	}
	if s := m.Stats(); s.Live != 1 || s.Freed != 0 {
		t.Fatalf("unexpected stats: %#v", s)
	}
}

func TestReallocFailureKeepsOldChunkLive(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))

	ev := core.Event{
		Timestamp: time.Unix(0, 2), Type: core.EventAllocFail, PID: 1, TID: 1,
		ReqSize: 0x100000, Arg1: 0x1000, Arg2: uint64(core.OpRealloc),
	}
	m.Apply(ev)
	a, ok := m.Query(0x1000)
	if !ok || a.State != core.StateLive {
		t.Fatalf("failed realloc freed the old chunk: %#v", a)
	}
}
