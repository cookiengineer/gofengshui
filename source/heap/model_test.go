package heap

import (
	"testing"
	"time"

	"gofengshui/core"
)

func ev(t core.EventType, addr, size, req uint64) core.Event {
	return core.Event{
		Timestamp: time.Now(), Type: t, PID: 1, TID: 1,
		Addr: addr, Size: size, ReqSize: req, Comm: "test",
	}
}

func TestDoubleFreeAndUAF(t *testing.T) {
	m := NewModel()
	if f := m.Apply(ev(core.EventAlloc, 0x1000, 0x20, 0x18)); len(f) != 0 {
		t.Fatalf("unexpected alloc findings: %v", f)
	}
	if f := m.Apply(ev(core.EventFree, 0x1000, 0x20, 0)); len(f) != 0 {
		t.Fatalf("unexpected free findings: %v", f)
	}
	f := m.Apply(ev(core.EventDoubleFree, 0x1000, 0x20, 0))
	if len(f) != 1 || f[0].ID != "D1" {
		t.Fatalf("expected D1 double free, got %#v", f)
	}
	f = m.Apply(ev(core.EventMemAccess, 0x1000, 8, 0))
	if len(f) != 1 || f[0].ID != "D2" {
		t.Fatalf("expected D2 UAF, got %#v", f)
	}
}

func TestOverflow(t *testing.T) {
	m := NewModel()
	m.Apply(ev(core.EventAlloc, 0x2000, 0x10, 0x10))
	f := m.Apply(ev(core.EventMemAccess, 0x2000, 0x40, 0))
	if len(f) != 1 || f[0].ID != "D3" {
		t.Fatalf("expected D3 overflow, got %#v", f)
	}
}

func TestAllocReuseRemovesTombstone(t *testing.T) {
	m := NewModel()
	m.Apply(ev(core.EventAlloc, 0x3000, 0x20, 0x20))
	m.Apply(ev(core.EventFree, 0x3000, 0x20, 0))
	m.Apply(ev(core.EventAlloc, 0x3000, 0x20, 0x20))
	if got := len(m.Tombstones()); got != 0 {
		t.Fatalf("expected no tombstones, got %d", got)
	}
	a, ok := m.Query(0x3000)
	if !ok || a.State != core.StateLive {
		t.Fatalf("expected live allocation, got %#v %v", a, ok)
	}
}

func TestMmapTracking(t *testing.T) {
	m := NewModel()
	e := ev(core.EventMmap, 0, 0x20000, 0)
	e.Arg1 = 3
	e.TID = 7
	m.Apply(e)
	r := ev(core.EventSyscallRet, 0x700000, 0, 0)
	r.Arg1 = core.SysMmap
	r.TID = 7
	m.Apply(r)
	if got := len(m.Mappings()); got != 1 {
		t.Fatalf("expected one mmap, got %d", got)
	}
}

func TestAnalyze(t *testing.T) {
	m := NewModel()
	m.Apply(ev(core.EventAlloc, 0x1000, 0x20, 0x18))
	m.Apply(ev(core.EventAlloc, 0x1100, 0x20, 0x18))
	m.Apply(ev(core.EventFree, 0x1000, 0x20, 0))
	m.Apply(ev(core.EventAlloc, 0x1000, 0x20, 0x18))
	a := m.Analyze()
	if a.Live != 2 || a.Freed != 0 {
		t.Fatalf("unexpected live/freed: %#v", a)
	}
	if len(a.SizeClasses) != 1 || a.SizeClasses[0].ChunkSize != 0x20 || a.SizeClasses[0].Live != 2 {
		t.Fatalf("unexpected size classes: %#v", a.SizeClasses)
	}
	if len(a.Gaps) == 0 || a.Gaps[0].Size != 0x100-0x20 {
		t.Fatalf("unexpected gaps: %#v", a.Gaps)
	}
	if len(a.Reuses) != 1 || a.Reuses[0].Addr != 0x1000 || a.Reuses[0].Count != 2 {
		t.Fatalf("unexpected reuses: %#v", a.Reuses)
	}
}
