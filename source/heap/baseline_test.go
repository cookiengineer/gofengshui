package heap

import (
	"testing"

	"gofengshui/source/core"
)

func TestBaselineDiff(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))
	m.Apply(evAt(core.EventAlloc, 1, 0x1020, 0x20, 2))
	base := m.CaptureBaseline("before")
	if base.Stats.Live != 2 || base.Profile.Version == "" {
		t.Fatalf("unexpected baseline: %#v", base)
	}

	m.Apply(evAt(core.EventFree, 1, 0x1000, 0x20, 3))
	cur := m.CaptureBaseline("after")
	d := DiffBaselines(base, cur)
	if d.LiveDelta != -1 || d.FreedDelta != 1 {
		t.Fatalf("unexpected deltas: %#v", d)
	}
	if len(d.SizeClasses) != 1 || d.SizeClasses[0].ChunkSize != 0x20 ||
		d.SizeClasses[0].LiveDelta != -1 || d.SizeClasses[0].FreedDelta != 1 {
		t.Fatalf("unexpected size-class delta: %#v", d.SizeClasses)
	}
}

func TestBaselineDiffGapsAndReuse(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))
	m.Apply(evAt(core.EventAlloc, 1, 0x1060, 0x20, 2))
	base := m.CaptureBaseline("base")
	m.Apply(evAt(core.EventFree, 1, 0x1000, 0x20, 3))
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 4))
	m.Apply(evAt(core.EventFree, 1, 0x1000, 0x20, 5))
	cur := m.CaptureBaseline("cur")
	d := DiffBaselines(base, cur)
	if len(d.Reuses) != 1 || d.Reuses[0].Addr != 0x1000 {
		t.Fatalf("unexpected reuse delta: %#v", d.Reuses)
	}
	if len(d.GapsRemoved) != 1 || d.GapsRemoved[0].Start != 0x1020 {
		t.Fatalf("unexpected gap delta: %#v", d.GapsRemoved)
	}
}
