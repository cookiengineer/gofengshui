package heap

import (
	"testing"

	"gofengshui/core"
)

func fillArena(t *testing.T, m *Model, tid uint32, base uint64, startTS int64) {
	t.Helper()
	for i := 0; i < 10; i++ {
		m.Apply(evAt(core.EventAlloc, tid, base+uint64(i)*0x20, 0x20, startTS+int64(i)))
	}
	for i := 0; i < 10; i++ {
		m.Apply(evAt(core.EventFree, tid, base+uint64(i)*0x20, 0x20, startTS+100+int64(i)))
	}
}

func TestArenaBinsSeparate(t *testing.T) {
	m := NewModel()
	m.SetRegions([]Region{
		{Start: 0x1000, End: 0x2000, Path: "[heap]"},
		{Start: 0x10000, End: 0x11000},
	})
	fillArena(t, m, 1, 0x1000, 100)
	fillArena(t, m, 2, 0x10000, 200)

	p := m.Predict(1, 0x18, 20)
	if len(p.Candidates) != 10 || p.TcacheCount != 7 {
		t.Fatalf("unexpected main-arena prediction: %#v", p)
	}
	for _, c := range p.Candidates {
		if c.Addr >= 0x10000 && c.Addr < 0x11000 {
			t.Fatalf("main-arena prediction leaked thread-arena chunk: %#v", c)
		}
	}
	if p.Candidates[7].Source != "fastbin-lifo" || p.Candidates[7].Addr != 0x1120 {
		t.Fatalf("unexpected fastbin order: %#v", p.Candidates[7])
	}

	p = m.Predict(2, 0x18, 20)
	if len(p.Candidates) != 10 {
		t.Fatalf("unexpected thread-arena prediction: %#v", p)
	}
	for _, c := range p.Candidates {
		if c.Addr < 0x10000 || c.Addr >= 0x11000 {
			t.Fatalf("thread-arena prediction leaked main-arena chunk: %#v", c)
		}
	}
}

func TestArenaBinKeys(t *testing.T) {
	m := NewModel()
	m.SetRegions([]Region{
		{Start: 0x1000, End: 0x2000, Path: "[heap]"},
		{Start: 0x10000, End: 0x11000},
	})
	fillArena(t, m, 1, 0x1000, 100)
	fillArena(t, m, 2, 0x10000, 200)

	if k := m.freeLoc[0x1120]; k.Arena != 0x1000 || k.TID != 0 {
		t.Fatalf("main fastbin key = %#v", k)
	}
	if k := m.freeLoc[0x10120]; k.Arena != 0x10000 || k.TID != 0 {
		t.Fatalf("thread fastbin key = %#v", k)
	}
	if k := m.freeLoc[0x1000]; k.Arena != 0 || k.TID != 1 {
		t.Fatalf("main tcache key = %#v", k)
	}
	if m.tidArena[1] != 0x1000 || m.tidArena[2] != 0x10000 {
		t.Fatalf("tid arena hints = %#v", m.tidArena)
	}
}

func TestPredictMergedTid0AcrossArenas(t *testing.T) {
	m := NewModel()
	m.SetRegions([]Region{
		{Start: 0x1000, End: 0x2000, Path: "[heap]"},
		{Start: 0x10000, End: 0x11000},
	})
	fillArena(t, m, 1, 0x1000, 100)
	fillArena(t, m, 2, 0x10000, 200)
	p := m.Predict(0, 0x18, 30)
	if len(p.Candidates) != 20 {
		t.Fatalf("merged prediction count = %d", len(p.Candidates))
	}
	var mainCount, threadCount int
	for _, c := range p.Candidates {
		if c.Addr >= 0x1000 && c.Addr < 0x2000 {
			mainCount++
		}
		if c.Addr >= 0x10000 && c.Addr < 0x11000 {
			threadCount++
		}
	}
	if mainCount != 10 || threadCount != 10 {
		t.Fatalf("merged prediction split main=%d thread=%d", mainCount, threadCount)
	}
}
