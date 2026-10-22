package heap

import (
	"testing"
	"time"

	"gofengshui/core"
)

func BenchmarkApplyAllocFree(b *testing.B) {
	m := NewModel()
	ev := core.Event{PID: 1, TID: 1, Addr: 0x10000, Size: 0x20, ReqSize: 0x18}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.Timestamp = time.Unix(0, int64(i*2))
		ev.Type = core.EventAlloc
		m.Apply(ev)
		ev.Type = core.EventFree
		m.Apply(ev)
	}
}

func BenchmarkPredict(b *testing.B) {
	m := NewModel()
	for i := 0; i < 7; i++ {
		addr := uint64(0x10000 + i*0x20)
		m.Apply(evAt(core.EventAlloc, 1, addr, 0x20, int64(i)))
		m.Apply(evAt(core.EventFree, 1, addr, 0x20, int64(10+i)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Predict(1, 0x18, 16)
	}
}

func BenchmarkAnalyze(b *testing.B) {
	m := NewModel()
	for i := 0; i < 1000; i++ {
		addr := uint64(0x100000 + i*0x40)
		m.Apply(evAt(core.EventAlloc, 1, addr, 0x40, int64(i)))
		if i%2 == 0 {
			m.Apply(evAt(core.EventFree, 1, addr, 0x40, int64(2000+i)))
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Analyze()
	}
}

func BenchmarkCheckAccess(b *testing.B) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x10000, 0x40, 1))
	m.Apply(evAt(core.EventFree, 1, 0x10000, 0x40, 2))
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.CheckAccess(0x10000, 8, 1, now)
	}
}
