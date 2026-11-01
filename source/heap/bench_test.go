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

func BenchmarkScoreWindow(b *testing.B) {
	windows := make([]TimelineWindow, 0, 20)
	for i := 0; i < 20; i++ {
		windows = append(windows, TimelineWindow{
			ID:     uint64(i + 1),
			Events: 100,
			Allocs: 60,
			Frees:  40,
			Live:   64,
			Freed:  20,
			Rates: RateWindow{
				Events:      400,
				Allocs:      240,
				Frees:       160,
				Reallocs:    4,
				BytesPerSec: 8192,
			},
			Reuse: ReuseWindow{Count: 8, SameClass: 4},
			Classes: []ClassWindow{
				{ChunkSize: 0x20, Live: 48, LiveShare: 0.75, ByteShare: 0.5},
				{ChunkSize: 0x40, Live: 16, LiveShare: 0.25, ByteShare: 0.5},
			},
		})
	}
	baseline := BuildBaseline("bench", "bench", DefaultProfile(), windows)
	w := windows[len(windows)-1]
	cfg := DefaultAnomalyConfig()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScoreWindow(w, baseline, cfg)
	}
}

func BenchmarkTimelineObserve(b *testing.B) {
	tl := NewTimeline(DefaultTimelineConfig())
	ev := core.Event{PID: 1, TID: 1, Addr: 0x10000, Size: 0x20, ReqSize: 0x18}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.Timestamp = time.Unix(0, int64(i*2))
		ev.Type = core.EventAlloc
		tl.Observe(ev)
		ev.Type = core.EventFree
		tl.Observe(ev)
	}
}
