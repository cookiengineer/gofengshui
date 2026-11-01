package heap

import (
	"testing"
	"time"

	"gofengshui/core"
)

func twev(at time.Time, typ core.EventType, addr, size, req uint64, tid uint32) core.Event {
	return core.Event{
		Timestamp: at, Type: typ, PID: 1, TID: tid,
		Addr: addr, Size: size, ReqSize: req, Comm: "test",
	}
}

func classBySize(classes []ClassWindow, size uint64) (ClassWindow, bool) {
	for _, c := range classes {
		if c.ChunkSize == size {
			return c, true
		}
	}
	return ClassWindow{}, false
}

func TestTimelineHistogram(t *testing.T) {
	base := time.Unix(1000, 0)
	tl := NewTimeline(TimelineConfig{WindowEvents: 16, WindowMS: 1000, MaxWindows: 8})

	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))
	tl.Observe(twev(base.Add(time.Millisecond), core.EventAlloc, 0x1100, 0x40, 0x38, 2))
	tl.Observe(twev(base.Add(2*time.Millisecond), core.EventFree, 0x1000, 0x20, 0, 1))

	windows := tl.Flush()
	if len(windows) != 1 {
		t.Fatalf("windows: got %d want 1", len(windows))
	}
	w := windows[0]
	if w.Events != 3 || w.Allocs != 2 || w.Frees != 1 || w.Live != 1 {
		t.Fatalf("unexpected window counters: %#v", w)
	}
	small, ok := classBySize(w.Classes, 0x20)
	if !ok || small.Live != 0 || small.Freed != 1 || small.Alloc != 1 {
		t.Fatalf("unexpected 0x20 class: %#v", small)
	}
	large, ok := classBySize(w.Classes, 0x40)
	if !ok || large.Live != 1 || large.LiveBytes != 0x40 || large.LiveShare != 1 {
		t.Fatalf("unexpected 0x40 class: %#v", large)
	}
	if len(w.Threads) != 2 {
		t.Fatalf("threads: got %d want 2", len(w.Threads))
	}
}

func TestTimelineEventWindow(t *testing.T) {
	base := time.Unix(1000, 0)
	tl := NewTimeline(TimelineConfig{WindowEvents: 2, WindowMS: 1000, MaxWindows: 8})

	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))
	closed := tl.Observe(twev(base, core.EventAlloc, 0x1100, 0x20, 0x18, 1))

	if len(closed) != 1 || closed[0].Events != 2 || closed[0].Trigger != "events" {
		t.Fatalf("unexpected closed window: %#v", closed)
	}
	tl.Observe(twev(base, core.EventAlloc, 0x1200, 0x20, 0x18, 1))
	snap := tl.Snapshot()
	if len(snap) != 2 || snap[1].Trigger != "current" || snap[1].Events != 1 {
		t.Fatalf("unexpected snapshot: %#v", snap)
	}
}

func TestTimelineCompleted(t *testing.T) {
	base := time.Unix(1000, 0)
	tl := NewTimeline(TimelineConfig{WindowEvents: 2, WindowMS: 1000, MaxWindows: 8})
	if got := tl.Completed(); got != 0 {
		t.Fatalf("initial completed: got %d want 0", got)
	}
	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))
	if got := tl.Completed(); got != 0 {
		t.Fatalf("completed before close: got %d want 0", got)
	}
	tl.Observe(twev(base, core.EventAlloc, 0x1100, 0x20, 0x18, 1))
	if got := tl.Completed(); got != 1 {
		t.Fatalf("completed after close: got %d want 1", got)
	}
	tl.Observe(twev(base, core.EventAlloc, 0x1200, 0x20, 0x18, 1))
	tl.Flush()
	if got := tl.Completed(); got != 2 {
		t.Fatalf("completed after flush: got %d want 2", got)
	}
	tl.Reset()
	if got := tl.Completed(); got != 0 {
		t.Fatalf("completed after reset: got %d want 0", got)
	}
}

func TestTimelineTimeWindow(t *testing.T) {
	base := time.Unix(1000, 0)
	tl := NewTimeline(TimelineConfig{WindowEvents: 100, WindowMS: 10, MaxWindows: 8})

	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))
	closed := tl.Observe(twev(base.Add(20*time.Millisecond), core.EventAlloc, 0x1100, 0x20, 0x18, 1))

	if len(closed) != 1 || closed[0].Trigger != "time" || closed[0].Events != 1 {
		t.Fatalf("unexpected time window: %#v", closed)
	}
	snap := tl.Snapshot()
	if len(snap) != 2 || snap[1].Events != 1 {
		t.Fatalf("unexpected snapshot: %#v", snap)
	}
}

func TestTimelineRealloc(t *testing.T) {
	base := time.Unix(1000, 0)
	tl := NewTimeline(TimelineConfig{WindowEvents: 16, WindowMS: 1000, MaxWindows: 8})

	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))

	inPlace := twev(base, core.EventAlloc, 0x1000, 0x40, 0x38, 1)
	inPlace.Arg1 = 0x1000
	inPlace.Arg2 = uint64(core.OpRealloc)
	tl.Observe(inPlace)

	moved := twev(base, core.EventAlloc, 0x2000, 0x60, 0x58, 1)
	moved.Arg1 = 0x1000
	moved.Arg2 = uint64(core.OpRealloc)
	tl.Observe(moved)

	w := tl.Flush()[0]
	if w.Reallocs != 2 || w.Allocs != 3 || w.Frees != 1 || w.Live != 1 {
		t.Fatalf("unexpected realloc counters: %#v", w)
	}
	oldClass, ok := classBySize(w.Classes, 0x40)
	if !ok || oldClass.Freed != 1 || oldClass.Live != 0 {
		t.Fatalf("unexpected freed old class: %#v", oldClass)
	}
	newClass, ok := classBySize(w.Classes, 0x60)
	if !ok || newClass.Live != 1 || newClass.LiveBytes != 0x60 {
		t.Fatalf("unexpected moved class: %#v", newClass)
	}
}

func TestTimelineReuse(t *testing.T) {
	base := time.Unix(1000, 0)
	tl := NewTimeline(TimelineConfig{WindowEvents: 16, WindowMS: 1000, MaxWindows: 8})

	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))
	tl.Observe(twev(base, core.EventFree, 0x1000, 0x20, 0, 1))
	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))
	tl.Observe(twev(base, core.EventFree, 0x1000, 0x20, 0, 1))
	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x40, 0x38, 1))

	w := tl.Flush()[0]
	if w.Reuse.Count != 2 || w.Reuse.SameClass != 1 {
		t.Fatalf("unexpected reuse: %#v", w.Reuse)
	}
}

func TestReplayTimeline(t *testing.T) {
	base := time.Unix(1000, 0)
	events := []core.Event{
		twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1),
		twev(base.Add(time.Millisecond), core.EventFree, 0x1000, 0x20, 0, 1),
	}
	tl := ReplayTimeline(events, TimelineConfig{WindowEvents: 16, WindowMS: 1000, MaxWindows: 8})
	windows := tl.Windows()
	if len(windows) != 1 || windows[0].Allocs != 1 || windows[0].Frees != 1 {
		t.Fatalf("unexpected replay: %#v", windows)
	}
}

func TestTimelineLiveCarriesAcrossWindows(t *testing.T) {
	base := time.Unix(1000, 0)
	tl := NewTimeline(TimelineConfig{WindowEvents: 1, WindowMS: 1000, MaxWindows: 8})
	tl.Observe(twev(base, core.EventAlloc, 0x1000, 0x20, 0x18, 1))
	tl.Observe(twev(base.Add(time.Millisecond), core.EventAlloc, 0x1100, 0x40, 0x38, 1))
	tl.Observe(twev(base.Add(2*time.Millisecond), core.EventFree, 0x1000, 0x20, 0, 1))

	windows := tl.Windows()
	if len(windows) != 3 {
		t.Fatalf("windows: got %d want 3", len(windows))
	}
	second := windows[1]
	if second.Live != 2 {
		t.Fatalf("second window live: got %d want 2", second.Live)
	}
	if small, ok := classBySize(second.Classes, 0x20); !ok || small.Live != 1 {
		t.Fatalf("0x20 not carried into second window: %#v", second.Classes)
	}
	third := windows[2]
	if third.Live != 1 {
		t.Fatalf("third window live: got %d want 1", third.Live)
	}
	if small, ok := classBySize(third.Classes, 0x20); !ok || small.Live != 0 {
		t.Fatalf("0x20 still live in third window: %#v", third.Classes)
	}
	if large, ok := classBySize(third.Classes, 0x40); !ok || large.Live != 1 {
		t.Fatalf("0x40 missing in third window: %#v", third.Classes)
	}
}
