package detect

import (
	"testing"
	"time"

	"gofengshui/core"
	"gofengshui/heap"
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

func TestDedupIncludesSyscall(t *testing.T) {
	e := New(nil)
	now := time.Now()
	e.Observe(core.Event{Timestamp: now, Type: core.EventAlloc, Addr: 0x1000, Size: 0x40, ReqSize: 0x30, TID: 1, Arg2: uint64(core.OpMalloc)})
	e.Observe(core.Event{Timestamp: now, Type: core.EventFree, Addr: 0x1000, Size: 0x40, TID: 1})
	first := e.Observe(core.Event{Timestamp: now, Type: core.EventMemAccess, Addr: 0x1000, Size: 4, TID: 1, Arg1: core.SysOpenat, Arg2: 2})
	second := e.Observe(core.Event{Timestamp: now, Type: core.EventMemAccess, Addr: 0x1000, Size: 4, TID: 1, Arg1: core.SysExecve, Arg2: 2})
	if len(first) != 1 || first[0].ID != "D2" {
		t.Fatalf("first findings = %v", first)
	}
	if len(second) != 1 || second[0].ID != "D2" {
		t.Fatalf("second findings = %v", second)
	}
}

func TestEngineTimeline(t *testing.T) {
	e := New(nil)
	now := time.Now()
	e.Observe(core.Event{Timestamp: now, Type: core.EventAlloc, Addr: 0x1000, Size: 0x40, ReqSize: 0x30, TID: 1, Arg2: uint64(core.OpMalloc)})
	e.Observe(core.Event{Timestamp: now.Add(time.Millisecond), Type: core.EventFree, Addr: 0x1000, Size: 0x40, TID: 1})
	windows := e.Timeline().Snapshot()
	if len(windows) != 1 || windows[0].Events != 2 || windows[0].Live != 0 || windows[0].Frees != 1 {
		t.Fatalf("unexpected timeline windows: %#v", windows)
	}
}

func TestEngineEmitsD10(t *testing.T) {
	base := heap.TimelineWindow{
		ID: 1, Live: 1,
		Classes: []heap.ClassWindow{{ChunkSize: 0x20, Live: 1, LiveBytes: 0x20, LiveShare: 1, ByteShare: 1}},
		Rates:   heap.RateWindow{Events: 1, Allocs: 1},
	}
	baseline := heap.BuildBaseline("key", "test", heap.DefaultProfile(), []heap.TimelineWindow{base})
	e := New(nil)
	e.Timeline().SetConfig(heap.TimelineConfig{WindowEvents: 1, WindowMS: 1000, MaxWindows: 8})
	scoreCfg := heap.DefaultAnomalyConfig()
	scoreCfg.MinHistogramLive = 0
	tr := e.EnableAnomaly(AnomalyTrackerConfig{WarmupWindows: 1, Score: scoreCfg})
	tr.SetBaseline(&baseline)

	findings := e.Observe(core.Event{
		Timestamp: time.Now(), Type: core.EventAlloc, TID: 1,
		Addr: 0x1000, Size: 0x40, ReqSize: 0x38, Arg2: uint64(core.OpMalloc),
	})
	var found bool
	for _, f := range findings {
		if f.ID == "D10" {
			found = true
		}
	}
	if !found {
		t.Fatalf("D10 not emitted: %#v", findings)
	}
	extra := e.Add(core.Finding{ID: "D6", Timestamp: time.Now()})
	if len(extra) == 0 || extra[0].ID != "D11" {
		t.Fatalf("D11 not correlated: %#v", extra)
	}
}
