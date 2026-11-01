package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gofengshui/core"
	"gofengshui/heap"
)

func TestLoadEventsAndTimeline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	base := time.Unix(1000, 0)
	events := []core.Event{
		{Timestamp: base, Type: core.EventAlloc, PID: 1, TID: 1, Addr: 0x1000, Size: 0x20, ReqSize: 0x18},
		{Timestamp: base.Add(time.Millisecond), Type: core.EventFree, PID: 1, TID: 1, Addr: 0x1000, Size: 0x20},
	}
	for i, ev := range events {
		frame := map[string]any{
			"v": 1, "type": "event", "session": "s1", "seq": i + 1,
			"event": map[string]any{"kind": "event", "event": ev},
		}
		if err := enc.Encode(frame); err != nil {
			t.Fatal(err)
		}
	}
	finding := map[string]any{
		"v": 1, "type": "event", "session": "s1", "seq": 3,
		"event": map[string]any{"kind": "finding", "finding": map[string]any{"id": "D1"}},
	}
	if err := enc.Encode(finding); err != nil {
		t.Fatal(err)
	}
	raw := core.Event{Timestamp: base.Add(2 * time.Millisecond), Type: core.EventAlloc, PID: 1, TID: 1, Addr: 0x1100, Size: 0x40, ReqSize: 0x38}
	if err := enc.Encode(raw); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 3 {
		t.Fatalf("loaded events: got %d want 3", len(loaded))
	}
	tl, count, err := TimelineFile(path, heap.TimelineConfig{WindowEvents: 100, WindowMS: 1000, MaxWindows: 8})
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("replayed events: got %d want 3", count)
	}
	windows := tl.Windows()
	if len(windows) != 1 || windows[0].Allocs != 2 || windows[0].Frees != 1 || windows[0].Live != 1 {
		t.Fatalf("unexpected timeline: %#v", windows)
	}
}
