package detect

import (
	"testing"
	"time"

	"gofengshui/heap"
)

func trackerWindow(id uint64, live map[uint64]int, reuse int, findings map[string]int) heap.TimelineWindow {
	total := 0
	var totalBytes uint64
	var classes []heap.ClassWindow
	for size, count := range live {
		total += count
		totalBytes += uint64(count) * size
		classes = append(classes, heap.ClassWindow{
			ChunkSize: size, Live: count, LiveBytes: uint64(count) * size,
		})
	}
	for i := range classes {
		if total > 0 {
			classes[i].LiveShare = float64(classes[i].Live) / float64(total)
		}
		if totalBytes > 0 {
			classes[i].ByteShare = float64(classes[i].LiveBytes) / float64(totalBytes)
		}
	}
	ts := time.Unix(2000+int64(id), 0)
	return heap.TimelineWindow{
		ID: id, Trigger: "events", WallFrom: ts, WallTo: ts.Add(time.Second),
		Events: 20, Allocs: 20, Live: total, Classes: classes,
		Reuse:    heap.ReuseWindow{Count: reuse, SameClass: reuse},
		Rates:    heap.RateWindow{Events: 20, Allocs: 20, BytesPerSec: float64(totalBytes)},
		Findings: findings,
	}
}

func TestAnomalyTrackerWarmupAndScore(t *testing.T) {
	cfg := heap.DefaultAnomalyConfig()
	tr := NewAnomalyTracker(AnomalyTrackerConfig{
		Key: "test", Profile: heap.DefaultProfile(), WarmupWindows: 3, Score: cfg,
	})
	for i := 1; i <= 3; i++ {
		if score := tr.Observe(trackerWindow(uint64(i), map[uint64]int{0x20: 8, 0x40: 2}, 0, nil)); score != nil {
			t.Fatalf("unexpected score during warmup: %#v", score)
		}
	}
	if tr.Baseline() == nil {
		t.Fatal("baseline was not built")
	}
	score := tr.Observe(trackerWindow(4, map[uint64]int{0x20: 40}, 30, map[string]int{"D8": 1}))
	if score == nil || score.Score < cfg.Threshold {
		t.Fatalf("expected anomalous score, got %#v", score)
	}
	f := AnomalyFinding(trackerWindow(5, map[uint64]int{0x20: 40}, 30, nil), *score)
	if f.ID != "D10" || f.Severity == "info" {
		t.Fatalf("unexpected finding: %#v", f)
	}
	if tr.Last() == nil || len(tr.Recent()) != 1 {
		t.Fatalf("tracker did not retain scores: %#v", tr.Recent())
	}
	if score.Phase != "primitive" && score.Phase != "suspect" {
		t.Fatalf("unexpected phase: %#v", score)
	}
	if control, ok := tr.ControlFlow(); !ok || control.Phase != "control" {
		t.Fatalf("control-flow correlation failed: %#v %v", control, ok)
	}
}

func contentSummary(entropy, printable, pointer, zero, top float64) heap.ContentSummary {
	return heap.ContentSummary{ContentMetrics: heap.ContentMetrics{
		Samples: 16, Bytes: 4096, Entropy: entropy, PrintableRatio: printable,
		PointerRatio: pointer, ZeroRatio: zero, TopQwordRatio: top,
	}}
}

func TestAnomalyTrackerContentWarmup(t *testing.T) {
	cfg := heap.DefaultAnomalyConfig()
	tr := NewAnomalyTracker(AnomalyTrackerConfig{
		Key: "test", Profile: heap.DefaultProfile(), WarmupWindows: 3, Score: cfg,
	})
	tr.ObserveContent(contentSummary(7.5, 0.4, 0.1, 0.1, 0.05))
	for i := 1; i <= 3; i++ {
		tr.Observe(trackerWindow(uint64(i), map[uint64]int{0x20: 8, 0x40: 2}, 0, nil))
	}
	b := tr.Baseline()
	if b == nil || b.Content.Samples.Count != 1 || b.Content.Entropy.Median != 7.5 {
		t.Fatalf("content baseline not seeded from warmup: %#v", b)
	}
	bad := trackerWindow(4, map[uint64]int{0x20: 8, 0x40: 2}, 0, nil)
	bad.Content = &heap.ContentSummary{ContentMetrics: heap.ContentMetrics{
		Samples: 16, Bytes: 4096, Entropy: 0.2, PrintableRatio: 0.01,
		PointerRatio: 0.9, ZeroRatio: 0.8, TopQwordRatio: 0.9,
	}}
	score := tr.Observe(bad)
	if score == nil || score.Components["content"] == 0 {
		t.Fatalf("seeded content baseline was not used for scoring: %#v", score)
	}
}

func TestAnomalyTrackerContentSeedsEmptyBaseline(t *testing.T) {
	tr := NewAnomalyTracker(AnomalyTrackerConfig{
		WarmupWindows: 2, Score: heap.DefaultAnomalyConfig(),
	})
	tr.Observe(trackerWindow(1, map[uint64]int{0x20: 4}, 0, nil))
	tr.Observe(trackerWindow(2, map[uint64]int{0x20: 4}, 0, nil))
	if b := tr.Baseline(); b == nil || b.Content.Samples.Count != 0 {
		t.Fatalf("unexpected initial content baseline: %#v", b)
	}
	tr.ObserveContent(contentSummary(6, 0.3, 0.2, 0.1, 0.1))
	b := tr.Baseline()
	if b.Content.Samples.Count != 1 || b.Content.Entropy.Median != 6 {
		t.Fatalf("empty baseline not seeded: %#v", b.Content)
	}
	tr.ObserveContent(contentSummary(2, 0.9, 0.8, 0.7, 0.6))
	b = tr.Baseline()
	if b.Content.Samples.Count != 1 || b.Content.Entropy.Median != 6 {
		t.Fatalf("seed was not one-shot: %#v", b.Content)
	}
}

func TestAnomalyTrackerResetWarmup(t *testing.T) {
	tr := NewAnomalyTracker(AnomalyTrackerConfig{WarmupWindows: 2, Score: heap.DefaultAnomalyConfig()})
	tr.Observe(trackerWindow(1, map[uint64]int{0x20: 4}, 0, nil))
	tr.Observe(trackerWindow(2, map[uint64]int{0x20: 4}, 0, nil))
	if tr.Baseline() == nil {
		t.Fatal("baseline was not built")
	}
	tr.ResetWarmup()
	if tr.Baseline() != nil {
		t.Fatal("baseline survived reset")
	}
	if got, want := tr.Warmup(); got != 0 || want != 2 {
		t.Fatalf("warmup: got %d/%d", got, want)
	}
}
