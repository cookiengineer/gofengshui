package heap

import (
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func testTimelineWindow(id uint64, live map[uint64]int, allocs, frees, reuse, same int, findings map[string]int) TimelineWindow {
	total := 0
	var totalBytes uint64
	var classes []ClassWindow
	for size, count := range live {
		total += count
		totalBytes += uint64(count) * size
		classes = append(classes, ClassWindow{
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
	sort.Slice(classes, func(i, j int) bool { return classes[i].ChunkSize < classes[j].ChunkSize })
	ts := time.Unix(1000+int64(id), 0)
	return TimelineWindow{
		ID: id, Trigger: "events",
		WallFrom: ts, WallTo: ts.Add(250 * time.Millisecond),
		Events: allocs + frees, Allocs: allocs, Frees: frees,
		Live: total, Freed: frees,
		Classes:  classes,
		Reuse:    ReuseWindow{Count: reuse, SameClass: same},
		Findings: findings,
		Rates: RateWindow{
			Events: float64(allocs + frees), Allocs: float64(allocs),
			Frees: float64(frees), BytesPerSec: float64(totalBytes),
		},
	}
}

func TestBuildBaselineAndScore(t *testing.T) {
	var windows []TimelineWindow
	for i := 1; i <= 8; i++ {
		windows = append(windows, testTimelineWindow(uint64(i), map[uint64]int{0x20: 8, 0x40: 2}, 20, 10, 0, 0, nil))
	}
	b := BuildBaseline("key", "test", DefaultProfile(), windows)
	if b.Windows != 8 || len(b.Classes) != 2 || len(b.Reference) != 2 {
		t.Fatalf("unexpected baseline: %#v", b)
	}
	var shares float64
	for _, r := range b.Reference {
		shares += r.LiveShare
	}
	if math.Abs(shares-1) > 1e-9 {
		t.Fatalf("reference shares sum to %f", shares)
	}

	cfg := DefaultAnomalyConfig()
	normal := testTimelineWindow(9, map[uint64]int{0x20: 8, 0x40: 2}, 20, 10, 0, 0, nil)
	normalScore := ScoreWindow(normal, b, cfg)
	if normalScore.Score >= cfg.Threshold {
		t.Fatalf("normal window scored %.2f: %#v", normalScore.Score, normalScore)
	}

	anomalous := testTimelineWindow(10, map[uint64]int{0x20: 40}, 200, 0, 30, 25, map[string]int{"D8": 1})
	badScore := ScoreWindow(anomalous, b, cfg)
	if badScore.Score <= normalScore.Score {
		t.Fatalf("anomalous %.2f <= normal %.2f", badScore.Score, normalScore.Score)
	}
	if badScore.Score < cfg.Threshold {
		t.Fatalf("anomalous window did not cross threshold: %#v", badScore)
	}
	if badScore.Components["histogram"] == 0 || badScore.Components["reuse"] == 0 ||
		badScore.Components["structural"] == 0 {
		t.Fatalf("missing anomaly components: %#v", badScore.Components)
	}
}

func TestScoreWindowSkipsSparseHistogram(t *testing.T) {
	var windows []TimelineWindow
	for i := 1; i <= 8; i++ {
		windows = append(windows, testTimelineWindow(uint64(i), map[uint64]int{0x20: 40, 0x40: 10}, 20, 10, 0, 0, nil))
	}
	b := BuildBaseline("key", "test", DefaultProfile(), windows)
	sparse := testTimelineWindow(9, map[uint64]int{0x40: 1}, 20, 10, 0, 0, nil)

	cfg := DefaultAnomalyConfig()
	if score := ScoreWindow(sparse, b, cfg); score.Components["histogram"] != 0 {
		t.Fatalf("sparse histogram was scored: %#v", score.Components)
	}

	cfg.MinHistogramLive = 0
	if score := ScoreWindow(sparse, b, cfg); score.Components["histogram"] == 0 {
		t.Fatalf("histogram was not scored with the guard disabled: %#v", score.Components)
	}
}

func TestContentScoreUsesScaleFloor(t *testing.T) {
	var windows []TimelineWindow
	for i := 1; i <= 8; i++ {
		w := testTimelineWindow(uint64(i), map[uint64]int{0x20: 8, 0x40: 2}, 20, 10, 0, 0, nil)
		w.Content = &ContentSummary{ContentMetrics: ContentMetrics{
			Samples: 16, Bytes: 4096, Entropy: 5, PrintableRatio: 0.2,
			PointerRatio: 0.1, ZeroRatio: 0.2, TopQwordRatio: 0.1,
		}}
		windows = append(windows, w)
	}
	b := BuildBaseline("key", "test", DefaultProfile(), windows)
	cfg := DefaultAnomalyConfig()

	small := testTimelineWindow(9, map[uint64]int{0x20: 8, 0x40: 2}, 20, 10, 0, 0, nil)
	small.Content = &ContentSummary{ContentMetrics: ContentMetrics{
		Samples: 16, Bytes: 4096, Entropy: 5, PrintableRatio: 0.5,
		PointerRatio: 0.1, ZeroRatio: 0.2, TopQwordRatio: 0.1,
	}}
	if score := ScoreWindow(small, b, cfg); score.Components["content"] >= 2 {
		t.Fatalf("small content shift scored too high: %#v", score.Components)
	}

	large := testTimelineWindow(10, map[uint64]int{0x20: 8, 0x40: 2}, 20, 10, 0, 0, nil)
	large.Content = &ContentSummary{ContentMetrics: ContentMetrics{
		Samples: 16, Bytes: 4096, Entropy: 5, PrintableRatio: 0.9,
		PointerRatio: 0.1, ZeroRatio: 0.2, TopQwordRatio: 0.1,
	}}
	if score := ScoreWindow(large, b, cfg); score.Components["content"] <= 1 {
		t.Fatalf("large content shift was suppressed: %#v", score.Components)
	}
}

func TestBaselineSaveLoad(t *testing.T) {
	windows := []TimelineWindow{
		testTimelineWindow(1, map[uint64]int{0x20: 4}, 8, 4, 0, 0, nil),
		testTimelineWindow(2, map[uint64]int{0x20: 4}, 8, 4, 0, 0, nil),
	}
	b := BuildBaseline("key", "label", DefaultProfile(), windows)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := SaveBaseline(path, b); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != b.Key || got.Windows != b.Windows || len(got.Reference) != len(b.Reference) {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}
