package heap

import (
	"encoding/binary"
	"testing"

	"gofengshui/core"
)

func TestAnalyzeContentPatterns(t *testing.T) {
	zeros := make([]byte, 64)
	m := AnalyzeContent(zeros, nil)
	if m.Entropy != 0 || m.ZeroRatio != 1 || m.PrintableRatio != 0 {
		t.Fatalf("unexpected zero-buffer metrics: %#v", m)
	}

	data := make([]byte, 32)
	for i := 0; i < len(data); i += 8 {
		binary.LittleEndian.PutUint64(data[i:], 0x1000+uint64(i))
	}
	regions := []Region{{Start: 0x1000, End: 0x2000}}
	ptr := AnalyzeContent(data, regions)
	if ptr.PointerRatio != 1 {
		t.Fatalf("pointer ratio: got %f want 1", ptr.PointerRatio)
	}
	if ptr.TopQwordRatio == 0 || ptr.Entropy == 0 {
		t.Fatalf("unexpected pointer metrics: %#v", ptr)
	}
}

func TestAggregateAndMergeContent(t *testing.T) {
	a := ContentMetrics{Samples: 1, Bytes: 8, Entropy: 1, PointerRatio: 0.2}
	b := ContentMetrics{Samples: 1, Bytes: 24, Entropy: 3, PointerRatio: 0.6}
	summary := AggregateContent([]ContentMetrics{a, b})
	if summary.Samples != 2 || summary.Bytes != 32 {
		t.Fatalf("unexpected aggregate: %#v", summary)
	}
	if summary.Entropy < 1 || summary.Entropy > 3 {
		t.Fatalf("unexpected entropy: %f", summary.Entropy)
	}
	merged := MergeContent(&summary, &ContentSummary{ContentMetrics: ContentMetrics{Bytes: 32, Entropy: 3}})
	if merged.Bytes != 64 || merged.Samples != 2 {
		t.Fatalf("unexpected merge: %#v", merged)
	}
}

func TestSelectContentCandidates(t *testing.T) {
	allocs := []core.Allocation{
		{Addr: 0x1000, ChunkSize: 0x20, TID: 1, State: core.StateLive},
		{Addr: 0x1020, ChunkSize: 0x20, TID: 1, State: core.StateLive},
		{Addr: 0x2000, ChunkSize: 0x40, TID: 2, State: core.StateFreed},
	}
	tombs := []Tombstone{{Addr: 0x3000, Size: 0x40, TID: 2}}
	got := SelectContentCandidates(allocs, tombs, 3)
	if len(got) != 3 {
		t.Fatalf("candidates: got %d want 3", len(got))
	}
	seen := map[uint64]bool{}
	for _, c := range got {
		seen[c.Class] = true
	}
	if !seen[0x20] || !seen[0x40] {
		t.Fatalf("classes not stratified: %#v", got)
	}
}

func TestContentBaselineFromSummaries(t *testing.T) {
	if got := ContentBaselineFromSummaries(nil); got.Samples.Count != 0 {
		t.Fatalf("empty summaries: %#v", got)
	}
	summaries := []ContentSummary{
		{ContentMetrics: ContentMetrics{Samples: 8, Bytes: 1024, Entropy: 6, PrintableRatio: 0.2, PointerRatio: 0.1, ZeroRatio: 0.3, TopQwordRatio: 0.1}},
		{ContentMetrics: ContentMetrics{Samples: 16, Bytes: 2048, Entropy: 8, PrintableRatio: 0.4, PointerRatio: 0.3, ZeroRatio: 0.1, TopQwordRatio: 0.2}},
		{ContentMetrics: ContentMetrics{Samples: 12, Bytes: 1536, Entropy: 7, PrintableRatio: 0.3, PointerRatio: 0.2, ZeroRatio: 0.2, TopQwordRatio: 0.15}},
	}
	b := ContentBaselineFromSummaries(summaries)
	if b.Samples.Count != 3 || b.Samples.Median != 12 {
		t.Fatalf("unexpected samples stats: %#v", b.Samples)
	}
	if b.Entropy.Median != 7 || b.PrintableRatio.Median != 0.3 {
		t.Fatalf("unexpected content stats: %#v", b)
	}
	if b.PointerRatio.Min != 0.1 || b.PointerRatio.Max != 0.3 {
		t.Fatalf("unexpected pointer range: %#v", b.PointerRatio)
	}
}

func TestContentBaselineAndScore(t *testing.T) {
	var windows []TimelineWindow
	for i := 1; i <= 6; i++ {
		w := testTimelineWindow(uint64(i), map[uint64]int{0x20: 8, 0x40: 2}, 20, 10, 0, 0, nil)
		w.Content = &ContentSummary{ContentMetrics: ContentMetrics{
			Samples: 16, Bytes: 4096, Entropy: 7.5, PrintableRatio: 0.4,
			PointerRatio: 0.1, ZeroRatio: 0.1, TopQwordRatio: 0.05,
		}}
		windows = append(windows, w)
	}
	b := BuildBaseline("key", "content", DefaultProfile(), windows)
	if b.Content.Samples.Count != 6 || b.Content.Entropy.Median != 7.5 {
		t.Fatalf("unexpected content baseline: %#v", b.Content)
	}
	bad := testTimelineWindow(7, map[uint64]int{0x20: 8, 0x40: 2}, 20, 10, 0, 0, nil)
	bad.Content = &ContentSummary{ContentMetrics: ContentMetrics{
		Samples: 16, Bytes: 4096, Entropy: 0.2, PrintableRatio: 0.01,
		PointerRatio: 0.9, ZeroRatio: 0.8, TopQwordRatio: 0.9,
	}}
	score := ScoreWindow(bad, b, DefaultAnomalyConfig())
	if score.Components["content"] == 0 {
		t.Fatalf("content anomaly not scored: %#v", score)
	}
}
