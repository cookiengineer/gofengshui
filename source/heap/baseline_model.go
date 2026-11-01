package heap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"time"
)

// RobustStats is a median/MAD summary of one metric.
type RobustStats struct {
	Count  int     `json:"count"`
	Median float64 `json:"median"`
	MAD    float64 `json:"mad"`
	Min    float64 `json:"min,omitempty"`
	Max    float64 `json:"max,omitempty"`
}

// ClassBaseline summarizes one chunk-size class in a baseline.
type ClassBaseline struct {
	ChunkSize  uint64      `json:"chunk_size"`
	LiveShare  RobustStats `json:"live_share"`
	ByteShare  RobustStats `json:"byte_share"`
	LiveCount  RobustStats `json:"live_count"`
	AllocCount RobustStats `json:"alloc_count"`
}

// HistogramPoint is one normalized reference-histogram bucket.
type HistogramPoint struct {
	ChunkSize uint64  `json:"chunk_size"`
	LiveShare float64 `json:"live_share"`
	ByteShare float64 `json:"byte_share"`
}

// BaselineRates is the robust rate summary of a baseline.
type BaselineRates struct {
	Events      RobustStats `json:"events"`
	Allocs      RobustStats `json:"allocs"`
	Frees       RobustStats `json:"frees"`
	Reallocs    RobustStats `json:"reallocs"`
	BytesPerSec RobustStats `json:"bytes_per_sec"`
}

// BaselineCounts is the robust window-count summary of a baseline.
type BaselineCounts struct {
	Live           RobustStats `json:"live"`
	Freed          RobustStats `json:"freed"`
	ReuseCount     RobustStats `json:"reuse_count"`
	ReuseSameClass RobustStats `json:"reuse_same_class"`
}

// ContentBaseline is the robust content-metric summary of a baseline.
type ContentBaseline struct {
	Samples        RobustStats `json:"samples"`
	Entropy        RobustStats `json:"entropy"`
	PrintableRatio RobustStats `json:"printable_ratio"`
	PointerRatio   RobustStats `json:"pointer_ratio"`
	ZeroRatio      RobustStats `json:"zero_ratio"`
	TopQwordRatio  RobustStats `json:"top_qword_ratio"`
}

// BaselineModel is a learned or stored description of normal heap behavior.
type BaselineModel struct {
	Key       string           `json:"key,omitempty"`
	Label     string           `json:"label,omitempty"`
	Profile   Profile          `json:"profile"`
	Windows   int              `json:"windows"`
	Created   time.Time        `json:"created"`
	Rates     BaselineRates    `json:"rates"`
	Counts    BaselineCounts   `json:"counts"`
	Entropy   RobustStats      `json:"entropy"`
	Content   ContentBaseline  `json:"content"`
	Classes   []ClassBaseline  `json:"classes,omitempty"`
	Reference []HistogramPoint `json:"reference,omitempty"`
}

// BuildBaseline computes robust statistics from a set of windows.
func BuildBaseline(key, label string, p Profile, windows []TimelineWindow) BaselineModel {
	b := BaselineModel{
		Key:     key,
		Label:   label,
		Profile: p,
		Windows: len(windows),
		Created: time.Now(),
	}
	if len(windows) == 0 {
		return b
	}

	rateValues := struct {
		events, allocs, frees, reallocs, bytes []float64
	}{}
	countValues := struct {
		live, freed, reuse, same []float64
	}{}
	var entropyValues []float64
	var contentSummaries []ContentSummary

	classSet := make(map[uint64]bool)
	for _, w := range windows {
		for _, c := range w.Classes {
			classSet[c.ChunkSize] = true
		}
		rateValues.events = append(rateValues.events, w.Rates.Events)
		rateValues.allocs = append(rateValues.allocs, w.Rates.Allocs)
		rateValues.frees = append(rateValues.frees, w.Rates.Frees)
		rateValues.reallocs = append(rateValues.reallocs, w.Rates.Reallocs)
		rateValues.bytes = append(rateValues.bytes, w.Rates.BytesPerSec)
		countValues.live = append(countValues.live, float64(w.Live))
		countValues.freed = append(countValues.freed, float64(w.Freed))
		countValues.reuse = append(countValues.reuse, float64(w.Reuse.Count))
		countValues.same = append(countValues.same, float64(w.Reuse.SameClass))
		entropyValues = append(entropyValues, WindowEntropy(w))
		if w.Content != nil && w.Content.Samples > 0 {
			contentSummaries = append(contentSummaries, *w.Content)
		}
	}

	b.Rates = BaselineRates{
		Events:      robustStats(rateValues.events),
		Allocs:      robustStats(rateValues.allocs),
		Frees:       robustStats(rateValues.frees),
		Reallocs:    robustStats(rateValues.reallocs),
		BytesPerSec: robustStats(rateValues.bytes),
	}
	b.Counts = BaselineCounts{
		Live:           robustStats(countValues.live),
		Freed:          robustStats(countValues.freed),
		ReuseCount:     robustStats(countValues.reuse),
		ReuseSameClass: robustStats(countValues.same),
	}
	b.Entropy = robustStats(entropyValues)
	b.Content = ContentBaselineFromSummaries(contentSummaries)

	classes := make([]uint64, 0, len(classSet))
	for size := range classSet {
		classes = append(classes, size)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })

	b.Classes = make([]ClassBaseline, 0, len(classes))
	b.Reference = make([]HistogramPoint, 0, len(classes))
	var shareTotal, byteTotal float64
	for _, size := range classes {
		var liveShares, byteShares, liveCounts, allocCounts []float64
		for _, w := range windows {
			cw, ok := findClassWindow(w.Classes, size)
			if ok {
				liveShares = append(liveShares, cw.LiveShare)
				byteShares = append(byteShares, cw.ByteShare)
				liveCounts = append(liveCounts, float64(cw.Live))
				allocCounts = append(allocCounts, float64(cw.Alloc))
			} else {
				liveShares = append(liveShares, 0)
				byteShares = append(byteShares, 0)
				liveCounts = append(liveCounts, 0)
				allocCounts = append(allocCounts, 0)
			}
		}
		cb := ClassBaseline{
			ChunkSize:  size,
			LiveShare:  robustStats(liveShares),
			ByteShare:  robustStats(byteShares),
			LiveCount:  robustStats(liveCounts),
			AllocCount: robustStats(allocCounts),
		}
		b.Classes = append(b.Classes, cb)
		b.Reference = append(b.Reference, HistogramPoint{
			ChunkSize: size,
			LiveShare: cb.LiveShare.Median,
			ByteShare: cb.ByteShare.Median,
		})
		shareTotal += cb.LiveShare.Median
		byteTotal += cb.ByteShare.Median
	}

	if shareTotal > 0 {
		for i := range b.Reference {
			b.Reference[i].LiveShare /= shareTotal
		}
	} else if byteTotal > 0 {
		for i := range b.Reference {
			b.Reference[i].LiveShare = b.Reference[i].ByteShare / byteTotal
		}
	}
	if byteTotal > 0 {
		for i := range b.Reference {
			b.Reference[i].ByteShare /= byteTotal
		}
	}
	return b
}

// ContentBaselineFromSummaries computes robust content statistics from sampled
// summaries. It is also used to seed a baseline when content samples arrive
// after warmup windows have already closed.
func ContentBaselineFromSummaries(summaries []ContentSummary) ContentBaseline {
	if len(summaries) == 0 {
		return ContentBaseline{}
	}
	samples := make([]float64, 0, len(summaries))
	entropy := make([]float64, 0, len(summaries))
	printable := make([]float64, 0, len(summaries))
	pointer := make([]float64, 0, len(summaries))
	zero := make([]float64, 0, len(summaries))
	top := make([]float64, 0, len(summaries))
	for _, s := range summaries {
		samples = append(samples, float64(s.Samples))
		entropy = append(entropy, s.Entropy)
		printable = append(printable, s.PrintableRatio)
		pointer = append(pointer, s.PointerRatio)
		zero = append(zero, s.ZeroRatio)
		top = append(top, s.TopQwordRatio)
	}
	return ContentBaseline{
		Samples:        robustStats(samples),
		Entropy:        robustStats(entropy),
		PrintableRatio: robustStats(printable),
		PointerRatio:   robustStats(pointer),
		ZeroRatio:      robustStats(zero),
		TopQwordRatio:  robustStats(top),
	}
}

func findClassWindow(classes []ClassWindow, size uint64) (ClassWindow, bool) {
	for _, c := range classes {
		if c.ChunkSize == size {
			return c, true
		}
	}
	return ClassWindow{}, false
}

func robustStats(values []float64) RobustStats {
	if len(values) == 0 {
		return RobustStats{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	median := medianSorted(sorted)
	deviations := make([]float64, len(sorted))
	for i, v := range sorted {
		deviations[i] = math.Abs(v - median)
	}
	sort.Float64s(deviations)
	return RobustStats{
		Count:  len(values),
		Median: median,
		MAD:    medianSorted(deviations),
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
	}
}

func medianSorted(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// WindowEntropy returns the Shannon entropy of a window's live class shares.
func WindowEntropy(w TimelineWindow) float64 {
	var entropy float64
	for _, c := range w.Classes {
		if c.LiveShare <= 0 {
			continue
		}
		entropy -= c.LiveShare * math.Log2(c.LiveShare)
	}
	return entropy
}

// BaselineKey identifies an executable/profile pair for baseline storage.
func BaselineKey(exePath string, p Profile) string {
	h := sha256.New()
	if data, err := os.ReadFile(exePath); err == nil {
		_, _ = h.Write(data)
	} else {
		_, _ = h.Write([]byte(exePath))
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%s:%s", sum[:16], p.Version)
}

// SaveBaseline writes a baseline model as JSON.
func SaveBaseline(path string, b BaselineModel) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// LoadBaseline reads a baseline model from JSON.
func LoadBaseline(path string) (BaselineModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BaselineModel{}, err
	}
	var b BaselineModel
	if err := json.Unmarshal(data, &b); err != nil {
		return BaselineModel{}, err
	}
	return b, nil
}
