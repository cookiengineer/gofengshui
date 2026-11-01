package heap

import (
	"encoding/binary"
	"math"
	"sort"

	"gofengshui/core"
)

// ContentMetrics summarizes sampled chunk bytes.
type ContentMetrics struct {
	Samples        int     `json:"samples"`
	Bytes          int     `json:"bytes"`
	Entropy        float64 `json:"entropy"`
	PrintableRatio float64 `json:"printable_ratio"`
	PointerRatio   float64 `json:"pointer_ratio"`
	ZeroRatio      float64 `json:"zero_ratio"`
	TopQwordRatio  float64 `json:"top_qword_ratio"`
}

// ContentSummary is the aggregate content view of one window.
type ContentSummary struct {
	ContentMetrics
}

// ContentCandidate is one chunk selected for content sampling.
type ContentCandidate struct {
	Addr  uint64 `json:"addr"`
	Size  uint64 `json:"size"`
	Class uint64 `json:"class"`
	TID   uint32 `json:"tid"`
	Live  bool   `json:"live"`
}

// AnalyzeContent computes byte and qword statistics for one sampled chunk.
func AnalyzeContent(data []byte, regions []Region) ContentMetrics {
	m := ContentMetrics{Bytes: len(data)}
	if len(data) == 0 {
		return m
	}
	var counts [256]int
	printable := 0
	zeros := 0
	for _, b := range data {
		counts[b]++
		if b == 0 {
			zeros++
		}
		if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(data))
		m.Entropy -= p * math.Log2(p)
	}
	m.PrintableRatio = float64(printable) / float64(len(data))
	m.ZeroRatio = float64(zeros) / float64(len(data))

	qwords := len(data) / 8
	if qwords > 0 {
		freq := make(map[uint64]int, qwords)
		pointers := 0
		for off := 0; off+8 <= len(data); off += 8 {
			v := binary.LittleEndian.Uint64(data[off:])
			freq[v]++
			if regionMapped(regions, v) {
				pointers++
			}
		}
		top := 0
		for _, count := range freq {
			if count > top {
				top = count
			}
		}
		m.PointerRatio = float64(pointers) / float64(qwords)
		m.TopQwordRatio = float64(top) / float64(qwords)
	}
	return m
}

// AggregateContent combines per-chunk metrics and marks the sample count.
func AggregateContent(metrics []ContentMetrics) ContentSummary {
	var out ContentSummary
	var totalBytes int
	for _, m := range metrics {
		out.Samples++
		totalBytes += m.Bytes
	}
	out.Bytes = totalBytes
	if totalBytes == 0 {
		return out
	}
	for _, m := range metrics {
		weight := float64(m.Bytes) / float64(totalBytes)
		out.Entropy += m.Entropy * weight
		out.PrintableRatio += m.PrintableRatio * weight
		out.PointerRatio += m.PointerRatio * weight
		out.ZeroRatio += m.ZeroRatio * weight
		out.TopQwordRatio += m.TopQwordRatio * weight
	}
	return out
}

// MergeContent merges two summaries by byte weight.
func MergeContent(a, b *ContentSummary) ContentSummary {
	if a == nil {
		if b == nil {
			return ContentSummary{}
		}
		return *b
	}
	if b == nil {
		return *a
	}
	out := ContentSummary{}
	out.Samples = a.Samples + b.Samples
	out.Bytes = a.Bytes + b.Bytes
	if out.Bytes == 0 {
		return out
	}
	wa := float64(a.Bytes) / float64(out.Bytes)
	wb := float64(b.Bytes) / float64(out.Bytes)
	out.Entropy = a.Entropy*wa + b.Entropy*wb
	out.PrintableRatio = a.PrintableRatio*wa + b.PrintableRatio*wb
	out.PointerRatio = a.PointerRatio*wa + b.PointerRatio*wb
	out.ZeroRatio = a.ZeroRatio*wa + b.ZeroRatio*wb
	out.TopQwordRatio = a.TopQwordRatio*wa + b.TopQwordRatio*wb
	return out
}

// SelectContentCandidates takes a bounded, class-stratified sample.
func SelectContentCandidates(allocs []core.Allocation, tombs []Tombstone, limit int) []ContentCandidate {
	if limit <= 0 {
		return nil
	}
	byClass := make(map[uint64][]ContentCandidate)
	add := func(addr, size uint64, tid uint32, live bool) {
		if addr == 0 || size == 0 {
			return
		}
		class := size
		byClass[class] = append(byClass[class], ContentCandidate{
			Addr: addr, Size: size, Class: class, TID: tid, Live: live,
		})
	}
	for _, a := range allocs {
		add(a.Addr, a.ChunkSize, a.TID, a.State == core.StateLive)
	}
	for _, t := range tombs {
		add(t.Addr, t.Size, t.TID, false)
	}

	classes := make([]uint64, 0, len(byClass))
	for class := range byClass {
		classes = append(classes, class)
		sort.Slice(byClass[class], func(i, j int) bool {
			return byClass[class][i].Addr < byClass[class][j].Addr
		})
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })

	var out []ContentCandidate
	for len(out) < limit {
		progress := false
		for _, class := range classes {
			if len(out) >= limit {
				break
			}
			list := byClass[class]
			if len(list) == 0 {
				continue
			}
			out = append(out, list[0])
			byClass[class] = list[1:]
			progress = true
		}
		if !progress {
			break
		}
	}
	return out
}
