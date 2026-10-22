package heap

import (
	"sort"

	"gofengshui/source/core"
)

// SizeClass summarizes allocations with the same chunk size.
type SizeClass struct {
	ChunkSize uint64 `json:"chunk_size"`
	Live      int    `json:"live"`
	Freed     int    `json:"freed"`
	Bytes     uint64 `json:"bytes"`
}

// Gap is an address-space gap between two live allocations.
type Gap struct {
	Start   uint64 `json:"start"`
	End     uint64 `json:"end"`
	Size    uint64 `json:"size"`
	LeftID  uint64 `json:"left_id,omitempty"`
	RightID uint64 `json:"right_id,omitempty"`
}

// Reuse records address reuse observed by the timeline.
type Reuse struct {
	Addr  uint64 `json:"addr"`
	Count int    `json:"count"`
}

// Analysis is a heap-feng-shui oriented summary.
type Analysis struct {
	Profile     Profile           `json:"profile"`
	Live        int               `json:"live"`
	Freed       int               `json:"freed"`
	SizeClasses []SizeClass       `json:"size_classes"`
	LargestFree []Tombstone       `json:"largest_free"`
	LargestLive []core.Allocation `json:"largest_live"`
	Gaps        []Gap             `json:"gaps"`
	Reuses      []Reuse           `json:"reuses"`
}

// Analyze computes size classes, large allocations, address gaps and reuse.
func (m *Model) Analyze() Analysis {
	m.mu.RLock()
	defer m.mu.RUnlock()

	a := Analysis{Profile: m.profile}
	classes := make(map[uint64]*SizeClass)
	var live []core.Allocation
	for _, al := range m.allocs {
		size := al.ChunkSize
		if size == 0 {
			size = al.ReqSize
		}
		c := classes[size]
		if c == nil {
			c = &SizeClass{ChunkSize: size}
			classes[size] = c
		}
		if al.State == core.StateLive {
			a.Live++
			c.Live++
			c.Bytes += size
			live = append(live, *al)
		} else {
			a.Freed++
			c.Freed++
		}
	}
	for _, c := range classes {
		a.SizeClasses = append(a.SizeClasses, *c)
	}
	sort.Slice(a.SizeClasses, func(i, j int) bool {
		return a.SizeClasses[i].ChunkSize < a.SizeClasses[j].ChunkSize
	})

	largestLive := append([]core.Allocation(nil), live...)
	sort.Slice(largestLive, func(i, j int) bool { return largestLive[i].ChunkSize > largestLive[j].ChunkSize })
	if len(largestLive) > 16 {
		largestLive = largestLive[:16]
	}
	a.LargestLive = largestLive

	for _, t := range m.tombs {
		a.LargestFree = append(a.LargestFree, t)
	}
	sort.Slice(a.LargestFree, func(i, j int) bool {
		return a.LargestFree[i].Size > a.LargestFree[j].Size
	})
	if len(a.LargestFree) > 16 {
		a.LargestFree = a.LargestFree[:16]
	}

	sort.Slice(live, func(i, j int) bool { return live[i].Addr < live[j].Addr })
	for i := 0; i+1 < len(live); i++ {
		end := live[i].End()
		if live[i+1].Addr > end {
			a.Gaps = append(a.Gaps, Gap{
				Start: end, End: live[i+1].Addr, Size: live[i+1].Addr - end,
				LeftID: live[i].ID, RightID: live[i+1].ID,
			})
		}
	}
	sort.Slice(a.Gaps, func(i, j int) bool { return a.Gaps[i].Size > a.Gaps[j].Size })
	if len(a.Gaps) > 16 {
		a.Gaps = a.Gaps[:16]
	}

	for addr, n := range m.reuses {
		if n > 1 {
			a.Reuses = append(a.Reuses, Reuse{Addr: addr, Count: n})
		}
	}
	sort.Slice(a.Reuses, func(i, j int) bool { return a.Reuses[i].Count > a.Reuses[j].Count })
	if len(a.Reuses) > 16 {
		a.Reuses = a.Reuses[:16]
	}
	return a
}
