package heap

import (
	"sort"
	"time"
)

// Baseline is a labeled heap-analysis snapshot.
type Baseline struct {
	Label    string    `json:"label,omitempty"`
	Captured time.Time `json:"captured"`
	Profile  Profile   `json:"profile"`
	Stats    Stats     `json:"stats"`
	Analysis Analysis  `json:"analysis"`
}

// SizeClassDelta is the change for one glibc chunk size.
type SizeClassDelta struct {
	ChunkSize  uint64 `json:"chunk_size"`
	LiveDelta  int    `json:"live_delta"`
	FreedDelta int    `json:"freed_delta"`
	BytesDelta int64  `json:"bytes_delta"`
}

// ReuseDelta compares how often an address was reused.
type ReuseDelta struct {
	Addr          uint64 `json:"addr"`
	BaselineCount int    `json:"baseline_count"`
	CurrentCount  int    `json:"current_count"`
	Delta         int    `json:"delta"`
}

// Diff compares a baseline with the current heap state.
type Diff struct {
	Baseline    Baseline         `json:"baseline"`
	Current     Baseline         `json:"current"`
	LiveDelta   int              `json:"live_delta"`
	FreedDelta  int              `json:"freed_delta"`
	SizeClasses []SizeClassDelta `json:"size_classes"`
	GapsAdded   []Gap            `json:"gaps_added"`
	GapsRemoved []Gap            `json:"gaps_removed"`
	Reuses      []ReuseDelta     `json:"reuses"`
	Notes       []string         `json:"notes,omitempty"`
}

// CaptureBaseline snapshots the current model without holding the model lock
// across Stats/Analyze calls.
func (m *Model) CaptureBaseline(label string) Baseline {
	return Baseline{
		Label:    label,
		Captured: time.Now(),
		Profile:  m.Profile(),
		Stats:    m.Stats(),
		Analysis: m.Analyze(),
	}
}

// DiffBaselines compares two snapshots.
func DiffBaselines(base, current Baseline) Diff {
	d := Diff{
		Baseline:   base,
		Current:    current,
		LiveDelta:  current.Stats.Live - base.Stats.Live,
		FreedDelta: current.Stats.Freed - base.Stats.Freed,
	}

	classMap := make(map[uint64]SizeClassDelta)
	for _, c := range base.Analysis.SizeClasses {
		classMap[c.ChunkSize] = SizeClassDelta{ChunkSize: c.ChunkSize, LiveDelta: -c.Live, FreedDelta: -c.Freed, BytesDelta: -int64(c.Bytes)}
	}
	for _, c := range current.Analysis.SizeClasses {
		x := classMap[c.ChunkSize]
		x.ChunkSize = c.ChunkSize
		x.LiveDelta += c.Live
		x.FreedDelta += c.Freed
		x.BytesDelta += int64(c.Bytes)
		classMap[c.ChunkSize] = x
	}
	for _, x := range classMap {
		if x.LiveDelta != 0 || x.FreedDelta != 0 || x.BytesDelta != 0 {
			d.SizeClasses = append(d.SizeClasses, x)
		}
	}
	sort.Slice(d.SizeClasses, func(i, j int) bool { return d.SizeClasses[i].ChunkSize < d.SizeClasses[j].ChunkSize })

	baseGaps := make(map[[2]uint64]Gap)
	for _, g := range base.Analysis.Gaps {
		baseGaps[[2]uint64{g.Start, g.End}] = g
	}
	curGaps := make(map[[2]uint64]Gap)
	for _, g := range current.Analysis.Gaps {
		curGaps[[2]uint64{g.Start, g.End}] = g
	}
	for key, g := range curGaps {
		if _, ok := baseGaps[key]; !ok {
			d.GapsAdded = append(d.GapsAdded, g)
		}
	}
	for key, g := range baseGaps {
		if _, ok := curGaps[key]; !ok {
			d.GapsRemoved = append(d.GapsRemoved, g)
		}
	}
	sort.Slice(d.GapsAdded, func(i, j int) bool { return d.GapsAdded[i].Start < d.GapsAdded[j].Start })
	sort.Slice(d.GapsRemoved, func(i, j int) bool { return d.GapsRemoved[i].Start < d.GapsRemoved[j].Start })

	reuseMap := make(map[uint64]ReuseDelta)
	for _, r := range base.Analysis.Reuses {
		reuseMap[r.Addr] = ReuseDelta{Addr: r.Addr, BaselineCount: r.Count, Delta: -r.Count}
	}
	for _, r := range current.Analysis.Reuses {
		x := reuseMap[r.Addr]
		x.Addr = r.Addr
		x.CurrentCount = r.Count
		x.Delta += r.Count
		reuseMap[r.Addr] = x
	}
	for _, x := range reuseMap {
		if x.Delta != 0 {
			d.Reuses = append(d.Reuses, x)
		}
	}
	sort.Slice(d.Reuses, func(i, j int) bool { return d.Reuses[i].Addr < d.Reuses[j].Addr })

	if base.Profile.Version != current.Profile.Version {
		d.Notes = append(d.Notes, "allocator profile changed between baseline and current")
	}
	return d
}
