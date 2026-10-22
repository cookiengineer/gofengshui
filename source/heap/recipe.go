package heap

import (
	"fmt"
	"sort"

	"gofengshui/source/core"
)

// RecipeStep is one suggested allocator action.
type RecipeStep struct {
	Action     string `json:"action"`
	Size       uint64 `json:"size,omitempty"`
	Expected   uint64 `json:"expected_addr,omitempty"`
	TID        uint32 `json:"tid,omitempty"`
	Source     string `json:"source,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Recipe is an advisory heap-feng-shui plan for a target size and count.
type Recipe struct {
	TID            uint32            `json:"tid"`
	RequestSize    uint64            `json:"request_size"`
	ChunkSize      uint64            `json:"chunk_size"`
	Count          int               `json:"count"`
	Profile        Profile           `json:"profile"`
	Reclaim        []PredictedChunk  `json:"reclaim"`
	LiveCandidates []core.Allocation `json:"live_candidates,omitempty"`
	Missing        int               `json:"missing"`
	Steps          []RecipeStep      `json:"steps"`
	Notes          []string          `json:"notes,omitempty"`
}

// BuildRecipe returns an ordered allocation plan using the current free-list
// model. Addresses are predictions, not guarantees.
func (m *Model) BuildRecipe(tid uint32, reqSize uint64, count int) Recipe {
	if count <= 0 {
		count = 1
	}
	if count > 256 {
		count = 256
	}
	if reqSize == 0 {
		reqSize = 1
	}
	p := m.Predict(tid, reqSize, count)
	r := Recipe{
		TID: tid, RequestSize: reqSize, ChunkSize: p.ChunkSize,
		Count: count, Profile: m.Profile(), Reclaim: p.Candidates,
		Notes: append([]string(nil), p.Notes...),
	}

	for _, c := range p.Candidates {
		if len(r.Steps) >= count {
			break
		}
		r.Steps = append(r.Steps, RecipeStep{
			Action: "malloc", Size: reqSize, Expected: c.Addr, TID: c.TID,
			Source: c.Source, Confidence: c.Confidence,
		})
	}

	if len(r.Steps) < count {
		var live []core.Allocation
		for _, a := range m.Allocations(true) {
			if a.ChunkSize == p.ChunkSize && (tid == 0 || a.TID == tid) {
				live = append(live, a)
			}
		}
		sort.Slice(live, func(i, j int) bool { return live[i].Addr < live[j].Addr })
		r.LiveCandidates = live
		for _, a := range live {
			if len(r.Steps) >= count {
				break
			}
			r.Steps = append(r.Steps, RecipeStep{
				Action: "free", Size: a.ReqSize, Expected: a.Addr, TID: a.TID,
				Note: "live chunk of the same size class; free before spraying to recycle it",
			})
		}
		for len(r.Steps) < count {
			r.Steps = append(r.Steps, RecipeStep{
				Action: "malloc", Size: reqSize, TID: tid,
				Note: "new chunk from the arena/top; address not predicted",
			})
			r.Missing++
		}
	}

	if r.Missing > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d allocation(s) have no deterministic address prediction", r.Missing))
	}
	return r
}
