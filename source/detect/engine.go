package detect

import (
	"fmt"
	"sync"

	"gofengshui/core"
	"gofengshui/heap"
)

// Engine folds events into the heap model and deduplicates findings.
type Engine struct {
	mu     sync.Mutex
	model  *heap.Model
	seen   map[string]int
	recent []core.Finding
}

func New(model *heap.Model) *Engine {
	if model == nil {
		model = heap.NewModel()
	}
	return &Engine{model: model, seen: make(map[string]int)}
}

func (e *Engine) Model() *heap.Model { return e.model }

func (e *Engine) Observe(ev core.Event) []core.Finding {
	findings := e.model.Apply(ev)
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []core.Finding
	for _, f := range findings {
		key := fmt.Sprintf("%s/%d/%d/%x/%d", f.ID, f.Event.Type, f.Event.TID, f.Event.Addr, f.Event.Size)
		if e.seen[key] > 0 {
			continue
		}
		e.seen[key] = 1
		e.recent = append(e.recent, f)
		if len(e.recent) > 4096 {
			e.recent = e.recent[len(e.recent)-2048:]
		}
		out = append(out, f)
	}
	return out
}

// Add records an externally classified finding (for example a ptrace crash).
func (e *Engine) Add(f core.Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recent = append(e.recent, f)
	if len(e.recent) > 4096 {
		e.recent = e.recent[len(e.recent)-2048:]
	}
}

func (e *Engine) Recent() []core.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]core.Finding, len(e.recent))
	copy(out, e.recent)
	return out
}

// Assertion is evaluated against a finding or a sink result.
type Assertion struct {
	ID       string            `json:"id,omitempty"`
	Type     string            `json:"type"`
	Address  uint64            `json:"address,omitempty"`
	Size     uint64            `json:"size,omitempty"`
	Symbol   string            `json:"symbol,omitempty"`
	Regs     map[string]uint64 `json:"regs,omitempty"`
	MinCount int               `json:"min_count,omitempty"`
}

// Check evaluates one assertion against accumulated findings.
func (e *Engine) Check(a Assertion) (bool, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a.Type == "" || a.Type == "finding" {
		count := 0
		for _, f := range e.recent {
			if a.ID != "" && f.ID != a.ID {
				continue
			}
			if a.Address != 0 && f.Event != nil && f.Event.Addr != a.Address {
				continue
			}
			count++
		}
		min := a.MinCount
		if min == 0 {
			min = 1
		}
		if count >= min {
			return true, ""
		}
		return false, fmt.Sprintf("expected %d finding(s), got %d", min, count)
	}
	return false, "unsupported assertion type " + a.Type
}
