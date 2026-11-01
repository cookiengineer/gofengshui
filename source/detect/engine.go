package detect

import (
	"fmt"
	"sync"

	"gofengshui/core"
	"gofengshui/heap"
)

// Engine folds events into the heap model and deduplicates findings.
type Engine struct {
	mu       sync.Mutex
	model    *heap.Model
	timeline *heap.Timeline
	anomaly  *AnomalyTracker
	seen     map[string]int
	recent   []core.Finding
}

func New(model *heap.Model) *Engine {
	if model == nil {
		model = heap.NewModel()
	}
	return &Engine{
		model:    model,
		timeline: heap.NewTimeline(heap.DefaultTimelineConfig()),
		seen:     make(map[string]int),
	}
}

func (e *Engine) Model() *heap.Model { return e.model }

func (e *Engine) Timeline() *heap.Timeline { return e.timeline }

// EnableAnomaly installs a timeline anomaly tracker.
func (e *Engine) EnableAnomaly(cfg AnomalyTrackerConfig) *AnomalyTracker {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.anomaly = NewAnomalyTracker(cfg)
	return e.anomaly
}

// Anomaly returns the configured anomaly tracker, if any.
func (e *Engine) Anomaly() *AnomalyTracker {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.anomaly
}

func (e *Engine) Observe(ev core.Event) []core.Finding {
	findings := e.model.Apply(ev)
	e.mu.Lock()
	defer e.mu.Unlock()

	var out []core.Finding
	var ids []string
	for _, f := range findings {
		key := fmt.Sprintf("%s/%d/%d/%x/%d/%d/%d/%x", f.ID, f.Event.Type, f.Event.TID, f.Event.Addr, f.Event.Size, f.Event.Arg1, f.Event.Arg2, f.Event.Caller)
		if e.seen[key] > 0 {
			continue
		}
		e.seen[key] = 1
		e.recent = append(e.recent, f)
		if len(e.recent) > 4096 {
			e.recent = e.recent[len(e.recent)-2048:]
		}
		out = append(out, f)
		ids = append(ids, f.ID)
	}

	closed := e.timeline.ObserveFindings(ev, ids)
	if e.anomaly != nil {
		for _, w := range closed {
			score := e.anomaly.Observe(w)
			if score == nil || !ShouldEmitD10(*score) {
				continue
			}
			f := AnomalyFinding(w, *score)
			e.recent = append(e.recent, f)
			if len(e.recent) > 4096 {
				e.recent = e.recent[len(e.recent)-2048:]
			}
			out = append(out, f)
			if score.PhaseChange && score.Phase == "primitive" {
				d11 := PhaseFinding(*score, "timeline phase")
				e.recent = append(e.recent, d11)
				out = append(out, d11)
			}
		}
	}
	return out
}

// Add records an externally classified finding (for example a ptrace crash).
// It returns any correlated D11 findings that callers should broadcast.
func (e *Engine) Add(f core.Finding) []core.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.timeline.AddFinding(f.ID)
	e.recent = append(e.recent, f)
	if len(e.recent) > 4096 {
		e.recent = e.recent[len(e.recent)-2048:]
	}
	var out []core.Finding
	if (f.ID == "D5" || f.ID == "D6") && e.anomaly != nil {
		if score, ok := e.anomaly.ControlFlow(); ok {
			d11 := PhaseFinding(*score, f.ID)
			e.recent = append(e.recent, d11)
			out = append(out, d11)
		}
	}
	return out
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
