package detect

import (
	"fmt"
	"math"
	"sync"
	"time"

	"gofengshui/core"
	"gofengshui/heap"
)

// AnomalyTrackerConfig controls warmup learning and anomaly scoring.
type AnomalyTrackerConfig struct {
	Key           string
	Label         string
	Profile       heap.Profile
	WarmupWindows int
	Score         heap.AnomalyConfig
}

// AnomalyTracker learns a baseline from warmup windows and scores later ones.
type AnomalyTracker struct {
	mu sync.Mutex

	cfg           AnomalyTrackerConfig
	warmup        []heap.TimelineWindow
	contentWarmup []heap.ContentSummary
	contentSeeded bool
	baseline      *heap.BaselineModel
	last          *heap.AnomalyScore
	lastAt        time.Time
	recent        []heap.AnomalyScore
	cusum         float64
	phase         string
}

const maxContentWarmup = 64

// NewAnomalyTracker creates a tracker with the given configuration.
func NewAnomalyTracker(cfg AnomalyTrackerConfig) *AnomalyTracker {
	if cfg.WarmupWindows <= 0 {
		cfg.WarmupWindows = 20
	}
	if cfg.Score == (heap.AnomalyConfig{}) {
		cfg.Score = heap.DefaultAnomalyConfig()
	}
	return &AnomalyTracker{cfg: cfg}
}

// Config returns the active tracker configuration.
func (a *AnomalyTracker) Config() AnomalyTrackerConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// SetBaseline installs a stored baseline and disables warmup.
func (a *AnomalyTracker) SetBaseline(b *heap.BaselineModel) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if b == nil {
		a.baseline = nil
		a.contentWarmup = nil
		a.contentSeeded = false
		return
	}
	cp := *b
	a.baseline = &cp
	a.warmup = nil
	a.contentWarmup = nil
	a.contentSeeded = cp.Content.Samples.Count > 0
	a.cusum = 0
	a.phase = "normal"
	a.last = nil
	a.lastAt = time.Time{}
}

// Baseline returns a copy of the current baseline, if any.
func (a *AnomalyTracker) Baseline() *heap.BaselineModel {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.baseline == nil {
		return nil
	}
	cp := *a.baseline
	return &cp
}

// Warmup returns the number of collected and required warmup windows.
func (a *AnomalyTracker) Warmup() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.warmup), a.cfg.WarmupWindows
}

// ResetWarmup discards the current baseline and starts learning again.
func (a *AnomalyTracker) ResetWarmup() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.warmup = nil
	a.contentWarmup = nil
	a.contentSeeded = false
	a.baseline = nil
	a.cusum = 0
	a.phase = "normal"
	a.last = nil
	a.lastAt = time.Time{}
	a.recent = nil
}

// ObserveContent makes a sampled content summary available to the baseline.
// Summaries received during warmup are accumulated and applied when the
// baseline is built. If warmup closed without content, the first post-warmup
// summary seeds the empty content baseline once.
func (a *AnomalyTracker) ObserveContent(summary heap.ContentSummary) {
	if summary.Samples == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.baseline == nil {
		if len(a.contentWarmup) < maxContentWarmup {
			a.contentWarmup = append(a.contentWarmup, summary)
		}
		return
	}
	if a.contentSeeded || a.baseline.Content.Samples.Count > 0 {
		a.contentSeeded = true
		return
	}
	a.baseline.Content = heap.ContentBaselineFromSummaries([]heap.ContentSummary{summary})
	a.contentSeeded = true
}

// Observe learns from a warmup window or scores a post-warmup window.
func (a *AnomalyTracker) Observe(w heap.TimelineWindow) *heap.AnomalyScore {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.baseline == nil {
		a.warmup = append(a.warmup, w)
		if len(a.warmup) < a.cfg.WarmupWindows {
			return nil
		}
		b := heap.BuildBaseline(a.cfg.Key, a.cfg.Label, a.cfg.Profile, a.warmup)
		if b.Content.Samples.Count == 0 && len(a.contentWarmup) > 0 {
			b.Content = heap.ContentBaselineFromSummaries(a.contentWarmup)
		}
		a.baseline = &b
		a.warmup = nil
		a.contentWarmup = nil
		a.contentSeeded = b.Content.Samples.Count > 0
		a.cusum = 0
		return nil
	}

	score := heap.ScoreWindow(w, *a.baseline, a.cfg.Score)
	if score.Score >= score.Threshold {
		a.cusum = math.Max(0, a.cusum+score.Score-score.Threshold)
	} else {
		a.cusum = math.Max(0, a.cusum*0.9)
	}
	score.CUSUM = a.cusum
	if a.cusum >= score.HighThreshold {
		score.ChangePoint = true
	}
	phase := "normal"
	if score.Score >= score.Threshold || a.cusum >= score.Threshold {
		phase = "suspect"
	}
	if (score.Score >= score.HighThreshold || score.ChangePoint) &&
		(score.Components["structural"] > 0 || score.Components["reuse"] > 0) {
		phase = "primitive"
	}
	if phase != a.phase {
		score.PhaseChange = true
	}
	a.phase = phase
	score.Phase = phase
	a.last = &score
	a.lastAt = time.Now()
	a.recent = append(a.recent, score)
	if len(a.recent) > 256 {
		a.recent = a.recent[len(a.recent)-128:]
	}
	return &score
}

// Last returns the most recent score, if any.
func (a *AnomalyTracker) Last() *heap.AnomalyScore {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		return nil
	}
	cp := *a.last
	return &cp
}

// Recent returns a copy of recent scores.
func (a *AnomalyTracker) Recent() []heap.AnomalyScore {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]heap.AnomalyScore, len(a.recent))
	copy(out, a.recent)
	return out
}

// ControlFlow marks a correlated control-flow finding and reports whether the
// current phase is suspicious enough to escalate it to D11.
func (a *AnomalyTracker) ControlFlow() (*heap.AnomalyScore, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil || a.phase == "normal" || a.phase == "" {
		return nil, false
	}
	if !a.lastAt.IsZero() && time.Since(a.lastAt) > 30*time.Second {
		return nil, false
	}
	score := *a.last
	score.Phase = "control"
	score.PhaseChange = true
	a.phase = "control"
	a.last = &score
	return &score, true
}

// ShouldEmitD10 reports whether a score has enough structural evidence to be
// emitted as a finding. Rate/reuse drift alone is too common in benign
// workloads, so at least one composition or content signal is required.
func ShouldEmitD10(score heap.AnomalyScore) bool {
	if score.Score < score.Threshold {
		return false
	}
	return score.Components["histogram"] >= 1 ||
		score.Components["structural"] > 0 ||
		score.Components["content"] >= 1
}

// PhaseFinding converts a correlated score into a D11 finding.
func PhaseFinding(score heap.AnomalyScore, cause string) core.Finding {
	ev := core.Event{Timestamp: time.Now(), Type: core.EventStat}
	return core.Finding{
		ID:        "D11",
		Severity:  "high",
		Message:   fmt.Sprintf("exploit phase %s correlated with %s (score %.2f)", score.Phase, cause, score.Score),
		Event:     &ev,
		Timestamp: time.Now(),
		Details: map[string]any{
			"phase":        score.Phase,
			"cause":        cause,
			"score":        score.Score,
			"window_id":    score.WindowID,
			"evidence":     score.Evidence,
			"cusum":        score.CUSUM,
			"change_point": score.ChangePoint,
		},
	}
}

// AnomalyFinding converts a score into a D10 finding.
func AnomalyFinding(w heap.TimelineWindow, score heap.AnomalyScore) core.Finding {
	ev := core.Event{
		Timestamp: w.WallTo,
		Type:      core.EventStat,
		Size:      uint64(w.Events),
	}
	details := map[string]any{
		"window_id":        w.ID,
		"score":            score.Score,
		"threshold":        score.Threshold,
		"high_threshold":   score.HighThreshold,
		"components":       score.Components,
		"evidence":         score.Evidence,
		"baseline_key":     score.BaselineKey,
		"baseline_windows": score.BaselineWindows,
		"cusum":            score.CUSUM,
		"change_point":     score.ChangePoint,
		"live":             w.Live,
		"freed":            w.Freed,
		"reuse":            w.Reuse,
		"events":           w.Events,
	}
	return core.Finding{
		ID:        "D10",
		Severity:  score.Severity,
		Message:   fmt.Sprintf("heap timeline anomaly score %.2f in window %d", score.Score, w.ID),
		Event:     &ev,
		Details:   details,
		Timestamp: w.WallTo,
	}
}
