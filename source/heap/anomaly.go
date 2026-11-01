package heap

import (
	"fmt"
	"math"
)

// AnomalyConfig controls timeline anomaly scoring.
type AnomalyConfig struct {
	HistogramWeight  float64 `json:"histogram_weight"`
	RateWeight       float64 `json:"rate_weight"`
	CountWeight      float64 `json:"count_weight"`
	ReuseWeight      float64 `json:"reuse_weight"`
	EntropyWeight    float64 `json:"entropy_weight"`
	ContentWeight    float64 `json:"content_weight"`
	StructuralWeight float64 `json:"structural_weight"`
	Threshold        float64 `json:"threshold"`
	HighThreshold    float64 `json:"high_threshold"`
	MinHistogramLive int     `json:"min_histogram_live"`
}

// DefaultAnomalyConfig returns a conservative starting point.
func DefaultAnomalyConfig() AnomalyConfig {
	return AnomalyConfig{
		HistogramWeight:  15,
		RateWeight:       0.5,
		CountWeight:      0.25,
		ReuseWeight:      0.75,
		EntropyWeight:    0.25,
		ContentWeight:    0.5,
		StructuralWeight: 3,
		Threshold:        8,
		HighThreshold:    16,
		MinHistogramLive: 32,
	}
}

// AnomalyScore is the result of comparing one window with a baseline.
type AnomalyScore struct {
	WindowID        uint64             `json:"window_id"`
	Score           float64            `json:"score"`
	Threshold       float64            `json:"threshold"`
	HighThreshold   float64            `json:"high_threshold"`
	Severity        string             `json:"severity"`
	Components      map[string]float64 `json:"components,omitempty"`
	Evidence        []string           `json:"evidence,omitempty"`
	BaselineKey     string             `json:"baseline_key,omitempty"`
	BaselineWindows int                `json:"baseline_windows,omitempty"`
	CUSUM           float64            `json:"cusum,omitempty"`
	ChangePoint     bool               `json:"change_point,omitempty"`
	Phase           string             `json:"phase,omitempty"`
	PhaseChange     bool               `json:"phase_change,omitempty"`
}

var structuralWeights = map[string]float64{
	"D1": 1, "D2": 1, "D3": 1, "D4": 0.5,
	"D5": 2, "D6": 2, "D7": 2, "D8": 2, "D9": 2,
}

// ScoreWindow compares a window against a baseline model.
func ScoreWindow(w TimelineWindow, b BaselineModel, cfg AnomalyConfig) AnomalyScore {
	score := AnomalyScore{
		WindowID:        w.ID,
		Threshold:       cfg.Threshold,
		HighThreshold:   cfg.HighThreshold,
		Components:      make(map[string]float64),
		BaselineKey:     b.Key,
		BaselineWindows: b.Windows,
	}

	var js float64
	if cfg.MinHistogramLive <= 0 || w.Live >= cfg.MinHistogramLive {
		js = JensenShannonWindow(w, b)
	}
	hist := js * cfg.HistogramWeight
	score.Components["histogram"] = hist
	if js > 0 {
		score.Evidence = append(score.Evidence, fmt.Sprintf("histogram divergence %.4f", js))
	}

	rateZ := maxRobustZ([]float64{
		RobustZ(w.Rates.Events, b.Rates.Events),
		RobustZ(w.Rates.Allocs, b.Rates.Allocs),
		RobustZ(w.Rates.Frees, b.Rates.Frees),
		RobustZ(w.Rates.Reallocs, b.Rates.Reallocs),
		RobustZ(w.Rates.BytesPerSec, b.Rates.BytesPerSec),
	})
	rate := rateZ * cfg.RateWeight
	score.Components["rates"] = rate
	if rateZ > 0 {
		score.Evidence = append(score.Evidence, fmt.Sprintf("rate deviation z=%.2f", rateZ))
	}

	countZ := maxRobustZ([]float64{
		RobustZ(float64(w.Live), b.Counts.Live),
		RobustZ(float64(w.Freed), b.Counts.Freed),
	})
	count := countZ * cfg.CountWeight
	score.Components["counts"] = count
	if countZ > 0 {
		score.Evidence = append(score.Evidence, fmt.Sprintf("count deviation z=%.2f", countZ))
	}

	reuseZ := maxRobustZ([]float64{
		RobustZ(float64(w.Reuse.Count), b.Counts.ReuseCount),
		RobustZ(float64(w.Reuse.SameClass), b.Counts.ReuseSameClass),
	})
	reuse := reuseZ * cfg.ReuseWeight
	score.Components["reuse"] = reuse
	if w.Reuse.Count > 0 {
		score.Evidence = append(score.Evidence,
			fmt.Sprintf("address reuse %d (same class %d)", w.Reuse.Count, w.Reuse.SameClass))
	}

	entropyZ := RobustZ(WindowEntropy(w), b.Entropy)
	entropy := entropyZ * cfg.EntropyWeight
	score.Components["entropy"] = entropy
	if entropyZ > 0 {
		score.Evidence = append(score.Evidence, fmt.Sprintf("entropy deviation z=%.2f", entropyZ))
	}

	if w.Content != nil && w.Content.Samples > 0 && b.Content.Samples.Count > 0 {
		contentZ := maxRobustZ([]float64{
			robustZFloor(w.Content.Entropy, b.Content.Entropy, 0.5),
			robustZFloor(w.Content.PrintableRatio, b.Content.PrintableRatio, 0.1),
			robustZFloor(w.Content.PointerRatio, b.Content.PointerRatio, 0.1),
			robustZFloor(w.Content.ZeroRatio, b.Content.ZeroRatio, 0.1),
			robustZFloor(w.Content.TopQwordRatio, b.Content.TopQwordRatio, 0.1),
		})
		content := contentZ * cfg.ContentWeight
		score.Components["content"] = content
		if contentZ > 0 {
			score.Evidence = append(score.Evidence, fmt.Sprintf("content deviation z=%.2f", contentZ))
		}
	}

	structural := structuralSignalWeight(w.Findings)
	structuralScore := structural * cfg.StructuralWeight
	score.Components["structural"] = structuralScore
	if structural > 0 {
		score.Evidence = append(score.Evidence, fmt.Sprintf("structural signals weight %.1f", structural))
	}

	for _, value := range score.Components {
		score.Score += value
	}
	score.Score = math.Round(score.Score*100) / 100
	switch {
	case score.Score >= cfg.HighThreshold:
		score.Severity = "high"
	case score.Score >= cfg.Threshold:
		score.Severity = "medium"
	default:
		score.Severity = "info"
	}
	return score
}

// RobustZ returns a bounded robust z-score for a value against a summary.
func RobustZ(x float64, s RobustStats) float64 {
	if s.Count == 0 {
		return 0
	}
	scale := 1.4826 * s.MAD
	if scale < 1e-9 {
		scale = math.Abs(s.Median) * 0.25
	}
	if scale < 1e-9 {
		scale = 1
	}
	z := math.Abs(x-s.Median) / scale
	if z > 10 {
		z = 10
	}
	return z
}

func robustZFloor(x float64, s RobustStats, floor float64) float64 {
	if s.Count == 0 {
		return 0
	}
	scale := 1.4826 * s.MAD
	if scale < floor {
		scale = floor
	}
	z := math.Abs(x-s.Median) / scale
	if z > 10 {
		z = 10
	}
	return z
}

func maxRobustZ(values []float64) float64 {
	var best float64
	for _, v := range values {
		if v > best {
			best = v
		}
	}
	return best
}

func structuralSignalWeight(findings map[string]int) float64 {
	var total float64
	for id, count := range findings {
		weight, ok := structuralWeights[id]
		if !ok {
			continue
		}
		total += weight * float64(count)
	}
	if total > 6 {
		total = 6
	}
	return total
}

// JensenShannonWindow compares a window's live class distribution with the
// baseline reference distribution.
func JensenShannonWindow(w TimelineWindow, b BaselineModel) float64 {
	if len(b.Reference) == 0 {
		return 0
	}
	p := make(map[uint64]float64, len(w.Classes))
	var pTotal float64
	for _, c := range w.Classes {
		if c.LiveShare <= 0 {
			continue
		}
		p[c.ChunkSize] += c.LiveShare
		pTotal += c.LiveShare
	}
	if pTotal <= 0 {
		return 0
	}
	for k, v := range p {
		p[k] = v / pTotal
	}
	q := make(map[uint64]float64, len(b.Reference))
	var qTotal float64
	for _, r := range b.Reference {
		if r.LiveShare <= 0 {
			continue
		}
		q[r.ChunkSize] += r.LiveShare
		qTotal += r.LiveShare
	}
	if qTotal <= 0 {
		return 0
	}
	for k, v := range q {
		q[k] = v / qTotal
	}

	keys := make(map[uint64]bool, len(p)+len(q))
	for k := range p {
		keys[k] = true
	}
	for k := range q {
		keys[k] = true
	}
	var divergence float64
	for k := range keys {
		pv, qv := p[k], q[k]
		mv := (pv + qv) / 2
		if pv > 0 && mv > 0 {
			divergence += 0.5 * pv * math.Log2(pv/mv)
		}
		if qv > 0 && mv > 0 {
			divergence += 0.5 * qv * math.Log2(qv/mv)
		}
	}
	if divergence < 0 {
		return 0
	}
	if divergence > 1 {
		return 1
	}
	return divergence
}
