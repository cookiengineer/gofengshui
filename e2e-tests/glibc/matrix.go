package glibc

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"gofengshui/core"
	"gofengshui/e2e/internal/agentrun"
	"gofengshui/e2e/internal/checks"
	"gofengshui/heap"
)

const (
	anomalyBenignFile   = "anomaly-benign.json"
	anomalyExploitFile  = "anomaly-exploit.json"
	anomalyOverheadFile = "anomaly-overhead.json"
	anomalyMarkerPath   = "/tmp/anomaly_exploit.t0"
)

type anomalyMatrixConfig struct {
	Warmup          int  `json:"warmup"`
	WindowEvents    int  `json:"window_events"`
	WindowMS        int  `json:"window_ms"`
	ContentSample   bool `json:"content_sample"`
	ContentSampleMS int  `json:"content_sample_ms"`
	ContentChunks   int  `json:"content_chunks"`
}

type anomalyMatrix struct {
	Generated time.Time            `json:"generated"`
	Config    anomalyMatrixConfig  `json:"config"`
	Runs      []anomalyRun         `json:"runs"`
	Summary   anomalyMatrixSummary `json:"summary"`
}

type anomalyMatrixSummary struct {
	Scorable      int     `json:"scorable"`
	FalsePositive int     `json:"false_positive"`
	FPR           float64 `json:"fpr"`
	Detected      int     `json:"detected"`
}

type anomalyRun struct {
	Kind                  string   `json:"kind"`
	Fixture               string   `json:"fixture"`
	Mode                  string   `json:"mode,omitempty"`
	ExitCode              int      `json:"exit_code"`
	Scorable              bool     `json:"scorable"`
	Windows               int      `json:"windows"`
	Warmup                int      `json:"warmup"`
	Scored                int      `json:"scored"`
	Events                int      `json:"events"`
	Baseline              bool     `json:"baseline"`
	ContentSamples        int      `json:"content_samples"`
	Findings              []string `json:"findings,omitempty"`
	D10                   int      `json:"d10"`
	D11                   int      `json:"d11"`
	MaxScore              float64  `json:"max_score"`
	MaxSeverity           string   `json:"max_severity"`
	FirstD10Window        uint64   `json:"first_d10_window,omitempty"`
	FirstStructuralWindow uint64   `json:"first_structural_window,omitempty"`
	FirstStructuralID     string   `json:"first_structural_id,omitempty"`
	ExpectedStructural    string   `json:"expected_structural,omitempty"`
	T0Source              string   `json:"t0_source,omitempty"`
	LatencyMeasured       bool     `json:"latency_measured,omitempty"`
	LatencyWindows        int      `json:"latency_windows"`
	LatencyMS             int64    `json:"latency_ms"`
	DurationMS            int64    `json:"duration_ms"`
	Error                 string   `json:"error,omitempty"`
}

type anomalyOverheadReport struct {
	Generated time.Time               `json:"generated"`
	Runs      []anomalyOverheadSample `json:"runs"`
	Medians   map[string]int64        `json:"medians"`
}

type anomalyOverheadSample struct {
	Profile         string `json:"profile"`
	DurationMS      int64  `json:"duration_ms"`
	TargetElapsedMS int64  `json:"target_elapsed_ms,omitempty"`
	Iterations      uint64 `json:"iterations,omitempty"`
}

func writeMatrix(t testing.TB, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readMatrix(t testing.TB, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func summarizeAnomalyRun(t testing.TB, kind, fixture, mode string, res *agentrun.Result, structuralID string) anomalyRun {
	t.Helper()
	report := res.Heap(t)
	windows := report.Timeline
	findings := checks.Findings(res.Frames(t))

	run := anomalyRun{
		Kind:               kind,
		Fixture:            fixture,
		Mode:               mode,
		ExitCode:           res.ExitCode,
		Windows:            len(windows),
		Baseline:           report.Baseline != nil,
		DurationMS:         res.Duration.Milliseconds(),
		MaxSeverity:        "info",
		ExpectedStructural: structuralID,
	}
	if report.Baseline != nil {
		run.Warmup = report.Baseline.Windows
		run.ContentSamples = report.Baseline.Content.Samples.Count
		if run.Warmup < len(windows) {
			run.Scored = len(windows) - run.Warmup
		}
	}
	run.Scorable = run.Baseline && run.Scored > 0
	for _, w := range windows {
		run.Events += w.Events
	}
	for _, score := range report.Anomalies {
		if score.Score > run.MaxScore {
			run.MaxScore = score.Score
			run.MaxSeverity = score.Severity
		}
	}
	for _, f := range findings {
		switch f.ID {
		case "D10":
			run.D10++
		case "D11":
			run.D11++
		}
	}
	run.Findings = checks.FindingIDs(res.Frames(t))

	firstD10, hasD10 := firstFindingWindow(findings, "D10")
	if hasD10 {
		run.FirstD10Window = firstD10
	}

	if structuralID != "" {
		if w, ok := firstWindowWithFinding(windows, structuralID); ok {
			run.FirstStructuralID = structuralID
			run.FirstStructuralWindow = w.ID
		}
	}

	var t0 time.Time
	if marker, ok := readMarkerNS(anomalyMarkerPath); ok {
		run.T0Source = "marker"
		t0 = time.Unix(0, marker)
	} else if w, ok := firstWindowWithFinding(windows, structuralID); ok && structuralID != "" {
		run.T0Source = "structural"
		t0 = w.WallFrom
	}

	if hasD10 {
		if d10, ok := findWindow(windows, firstD10); ok && !t0.IsZero() {
			run.LatencyMeasured = true
			if ms := d10.WallTo.Sub(t0).Milliseconds(); ms > 0 {
				run.LatencyMS = ms
			}
			if w, ok := firstWindowAtOrAfter(windows, t0); ok && d10.ID >= w.ID {
				run.LatencyWindows = int(d10.ID - w.ID)
			}
		}
	}
	return run
}

func firstFindingWindow(findings []core.Finding, id string) (uint64, bool) {
	for _, f := range findings {
		if f.ID != id {
			continue
		}
		if window, ok := findingWindowID(f); ok {
			return window, true
		}
	}
	return 0, false
}

func findingWindowID(f core.Finding) (uint64, bool) {
	value, ok := f.Details["window_id"]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case uint64:
		return v, true
	case int:
		return uint64(v), true
	case float64:
		return uint64(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil || n < 0 {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
}

func firstWindowWithFinding(windows []heap.TimelineWindow, id string) (heap.TimelineWindow, bool) {
	for _, w := range windows {
		if w.Findings[id] > 0 {
			return w, true
		}
	}
	return heap.TimelineWindow{}, false
}

func findWindow(windows []heap.TimelineWindow, id uint64) (heap.TimelineWindow, bool) {
	for _, w := range windows {
		if w.ID == id {
			return w, true
		}
	}
	return heap.TimelineWindow{}, false
}

func firstWindowAtOrAfter(windows []heap.TimelineWindow, at time.Time) (heap.TimelineWindow, bool) {
	for _, w := range windows {
		if !w.WallTo.Before(at) {
			return w, true
		}
	}
	return heap.TimelineWindow{}, false
}

func readMarkerNS(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var ns int64
	for _, r := range string(data) {
		if r < '0' || r > '9' {
			break
		}
		ns = ns*10 + int64(r-'0')
	}
	return ns, ns > 0
}
