package agent

import (
	"fmt"

	"gofengshui/detect"
	"gofengshui/heap"
	"gofengshui/proto"
	"gofengshui/transport"
)

func (s *Session) anomalyTrackerConfig() detect.AnomalyTrackerConfig {
	profile := s.model.Profile()
	score := heap.DefaultAnomalyConfig()
	if s.cfg.AnomalyThreshold > 0 {
		score.Threshold = s.cfg.AnomalyThreshold
	}
	if s.cfg.AnomalyHighThreshold > 0 {
		score.HighThreshold = s.cfg.AnomalyHighThreshold
	}
	return detect.AnomalyTrackerConfig{
		Key:           heap.BaselineKey(s.target.ExePath, profile),
		Label:         "warmup",
		Profile:       profile,
		WarmupWindows: s.cfg.AnomalyWarmup,
		Score:         score,
	}
}

func (s *Session) configureAnomaly() {
	if !s.cfg.Anomaly && s.cfg.BaselinePath == "" {
		return
	}
	tc := heap.DefaultTimelineConfig()
	if s.cfg.AnomalyWindowEvents > 0 {
		tc.WindowEvents = s.cfg.AnomalyWindowEvents
	}
	if s.cfg.AnomalyWindowMS > 0 {
		tc.WindowMS = s.cfg.AnomalyWindowMS
	}
	s.engine.Timeline().SetConfig(tc)

	cfg := s.anomalyTrackerConfig()
	tracker := s.engine.EnableAnomaly(cfg)
	if s.cfg.BaselinePath == "" {
		return
	}
	b, err := heap.LoadBaseline(s.cfg.BaselinePath)
	if err != nil {
		return
	}
	if b.Key != "" && b.Key != cfg.Key {
		return
	}
	tracker.SetBaseline(&b)
	s.mu.Lock()
	s.baselineModel = &b
	s.mu.Unlock()
}

func (s *Session) learnAnomalyBaseline(name string) (*heap.BaselineModel, error) {
	windows := s.engine.Timeline().Windows()
	if len(windows) == 0 {
		return nil, fmt.Errorf("no completed timeline windows to learn from")
	}
	if name == "" {
		name = "learned"
	}
	cfg := s.anomalyTrackerConfig()
	b := heap.BuildBaseline(cfg.Key, name, cfg.Profile, windows)
	tracker := s.engine.Anomaly()
	if tracker == nil {
		tracker = s.engine.EnableAnomaly(cfg)
	}
	tracker.SetBaseline(&b)
	s.mu.Lock()
	s.baselineModel = &b
	s.mu.Unlock()
	return &b, nil
}

func (s *Session) heapAnomaly(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Reset bool `json:"reset"`
	}
	_ = f.DecodeParams(&p)
	tracker := s.engine.Anomaly()
	if tracker == nil {
		s.reply(conn, f, map[string]any{"enabled": false}, nil)
		return
	}
	if p.Reset {
		tracker.ResetWarmup()
	}
	collected, required := tracker.Warmup()
	s.mu.Lock()
	content := s.content
	s.mu.Unlock()
	s.reply(conn, f, map[string]any{
		"enabled": true,
		"last":    tracker.Last(),
		"recent":  tracker.Recent(),
		"warmup": map[string]int{
			"collected": collected,
			"required":  required,
		},
		"baseline": tracker.Baseline(),
		"content":  content,
		"config":   tracker.Config(),
	}, nil)
}
