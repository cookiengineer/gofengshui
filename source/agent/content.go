package agent

import (
	"time"

	"gofengshui/heap"
)

func (s *Session) contentLoop() {
	interval := time.Duration(s.cfg.ContentSampleMS) * time.Millisecond
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var last time.Time
	sample := func() {
		if !last.IsZero() && time.Since(last) < interval {
			return
		}
		last = time.Now()
		s.sampleContent()
	}
	for {
		select {
		case <-ticker.C:
			sample()
		case <-s.contentWake:
			sample()
		case <-s.done:
			return
		}
	}
}

// wakeContent nudges the content sampler when a timeline window closes. The
// sampler rate-limits the actual pause/read work.
func (s *Session) wakeContent() {
	if !s.cfg.ContentSample || s.contentWake == nil {
		return
	}
	select {
	case s.contentWake <- struct{}{}:
	default:
	}
}

func (s *Session) sampleContent() {
	if !s.cfg.ContentSample {
		return
	}
	s.mu.Lock()
	active := s.rop != nil || s.hijack != nil
	s.mu.Unlock()
	if active {
		return
	}

	wasRunning := !s.tracer.AllStopped()
	if wasRunning {
		if err := s.tracer.Pause(); err != nil {
			return
		}
		if !s.tracer.WaitStopped(2 * time.Second) {
			return
		}
		defer func() { _ = s.ContinueAll() }()
	}
	if !s.tracer.AllStopped() {
		return
	}

	chunks := s.cfg.ContentSampleChunks
	if chunks <= 0 {
		chunks = 64
	}
	bytes := s.cfg.ContentSampleBytes
	if bytes <= 0 {
		bytes = 256
	}
	s.refreshRegions(true)
	regions := s.model.Regions()
	candidates := heap.SelectContentCandidates(s.model.Allocations(false), s.model.Tombstones(), chunks)
	metrics := make([]heap.ContentMetrics, 0, len(candidates))
	for _, c := range candidates {
		size := c.Size
		if size > uint64(bytes) {
			size = uint64(bytes)
		}
		if size == 0 {
			continue
		}
		data, err := s.tracer.ReadMemory(c.Addr, int(size))
		if err != nil || len(data) == 0 {
			continue
		}
		metrics = append(metrics, heap.AnalyzeContent(data, regions))
	}
	summary := heap.AggregateContent(metrics)
	if summary.Samples == 0 {
		return
	}
	s.engine.Timeline().AddContent(summary)
	if tracker := s.engine.Anomaly(); tracker != nil {
		tracker.ObserveContent(summary)
	}
	s.mu.Lock()
	s.content = &summary
	s.mu.Unlock()
}
