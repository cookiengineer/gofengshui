package agent

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gofengshui/source/core"
	"gofengshui/source/debugger"
)

func (s *Session) watchCtl() WatchController {
	if s.watcher != nil {
		return s.watcher
	}
	return s.tracer
}

// updateAutoWatch reacts to heap events when --watch-freed is enabled. Freed
// chunks get a write watchpoint; reused or unmapped addresses are cleared.
func (s *Session) updateAutoWatch(ev core.Event) {
	if !s.cfg.WatchFreed {
		return
	}
	switch ev.Type {
	case core.EventFree:
		a, ok := s.model.Query(ev.Addr)
		if !ok {
			return
		}
		s.armFreedWatch(ev.Addr, a.ID, watchSizeForChunk(a.ChunkSize))
	case core.EventAlloc:
		s.clearAutoAt(ev.Addr)
		if core.AllocOp(ev.Arg2) == core.OpRealloc && ev.Arg1 != 0 && ev.Arg1 != ev.Addr {
			if a, ok := s.model.Query(ev.Arg1); ok {
				s.armFreedWatch(ev.Arg1, a.ID, watchSizeForChunk(a.ChunkSize))
			}
		}
	case core.EventMunmap:
		s.clearAutoAt(ev.Addr)
	}
}

func (s *Session) armFreedWatch(addr, allocID, size uint64) {
	w := s.watchCtl()
	if w == nil {
		return
	}
	// Debug registers can only be written while the tracee is stopped.
	wasStopped := s.tracer.AllStopped()
	if !wasStopped {
		if err := s.tracer.Pause(); err != nil {
			return
		}
		defer func() { _ = s.tracer.Continue(0) }()
		if !s.tracer.WaitStopped(2 * time.Second) {
			return
		}
	}
	s.clearAutoAt(addr)
	wp, err := w.SetWatchpoint(addr, size, debugger.WatchWrite, allocID)
	if err != nil {
		if old, ok := s.popOldestAuto(); ok {
			_ = w.ClearWatchpoint(old)
			wp, err = w.SetWatchpoint(addr, size, debugger.WatchWrite, allocID)
		}
		if err != nil {
			if os.Getenv("GFS_PTRACE_LOG") != "" {
				fmt.Fprintf(os.Stderr, "gfs: auto-watch install failed: %v\n", err)
			}
			return
		}
	}
	s.mu.Lock()
	s.autoWatch[wp.ID] = true
	s.autoAddr[addr] = wp.ID
	s.autoOrder = append(s.autoOrder, wp.ID)
	s.mu.Unlock()
}

func (s *Session) popOldestAuto() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.autoOrder) > 0 {
		id := s.autoOrder[0]
		s.autoOrder = s.autoOrder[1:]
		if !s.autoWatch[id] {
			continue
		}
		delete(s.autoWatch, id)
		for addr, wid := range s.autoAddr {
			if wid == id {
				delete(s.autoAddr, addr)
				break
			}
		}
		return id, true
	}
	return 0, false
}

func (s *Session) forgetAuto(id uint64) {
	s.mu.Lock()
	delete(s.autoWatch, id)
	for addr, wid := range s.autoAddr {
		if wid == id {
			delete(s.autoAddr, addr)
			break
		}
	}
	for i, wid := range s.autoOrder {
		if wid == id {
			s.autoOrder = append(s.autoOrder[:i], s.autoOrder[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

func (s *Session) clearAutoAt(addr uint64) {
	s.mu.Lock()
	id, ok := s.autoAddr[addr]
	s.mu.Unlock()
	if !ok {
		return
	}
	s.forgetAuto(id)
	if w := s.watchCtl(); w != nil {
		_ = w.ClearWatchpoint(id)
	}
}

func (s *Session) isAutoWatch(id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.autoWatch[id]
}

// allocatorInternalStop reports whether RIP is inside libc or the dynamic
// loader. Free/malloc internals write chunk metadata into recycled memory, so
// those writes must not be reported as target UAF. Direct writes from the
// target (or a non-libc module) are still reported.
func (s *Session) allocatorInternalStop(st debugger.Stop) bool {
	mod, _, _, _ := s.symbolize(st.Regs.RIP)
	return strings.Contains(mod, "libc") || strings.Contains(mod, "ld-linux")
}

// autoWatchHit classifies a hardware watchpoint hit on a freed chunk, reports
// a D2 finding, clears the watchpoint and resumes the target.
func (s *Session) autoWatchHit(st debugger.Stop) bool {
	if st.Watchpoint == nil || !s.isAutoWatch(st.Watchpoint.ID) {
		return false
	}
	if s.allocatorInternalStop(st) {
		if err := s.tracer.Continue(st.TID); err != nil {
			s.broadcast("error", StreamEvent{Kind: "error", Message: "auto-watch continue: " + err.Error()})
		}
		return true
	}
	id := st.Watchpoint.ID
	s.forgetAuto(id)
	if w := s.watchCtl(); w != nil {
		_ = w.ClearWatchpoint(id)
	}

	now := time.Now()
	findings := s.model.CheckAccess(st.Address, st.Watchpoint.Size, 1, now)
	if len(findings) == 0 {
		a, _ := s.model.Query(st.Address)
		ev := core.Event{
			Timestamp: now, Type: core.EventMemAccess,
			PID: uint32(st.PID), TID: uint32(st.TID),
			Addr: st.Address, Size: st.Watchpoint.Size, Arg2: 1,
		}
		findings = []core.Finding{{
			ID:         "D2",
			Severity:   "high",
			Message:    fmt.Sprintf("write to freed chunk 0x%x via hardware watchpoint", st.Address),
			Event:      &ev,
			Allocation: a,
			Timestamp:  now,
		}}
	}
	for i := range findings {
		if findings[i].Details == nil {
			findings[i].Details = make(map[string]any)
		}
		findings[i].Details["source"] = "hardware-watchpoint"
		findings[i].Details["watchpoint_id"] = id
		s.engine.Add(findings[i])
		fc := findings[i]
		s.broadcast("finding", StreamEvent{Kind: "finding", Finding: &fc})
	}
	if err := s.tracer.Continue(st.TID); err != nil {
		s.broadcast("error", StreamEvent{Kind: "error", Message: "auto-watch continue: " + err.Error()})
	}
	return true
}
