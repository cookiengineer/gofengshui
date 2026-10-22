package heap

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"gofengshui/source/core"
)

// Tombstone is a freed allocation range retained for UAF checks.
type Tombstone struct {
	Addr uint64 `json:"addr"`
	Size uint64 `json:"size"`
	TS   int64  `json:"ts"`
	TID  uint32 `json:"tid"`
}

func (t Tombstone) End() uint64 { return t.Addr + t.Size }

// Mmap is a tracked anonymous/file mapping created through mmap.
type Mmap struct {
	Addr  uint64 `json:"addr"`
	Size  uint64 `json:"size"`
	Prot  uint64 `json:"prot"`
	Flags uint64 `json:"flags"`
	TID   uint32 `json:"tid"`
	TS    int64  `json:"ts"`
}

type pendingMmap struct {
	size  uint64
	prot  uint64
	flags uint64
	addr  uint64
	ts    int64
	tid   uint32
}

// Model is a concurrency-safe heap timeline and range index.
type Model struct {
	mu sync.RWMutex

	nextID uint64
	seq    uint64

	allocs  map[uint64]*core.Allocation
	byID    map[uint64]*core.Allocation
	reuses  map[uint64]int
	tombs   map[uint64]Tombstone
	mmaps   map[uint64]Mmap
	pending map[uint32]pendingMmap

	findings []core.Finding
}

func NewModel() *Model {
	return &Model{
		allocs:  make(map[uint64]*core.Allocation),
		byID:    make(map[uint64]*core.Allocation),
		reuses:  make(map[uint64]int),
		tombs:   make(map[uint64]Tombstone),
		mmaps:   make(map[uint64]Mmap),
		pending: make(map[uint32]pendingMmap),
	}
}

// Apply folds one event into the model and returns any new findings.
func (m *Model) Apply(ev core.Event) []core.Finding {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.seq++
	var out []core.Finding

	switch ev.Type {
	case core.EventAlloc:
		m.applyAlloc(ev)
	case core.EventAllocFail:
		m.findings = append(m.findings, core.Finding{
			ID:        "D4",
			Severity:  "info",
			Message:   fmt.Sprintf("allocation failed: request=%d comm=%s", ev.ReqSize, ev.Comm),
			Event:     &ev,
			Timestamp: ev.Timestamp,
		})
	case core.EventFree:
		m.applyFree(ev, false)
	case core.EventDoubleFree:
		m.applyFree(ev, true)
		f := core.Finding{
			ID:        "D1",
			Severity:  "high",
			Message:   fmt.Sprintf("double free of 0x%x", ev.Addr),
			Event:     &ev,
			Timestamp: ev.Timestamp,
		}
		m.findings = append(m.findings, f)
	case core.EventInvalidFree:
		m.applyFree(ev, false)
		f := core.Finding{
			ID:        "D1",
			Severity:  "medium",
			Message:   fmt.Sprintf("free of untracked pointer 0x%x", ev.Addr),
			Event:     &ev,
			Timestamp: ev.Timestamp,
			Details:   map[string]any{"unknown_allocation": ev.Flags&1 != 0},
		}
		m.findings = append(m.findings, f)
	case core.EventMmap:
		m.pending[ev.TID] = pendingMmap{
			size: ev.Size, prot: ev.Arg1, flags: ev.Arg2,
			addr: ev.Addr, ts: ev.Timestamp.UnixNano(), tid: ev.TID,
		}
	case core.EventSyscallRet:
		if ev.Arg1 == core.SysMmap || ev.Arg1 == core.SysMremap {
			m.applyMmapRet(ev)
		}
	case core.EventMunmap:
		m.applyMunmap(ev)
	case core.EventMemAccess:
		out = append(out, m.checkAccess(ev)...)
	}

	out = append(out, m.findings...)
	m.findings = m.findings[:0]
	return out
}

func (m *Model) applyAlloc(ev core.Event) {
	if ev.Addr == 0 {
		return
	}
	if ev.Size == 0 {
		ev.Size = ev.ReqSize
	}
	m.removeTombstoneContaining(ev.Addr)

	m.nextID++
	a := &core.Allocation{
		ID:          m.nextID,
		Addr:        ev.Addr,
		ReqSize:     ev.ReqSize,
		ChunkSize:   ev.Size,
		Allocator:   "glibc",
		State:       core.StateLive,
		TID:         ev.TID,
		StackID:     ev.StackID,
		AllocTS:     ev.Timestamp.UnixNano(),
		Generation:  m.nextID,
		LastEventID: m.seq,
	}
	m.allocs[a.Addr] = a
	m.byID[a.ID] = a
	m.reuses[a.Addr]++
}

func (m *Model) applyFree(ev core.Event, double bool) {
	if a := m.allocs[ev.Addr]; a != nil {
		a.State = core.StateFreed
		a.FreeTS = ev.Timestamp.UnixNano()
		a.LastEventID = m.seq
		if a.ChunkSize == 0 {
			a.ChunkSize = ev.Size
		}
		m.tombs[a.Addr] = Tombstone{Addr: a.Addr, Size: a.ChunkSize, TS: a.FreeTS, TID: ev.TID}
		return
	}
	size := ev.Size
	if size == 0 {
		size = 1
	}
	m.tombs[ev.Addr] = Tombstone{Addr: ev.Addr, Size: size, TS: ev.Timestamp.UnixNano(), TID: ev.TID}
}

func (m *Model) applyMmapRet(ev core.Event) {
	p, ok := m.pending[ev.TID]
	if !ok {
		return
	}
	delete(m.pending, ev.TID)
	// Negative return values are errno; anything with the high bit set and
	// within -4095..-1 is an error.
	if ev.Addr > ^uint64(0)-4096 {
		errCopy := ev
		m.findings = append(m.findings, core.Finding{
			ID:        "D4",
			Severity:  "medium",
			Message:   fmt.Sprintf("mmap/mremap failed: errno=%d", int64(-int64(ev.Addr))),
			Event:     &errCopy,
			Timestamp: ev.Timestamp,
			Details:   map[string]any{"syscall": ev.Arg1, "ret": ev.Addr},
		})
		return
	}
	m.mmaps[ev.Addr] = Mmap{
		Addr: ev.Addr, Size: p.size, Prot: p.prot, Flags: p.flags,
		TID: p.tid, TS: p.ts,
	}
	if p.size >= 128*1024 {
		m.nextID++
		a := &core.Allocation{
			ID: m.nextID, Addr: ev.Addr, ReqSize: p.size, ChunkSize: p.size,
			Allocator: "mmap", State: core.StateLive, TID: p.tid,
			AllocTS: p.ts, Generation: m.nextID, MmapBacked: true,
			LastEventID: m.seq,
		}
		m.allocs[a.Addr] = a
		m.byID[a.ID] = a
	}
}

func (m *Model) applyMunmap(ev core.Event) {
	delete(m.mmaps, ev.Addr)
	for addr, a := range m.allocs {
		if a.Allocator == "mmap" && addr == ev.Addr {
			a.State = core.StateFreed
			a.FreeTS = ev.Timestamp.UnixNano()
			m.tombs[addr] = Tombstone{Addr: addr, Size: a.ChunkSize, TS: a.FreeTS, TID: ev.TID}
		}
	}
}

func (m *Model) checkAccess(ev core.Event) []core.Finding {
	var out []core.Finding
	if ev.Size == 0 {
		return nil
	}
	end := ev.Addr + ev.Size
	if end < ev.Addr {
		end = ^uint64(0)
	}

	for _, t := range m.tombs {
		if rangesOverlap(ev.Addr, end, t.Addr, t.End()) {
			evCopy := ev
			out = append(out, core.Finding{
				ID:        "D2",
				Severity:  "high",
				Message:   fmt.Sprintf("use-after-free access 0x%x..0x%x overlaps freed chunk 0x%x..0x%x", ev.Addr, end, t.Addr, t.End()),
				Event:     &evCopy,
				Timestamp: ev.Timestamp,
				Details: map[string]any{
					"freed_addr": t.Addr,
					"freed_size": t.Size,
					"direction":  direction(ev.Arg2),
				},
			})
		}
	}

	for _, a := range m.allocs {
		if a.State != core.StateLive {
			continue
		}
		if ev.Addr >= a.Addr && ev.Addr < a.End() && end > a.End() {
			aCopy := *a
			evCopy := ev
			out = append(out, core.Finding{
				ID:         "D3",
				Severity:   "high",
				Message:    fmt.Sprintf("heap overflow 0x%x..0x%x exceeds allocation 0x%x..0x%x", ev.Addr, end, a.Addr, a.End()),
				Event:      &evCopy,
				Allocation: &aCopy,
				Timestamp:  ev.Timestamp,
				Details: map[string]any{
					"allocation_id": a.ID,
					"direction":     direction(ev.Arg2),
				},
			})
		}
	}
	return out
}

func direction(v uint64) string {
	switch v {
	case 1:
		return "write_to_heap"
	case 2:
		return "read_from_heap"
	default:
		return "unknown"
	}
}

func (m *Model) removeTombstoneContaining(addr uint64) {
	for a, t := range m.tombs {
		if addr >= t.Addr && addr < t.End() {
			delete(m.tombs, a)
		}
	}
}

func rangesOverlap(aStart, aEnd, bStart, bEnd uint64) bool {
	return aStart < bEnd && bStart < aEnd
}

// Query returns a copy of the allocation containing addr, if any.
func (m *Model) Query(addr uint64) (*core.Allocation, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.allocs[addr]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// QueryID returns a copy of an allocation by model ID.
func (m *Model) QueryID(id uint64) (*core.Allocation, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.byID[id]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// Allocations returns allocations sorted by address, optionally filtered.
func (m *Model) Allocations(liveOnly bool) []core.Allocation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]core.Allocation, 0, len(m.allocs))
	for _, a := range m.allocs {
		if liveOnly && a.State != core.StateLive {
			continue
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// Tombstones returns freed ranges sorted by address.
func (m *Model) Tombstones() []Tombstone {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Tombstone, 0, len(m.tombs))
	for _, t := range m.tombs {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// Mappings returns tracked mmap regions sorted by address.
func (m *Model) Mappings() []Mmap {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Mmap, 0, len(m.mmaps))
	for _, mm := range m.mmaps {
		out = append(out, mm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// Stats summarizes the current model.
type Stats struct {
	Allocations int    `json:"allocations"`
	Live        int    `json:"live"`
	Freed       int    `json:"freed"`
	Tombstones  int    `json:"tombstones"`
	Mappings    int    `json:"mappings"`
	Events      uint64 `json:"events"`
}

func (m *Model) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var s Stats
	s.Allocations = len(m.allocs)
	for _, a := range m.allocs {
		if a.State == core.StateLive {
			s.Live++
		} else {
			s.Freed++
		}
	}
	s.Tombstones = len(m.tombs)
	s.Mappings = len(m.mmaps)
	s.Events = m.seq
	return s
}

// AccessResult is a range check performed by callers such as the debugger.
func (m *Model) CheckAccess(addr, size uint64, directionValue uint64, ts time.Time) []core.Finding {
	ev := core.Event{
		Timestamp: ts,
		Type:      core.EventMemAccess,
		Addr:      addr,
		Size:      size,
		Arg2:      directionValue,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkAccess(ev)
}

// Reset clears all model state.
func (m *Model) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allocs = make(map[uint64]*core.Allocation)
	m.byID = make(map[uint64]*core.Allocation)
	m.reuses = make(map[uint64]int)
	m.tombs = make(map[uint64]Tombstone)
	m.mmaps = make(map[uint64]Mmap)
	m.pending = make(map[uint32]pendingMmap)
	m.findings = nil
	m.nextID = 0
	m.seq = 0
}
