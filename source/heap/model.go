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

// Region is a mapped address range used to classify corrupted free-list
// targets.
type Region struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
	Path  string `json:"path,omitempty"`
}

// Model is a concurrency-safe heap timeline and range index.
type Model struct {
	mu sync.RWMutex

	nextID uint64
	seq    uint64

	allocs  map[uint64]*core.Allocation
	byID    map[uint64]*core.Allocation
	reuses  map[uint64]int
	freeSeq map[freeKey][]freeEntry
	freeLoc map[uint64]freeKey
	tombs   map[uint64]Tombstone
	mmaps   map[uint64]Mmap
	pending map[uint32]pendingMmap
	regions []Region
	profile Profile
	hasMaps bool

	findings []core.Finding
}

func NewModel() *Model {
	return NewModelWithProfile(DefaultProfile())
}

// NewModelWithProfile creates a model using the given allocator profile.
func NewModelWithProfile(p Profile) *Model {
	return &Model{
		allocs:  make(map[uint64]*core.Allocation),
		byID:    make(map[uint64]*core.Allocation),
		reuses:  make(map[uint64]int),
		freeSeq: make(map[freeKey][]freeEntry),
		freeLoc: make(map[uint64]freeKey),
		tombs:   make(map[uint64]Tombstone),
		mmaps:   make(map[uint64]Mmap),
		pending: make(map[uint32]pendingMmap),
		profile: p,
	}
}

// SetProfile replaces the allocator profile. Callers should do this before
// events are folded into the model.
func (m *Model) SetProfile(p Profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.profile = p
}

// Profile returns the active allocator profile.
func (m *Model) Profile() Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.profile
}

// SetRegions records the target's mapped address ranges.
func (m *Model) SetRegions(regions []Region) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.regions = append([]Region(nil), regions...)
	m.hasMaps = true
}

// Apply folds one event into the model and returns any new findings.
func (m *Model) Apply(ev core.Event) []core.Finding {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.seq++
	var out []core.Finding

	switch ev.Type {
	case core.EventAlloc:
		out = append(out, m.applyAlloc(ev)...)
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
		out = append(out, m.checkMetadata(ev)...)
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
		// Invalid frees of untracked pointers are ambiguous after attaching
		// to a running process: the allocation may simply predate the
		// session. Keep the raw event, but only raise a finding when the
		// allocator-side event was not marked unknown.
		if ev.Flags&core.EventFlagUnknown == 0 {
			f := core.Finding{
				ID:        "D1",
				Severity:  "medium",
				Message:   fmt.Sprintf("free of untracked pointer 0x%x", ev.Addr),
				Event:     &ev,
				Timestamp: ev.Timestamp,
			}
			m.findings = append(m.findings, f)
		}
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

func (m *Model) applyAlloc(ev core.Event) []core.Finding {
	if ev.Addr == 0 {
		return nil
	}
	if ev.Size == 0 {
		ev.Size = ev.ReqSize
	}
	if core.AllocOp(ev.Arg2) == core.OpRealloc && ev.Arg1 != 0 {
		if ev.Arg1 == ev.Addr {
			if a := m.allocs[ev.Addr]; a != nil {
				a.ReqSize = ev.ReqSize
				if ev.Size != 0 {
					a.ChunkSize = ev.Size
				}
				a.LastEventID = m.seq
				return nil
			}
		} else {
			m.freeReallocOld(ev.Arg1, ev.Timestamp, ev.TID)
		}
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
	entry, pooled := m.consumeFree(ev.Addr)
	m.allocs[a.Addr] = a
	m.byID[a.ID] = a
	m.reuses[a.Addr]++

	if pooled && entry.Tcache {
		return m.checkTcacheLink(ev, entry, a)
	}
	return nil
}

// checkTcacheLink validates the decoded tcache next pointer of a chunk that
// glibc just popped from tcache. A chunk's next field still holds the old head
// after tcache_get, so corruption of that field is visible at allocation time.
func (m *Model) checkTcacheLink(ev core.Event, entry freeEntry, a *core.Allocation) []core.Finding {
	if !m.profile.Tcache || ev.Flags&core.EventFlagTcacheLink == 0 {
		return nil
	}
	raw := ev.Aux1
	decoded := raw
	if m.profile.SafeLinking {
		decoded = raw ^ (ev.Addr >> 12)
	}
	if decoded == 0 {
		return nil
	}

	severity := "medium"
	class := "unexpected tcache link"
	freeKey, isFree := m.freeLoc[decoded]
	live := m.allocs[decoded]
	switch {
	case decoded%16 != 0:
		severity = "high"
		class = "unaligned tcache link"
	case decoded == ev.Addr:
		severity = "high"
		class = "tcache self-loop"
	case live != nil && live.State == core.StateLive:
		severity = "high"
		class = "tcache link to live allocation"
	case isFree && freeKey.Chunk == ev.Size && freeKey.TID == entry.TID:
		return nil
	case isFree:
		severity = "high"
		class = "cross-size-class tcache link"
	case m.hasMaps && !m.addressMapped(decoded):
		severity = "high"
		class = "tcache link outside mapped memory"
	}

	evCopy := ev
	return []core.Finding{{
		ID:         "D7",
		Severity:   severity,
		Message:    fmt.Sprintf("%s: tcache next 0x%x decoded to 0x%x", class, raw, decoded),
		Event:      &evCopy,
		Allocation: a,
		Timestamp:  ev.Timestamp,
		Details: map[string]any{
			"raw":          raw,
			"decoded":      decoded,
			"safe_linking": m.profile.SafeLinking,
			"glibc":        m.profile.Version,
			"chunk_size":   ev.Size,
			"tid":          entry.TID,
			"taint":        class,
		},
	}}
}

func (m *Model) addressMapped(addr uint64) bool {
	for _, r := range m.regions {
		if addr >= r.Start && addr < r.End {
			return true
		}
	}
	return false
}

// Mapped reports whether addr falls inside a known target mapping.
func (m *Model) Mapped(addr uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.addressMapped(addr)
}

func (m *Model) applyFree(ev core.Event, double bool) {
	if ev.Flags&core.EventFlagUnknown != 0 && m.allocs[ev.Addr] == nil {
		// Unknown pointer after attach: do not fabricate a tombstone.
		return
	}
	if a := m.allocs[ev.Addr]; a != nil {
		a.State = core.StateFreed
		a.FreeTS = ev.Timestamp.UnixNano()
		a.LastEventID = m.seq
		if a.ChunkSize == 0 {
			a.ChunkSize = ev.Size
		}
		m.tombs[a.Addr] = Tombstone{Addr: a.Addr, Size: a.ChunkSize, TS: a.FreeTS, TID: ev.TID}
		if !double {
			m.recordFree(a.Addr, a.ChunkSize, ev.TID, a.FreeTS)
		}
		return
	}
	size := ev.Size
	if size == 0 {
		size = 1
	}
	m.tombs[ev.Addr] = Tombstone{Addr: ev.Addr, Size: size, TS: ev.Timestamp.UnixNano(), TID: ev.TID}
}

// freeReallocOld folds the implicit free performed by a moving realloc into
// the timeline so prediction and UAF checks see the old chunk.
func (m *Model) freeReallocOld(addr uint64, ts time.Time, tid uint32) {
	a := m.allocs[addr]
	if a == nil {
		return
	}
	a.State = core.StateFreed
	a.FreeTS = ts.UnixNano()
	a.LastEventID = m.seq
	if a.ChunkSize == 0 {
		a.ChunkSize = a.ReqSize
	}
	m.tombs[addr] = Tombstone{Addr: addr, Size: a.ChunkSize, TS: a.FreeTS, TID: tid}
	m.recordFree(addr, a.ChunkSize, tid, a.FreeTS)
}

// checkMetadata validates the chunk and next-chunk size words captured at
// free() entry. It catches corrupted size fields and cleared PREV_INUSE bits
// that would otherwise abort inside glibc or go unnoticed.
func (m *Model) checkMetadata(ev core.Event) []core.Finding {
	if ev.Flags&core.EventFlagMetadata == 0 {
		return nil
	}
	rawSize := ev.Aux1 &^ 7
	var out []core.Finding
	evCopy := ev
	if a := m.allocs[ev.Addr]; a != nil && a.ChunkSize != 0 && rawSize != a.ChunkSize {
		ac := *a
		out = append(out, core.Finding{
			ID:         "D9",
			Severity:   "high",
			Message:    fmt.Sprintf("chunk size changed while allocated at 0x%x: expected=0x%x actual=0x%x", ev.Addr, a.ChunkSize, rawSize),
			Event:      &evCopy,
			Allocation: &ac,
			Timestamp:  ev.Timestamp,
			Details: map[string]any{
				"allocation_id": a.ID,
				"expected_size": a.ChunkSize,
				"actual_size":   rawSize,
				"raw_size":      ev.Aux1,
				"glibc":         m.profile.Version,
			},
		})
	}

	var problem string
	switch {
	case rawSize < 0x20 || rawSize%16 != 0 || rawSize > 1<<40:
		problem = "invalid chunk size"
	case ev.Flags&core.EventFlagNextChunk != 0:
		nextSize := ev.Aux2 &^ 7
		if nextSize < 0x20 || nextSize%16 != 0 || nextSize > 1<<40 {
			problem = "invalid next chunk size"
		} else if ev.Aux2&1 == 0 {
			problem = "next chunk PREV_INUSE cleared"
		}
	}
	if problem != "" {
		out = append(out, core.Finding{
			ID:        "D8",
			Severity:  "high",
			Message:   fmt.Sprintf("%s at 0x%x: size=0x%x next=0x%x", problem, ev.Addr, rawSize, ev.Aux2),
			Event:     &evCopy,
			Timestamp: ev.Timestamp,
			Details: map[string]any{
				"raw_size":   ev.Aux1,
				"size":       rawSize,
				"next_raw":   ev.Aux2,
				"next_size":  ev.Aux2 &^ 7,
				"prev_inuse": ev.Aux2&1 != 0,
				"glibc":      m.profile.Version,
			},
		})
	}
	return out
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
	m.freeSeq = make(map[freeKey][]freeEntry)
	m.freeLoc = make(map[uint64]freeKey)
	m.tombs = make(map[uint64]Tombstone)
	m.mmaps = make(map[uint64]Mmap)
	m.pending = make(map[uint32]pendingMmap)
	m.regions = nil
	m.hasMaps = false
	m.findings = nil
	m.nextID = 0
	m.seq = 0
}
