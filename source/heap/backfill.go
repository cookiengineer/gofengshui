package heap

import (
	"encoding/binary"
	"time"

	"gofengshui/source/core"
)

// MemoryReader reads target memory at addr.
type MemoryReader func(addr uint64, size int) ([]byte, error)

// BackfillStats summarizes an attach-time heap scan.
type BackfillStats struct {
	HeapStart uint64 `json:"heap_start"`
	HeapEnd   uint64 `json:"heap_end"`
	Chunks    int    `json:"chunks"`
	Live      int    `json:"live"`
	Bytes     uint64 `json:"bytes"`
	Skipped   int    `json:"skipped"`
	Candidate uint64 `json:"candidate"`
}

func read64(reader MemoryReader, addr uint64) (uint64, bool) {
	b, err := reader(addr, 8)
	if err != nil || len(b) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// BackfillHeap scans a glibc main-heap mapping for live chunks and inserts
// them into the model. This is a best-effort recovery for attach mode; it does
// not recover thread arenas, tcache contents, or mmap-backed chunks.
func (m *Model) BackfillHeap(start, end uint64, reader MemoryReader, ts time.Time) BackfillStats {
	st := BackfillStats{HeapStart: start, HeapEnd: end}
	if end <= start || reader == nil {
		return st
	}
	best := 0
	var bestAddr uint64
	var bestChunks []struct {
		addr  uint64
		size  uint64
		inUse bool
	}
	limit := start + 0x200
	if limit > end {
		limit = end
	}
	for cand := start; cand < limit; cand += 0x10 {
		chunks, score := scanChunks(cand, end, reader)
		if score > best {
			best = score
			bestAddr = cand
			bestChunks = chunks
		}
	}
	st.Candidate = bestAddr
	if best == 0 {
		return st
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range bestChunks {
		st.Chunks++
		if !c.inUse {
			continue
		}
		ptr := c.addr + 0x10
		if _, exists := m.allocs[ptr]; exists {
			continue
		}
		m.nextID++
		a := &core.Allocation{
			ID: m.nextID, Addr: ptr, ReqSize: c.size - 8, ChunkSize: c.size,
			Allocator: "glibc-backfill", State: core.StateLive, TID: 0,
			AllocTS: ts.UnixNano(), Generation: m.nextID,
		}
		m.allocs[ptr] = a
		m.byID[a.ID] = a
		st.Live++
		st.Bytes += c.size
	}
	return st
}

func scanChunks(start, end uint64, reader MemoryReader) ([]struct {
	addr  uint64
	size  uint64
	inUse bool
}, int) {
	var out []struct {
		addr  uint64
		size  uint64
		inUse bool
	}
	addr := start
	for i := 0; i < 4096; i++ {
		if addr < start || addr+0x10 > end {
			break
		}
		raw, ok := read64(reader, addr+8)
		if !ok {
			break
		}
		size := raw &^ 7
		if size < 0x20 || size%0x10 != 0 {
			break
		}
		next := addr + size
		if next < addr || next >= end {
			break
		}
		nextRaw, ok := read64(reader, next+8)
		if !ok {
			break
		}
		nextSize := nextRaw &^ 7
		if nextSize < 0x20 || nextSize%0x10 != 0 {
			break
		}
		inUse := nextRaw&1 != 0
		out = append(out, struct {
			addr  uint64
			size  uint64
			inUse bool
		}{addr: addr, size: size, inUse: inUse})
		if next+nextSize >= end {
			// Top chunk reached; it is not an allocation.
			break
		}
		addr = next
	}
	return out, len(out)
}
