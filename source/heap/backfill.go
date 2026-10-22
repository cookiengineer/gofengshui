package heap

import (
	"encoding/binary"
	"time"

	"gofengshui/core"
)

// MemoryReader reads target memory at addr.
type MemoryReader func(addr uint64, size int) ([]byte, error)

// BackfillStats summarizes an attach-time heap scan.
type BackfillStats struct {
	HeapStart uint64 `json:"heap_start"`
	HeapEnd   uint64 `json:"heap_end"`
	Arenas    int    `json:"arenas,omitempty"`
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
	// Thread arenas keep heap_info and malloc_state before the first chunk,
	// which lands around offset 0x870 on current glibc. Main heaps start much
	// earlier, so scan a window that covers both.
	limit := start + 0x1000
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

func regionMapped(regions []Region, addr uint64) bool {
	for _, r := range regions {
		if addr >= r.Start && addr < r.End {
			return true
		}
	}
	return false
}

// BackfillThreadArenas scans anonymous mappings that look like glibc thread
// arenas and folds their live chunks into the model. It validates the
// heap_info prefix (arena pointer, previous heap, size, mprotect size) before
// scanning to avoid treating thread stacks as heaps.
func (m *Model) BackfillThreadArenas(regions []Region, reader MemoryReader, ts time.Time) BackfillStats {
	total := BackfillStats{}
	for _, r := range regions {
		if r.Path != "" {
			continue
		}
		size := r.End - r.Start
		if size < 0x10000 || size > 0x4400000 {
			continue
		}
		arPtr, ok1 := read64(reader, r.Start)
		prev, ok2 := read64(reader, r.Start+8)
		heapSize, ok3 := read64(reader, r.Start+16)
		mprotectSize, ok4 := read64(reader, r.Start+24)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			continue
		}
		const slack = uint64(0x100000)
		if heapSize < 0x10000 || heapSize%0x1000 != 0 ||
			heapSize+slack < size || heapSize > size+slack {
			continue
		}
		if mprotectSize < heapSize || mprotectSize > heapSize+slack {
			continue
		}
		if arPtr < 0x1000 || !regionMapped(regions, arPtr) {
			continue
		}
		if prev != 0 && !regionMapped(regions, prev) {
			continue
		}
		st := m.BackfillHeap(r.Start, r.End, reader, ts)
		if st.Chunks == 0 {
			continue
		}
		total.Arenas++
		total.Chunks += st.Chunks
		total.Live += st.Live
		total.Bytes += st.Bytes
		total.Skipped += st.Skipped
		if total.HeapStart == 0 {
			total.HeapStart = st.HeapStart
			total.HeapEnd = st.HeapEnd
		} else if st.HeapEnd > total.HeapEnd {
			total.HeapEnd = st.HeapEnd
		}
	}
	return total
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
