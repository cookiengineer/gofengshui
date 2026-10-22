package heap

import (
	"fmt"
	"sort"

	"gofengshui/core"
)

const (
	sizeSZ          = 8
	mallocAlignMask = 15
	minChunkSize    = 32
	// minLargeChunk is glibc's MIN_LARGE_SIZE on x86_64. Chunks below it are
	// inserted directly into smallbins when tcache is full.
	minLargeChunk = 0x400
)

type freeKey struct {
	TID   uint32
	Arena uint64
	Chunk uint64
}

type freeEntry struct {
	Addr   uint64
	TS     int64
	TID    uint32
	Tcache bool
}

// PredictedChunk is one likely future allocation address.
type PredictedChunk struct {
	Rank       int    `json:"rank"`
	Addr       uint64 `json:"addr"`
	ChunkSize  uint64 `json:"chunk_size"`
	TID        uint32 `json:"tid"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

// Prediction describes likely glibc allocator behavior for a request.
type Prediction struct {
	TID         uint32           `json:"tid"`
	RequestSize uint64           `json:"request_size"`
	ChunkSize   uint64           `json:"chunk_size"`
	Glibc       string           `json:"glibc"`
	SafeLinking bool             `json:"safe_linking"`
	Tcache      bool             `json:"tcache"`
	TcacheCount int              `json:"tcache_count"`
	FreePool    int              `json:"free_pool"`
	Observed    bool             `json:"observed,omitempty"`
	Candidates  []PredictedChunk `json:"candidates"`
	Notes       []string         `json:"notes,omitempty"`
}

// RequestChunkSize mirrors glibc request2size for x86_64.
func RequestChunkSize(req uint64) uint64 {
	chunk := (req + sizeSZ + mallocAlignMask) &^ mallocAlignMask
	if chunk < minChunkSize {
		chunk = minChunkSize
	}
	return chunk
}

func (m *Model) recordFree(addr, size uint64, tid uint32, ts int64) {
	if addr == 0 || size == 0 {
		return
	}
	if _, exists := m.freeLoc[addr]; exists {
		return
	}
	tkey := freeKey{TID: tid, Chunk: size}
	tcache := false
	if m.profile.Tcache && size <= m.profile.TcacheMaxChunk {
		n := 0
		for _, e := range m.freeSeq[tkey] {
			if e.Tcache {
				n++
			}
		}
		tcache = n < m.profile.TcacheCount
	}
	k := tkey
	arena, hasArena := m.arenaBase(addr)
	if hasArena {
		m.tidArena[tid] = arena
		if !tcache {
			// Fastbins/smallbins belong to the arena, not the thread.
			k = freeKey{Arena: arena, Chunk: size}
		}
	}
	m.freeSeq[k] = append(m.freeSeq[k], freeEntry{Addr: addr, TS: ts, TID: tid, Tcache: tcache})
	m.freeLoc[addr] = k
}

func (m *Model) consumeFree(addr uint64) (freeEntry, bool) {
	k, ok := m.freeLoc[addr]
	if !ok {
		return freeEntry{}, false
	}
	delete(m.freeLoc, addr)
	list := m.freeSeq[k]
	var consumed freeEntry
	for i, e := range list {
		if e.Addr == addr {
			consumed = e
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(m.freeSeq, k)
	} else {
		m.freeSeq[k] = list
	}
	return consumed, true
}

// Predict returns tcache/free-list candidates for a requested allocation size.
func (m *Model) Predict(tid uint32, reqSize uint64, limit int) Prediction {
	if limit <= 0 {
		limit = 16
	}
	chunk := RequestChunkSize(reqSize)
	p := Prediction{
		TID: tid, RequestSize: reqSize, ChunkSize: chunk,
		Glibc: m.profile.Version, SafeLinking: m.profile.SafeLinking,
		Tcache: m.profile.Tcache,
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var seq []freeEntry
	if tid != 0 {
		seq = append(seq, m.freeSeq[freeKey{TID: tid, Chunk: chunk}]...)
		if arena, ok := m.tidArena[tid]; ok {
			seq = append(seq, m.freeSeq[freeKey{Arena: arena, Chunk: chunk}]...)
		}
	} else {
		for k, list := range m.freeSeq {
			if k.Chunk == chunk {
				seq = append(seq, list...)
			}
		}
	}
	if len(seq) > 1 {
		sort.Slice(seq, func(i, j int) bool { return seq[i].TS < seq[j].TS })
	}
	p.FreePool = len(seq)
	if len(seq) == 0 {
		p.Notes = append(p.Notes, "no tracked frees for this size class")
		return p
	}

	add := func(e freeEntry, source, confidence string) {
		if len(p.Candidates) >= limit {
			return
		}
		p.Candidates = append(p.Candidates, PredictedChunk{
			Rank: len(p.Candidates) + 1, Addr: e.Addr, ChunkSize: chunk,
			TID: e.TID, Source: source, Confidence: confidence,
		})
	}

	if m.profile.Tcache && chunk <= m.profile.TcacheMaxChunk {
		var tcacheSeq, older []freeEntry
		for _, e := range seq {
			if e.Tcache {
				tcacheSeq = append(tcacheSeq, e)
			} else {
				older = append(older, e)
			}
		}
		// tcache is per-thread; only a single-thread prediction is capped.
		// Merged tid=0 views can legitimately contain 7 entries per thread.
		if tid != 0 && len(tcacheSeq) > m.profile.TcacheCount {
			tcacheSeq = tcacheSeq[len(tcacheSeq)-m.profile.TcacheCount:]
		}
		p.TcacheCount = len(tcacheSeq)
		// Tcache is per-thread LIFO: newest free is allocated first.
		for i := len(tcacheSeq) - 1; i >= 0; i-- {
			add(tcacheSeq[i], "tcache-lifo", "high")
		}
		if m.profile.Fastbins && chunk <= m.profile.FastbinMaxChunk {
			// Fastbins are LIFO but only after tcache is exhausted.
			for i := len(older) - 1; i >= 0; i-- {
				add(older[i], "fastbin-lifo", "medium")
			}
		} else if chunk < minLargeChunk {
			// Smallbin-style free chunks are consumed FIFO. This is also the
			// path used by glibc 2.44+, which no longer has fastbins.
			for _, e := range older {
				add(e, "smallbin-fifo", "medium")
			}
		} else {
			// Large frees pass through the unsorted list before being sorted
			// into largebins; keep the ordering advisory.
			for i := len(older) - 1; i >= 0; i-- {
				add(older[i], "free-order", "low")
			}
		}
		p.Notes = append(p.Notes,
			fmt.Sprintf("model: glibc %s tcache LIFO, max %d chunks", m.profile.Version, m.profile.TcacheCount),
		)
		if m.profile.Fastbins {
			p.Notes = append(p.Notes,
				fmt.Sprintf("model: fastbin LIFO for chunk <= 0x%x; smallbin FIFO otherwise", m.profile.FastbinMaxChunk))
		} else {
			p.Notes = append(p.Notes, "model: no fastbins; smallbin FIFO after tcache")
		}
		if m.profile.SafeLinking {
			p.Notes = append(p.Notes, "model: safe-linking enabled (glibc >= 2.32)")
		}
	} else if !m.profile.Tcache {
		if m.profile.Fastbins && chunk <= m.profile.FastbinMaxChunk {
			for i := len(seq) - 1; i >= 0; i-- {
				add(seq[i], "fastbin-lifo", "medium")
			}
		} else {
			for _, e := range seq {
				add(e, "smallbin-fifo", "medium")
			}
		}
		p.Notes = append(p.Notes,
			fmt.Sprintf("model: glibc %s has no tcache", m.profile.Version))
	} else {
		// Larger chunks bypass tcache; exact bin behavior depends on arena state.
		for i := len(seq) - 1; i >= 0; i-- {
			add(seq[i], "free-order", "low")
		}
		p.Notes = append(p.Notes, "model: large-chunk prediction is heuristic")
	}

	if tid == 0 {
		p.Notes = append(p.Notes, "tid 0 merges free sequences from multiple threads")
	}
	return p
}

// PredictObserved builds a prediction from a live tcache snapshot. It falls
// back to the event-derived model when the observed bin is empty or the size
// class is not a small tcache bin.
func PredictObserved(m *Model, intro *Introspection, tid uint32, reqSize uint64, limit int) Prediction {
	if intro == nil || m == nil {
		if m != nil {
			return m.Predict(tid, reqSize, limit)
		}
		return Prediction{RequestSize: reqSize}
	}
	if limit <= 0 {
		limit = 16
	}
	chunk := RequestChunkSize(reqSize)
	p := Prediction{
		TID: tid, RequestSize: reqSize, ChunkSize: chunk,
		Glibc: m.Profile().Version, SafeLinking: m.Profile().SafeLinking,
		Tcache: m.Profile().Tcache, Observed: true,
	}
	if chunk < 32 || chunk > 0x410 {
		p.Observed = false
		fallback := m.Predict(tid, reqSize, limit)
		fallback.Notes = append(fallback.Notes, "observed lookup: size class is not a small tcache bin")
		return fallback
	}
	idx := int((chunk - 32) / 16)
	var entries []uint64
	for _, th := range intro.Threads {
		if tid != 0 && th.TID != tid {
			continue
		}
		for _, bin := range th.Bins {
			if bin.Index == idx {
				entries = append(entries, bin.Entries...)
				break
			}
		}
	}
	if len(entries) == 0 {
		p.Observed = false
		fallback := m.Predict(tid, reqSize, limit)
		fallback.Notes = append(fallback.Notes, "observed tcache bin is empty; using event model")
		return fallback
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}
	for i, addr := range entries {
		p.Candidates = append(p.Candidates, PredictedChunk{
			Rank: i + 1, Addr: addr, ChunkSize: chunk, TID: tid,
			Source: "observed-tcache", Confidence: "high",
		})
	}
	p.TcacheCount = len(entries)
	p.FreePool = len(entries)
	p.Notes = append(p.Notes,
		fmt.Sprintf("observed: live tcache bin %d (%d entries)", idx, len(entries)))
	return p
}

// FreeSequence returns the tracked free order for one thread/size class.
func (m *Model) FreeSequence(tid uint32, chunkSize uint64) []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := append([]freeEntry(nil), m.freeSeq[freeKey{TID: tid, Chunk: chunkSize}]...)
	if arena, ok := m.tidArena[tid]; ok {
		list = append(list, m.freeSeq[freeKey{Arena: arena, Chunk: chunkSize}]...)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].TS < list[j].TS })
	out := make([]uint64, 0, len(list))
	for _, e := range list {
		out = append(out, e.Addr)
	}
	return out
}

// PredictFromEvent is a convenience helper matching the core event timestamp.
func (m *Model) PredictFromEvent(tid uint32, reqSize uint64, limit int, _ core.Event) Prediction {
	return m.Predict(tid, reqSize, limit)
}
