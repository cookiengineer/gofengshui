package heap

import (
	"sort"

	"gofengshui/source/core"
)

const (
	sizeSZ          = 8
	mallocAlignMask = 15
	minChunkSize    = 32
	tcacheMaxChunk  = 0x410
	tcacheCount     = 7
	fastbinMaxChunk = 0x80
)

type freeKey struct {
	TID   uint32
	Chunk uint64
}

type freeEntry struct {
	Addr uint64
	TS   int64
	TID  uint32
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
	TcacheCount int              `json:"tcache_count"`
	FreePool    int              `json:"free_pool"`
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
	k := freeKey{TID: tid, Chunk: size}
	m.freeSeq[k] = append(m.freeSeq[k], freeEntry{Addr: addr, TS: ts, TID: tid})
	m.freeLoc[addr] = k
}

func (m *Model) consumeFree(addr uint64) {
	k, ok := m.freeLoc[addr]
	if !ok {
		return
	}
	delete(m.freeLoc, addr)
	list := m.freeSeq[k]
	for i, e := range list {
		if e.Addr == addr {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(m.freeSeq, k)
	} else {
		m.freeSeq[k] = list
	}
}

// Predict returns tcache/free-list candidates for a requested allocation size.
func (m *Model) Predict(tid uint32, reqSize uint64, limit int) Prediction {
	if limit <= 0 {
		limit = 16
	}
	chunk := RequestChunkSize(reqSize)
	p := Prediction{TID: tid, RequestSize: reqSize, ChunkSize: chunk}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var seq []freeEntry
	if tid != 0 {
		seq = append(seq, m.freeSeq[freeKey{TID: tid, Chunk: chunk}]...)
	} else {
		for k, list := range m.freeSeq {
			if k.Chunk == chunk {
				seq = append(seq, list...)
			}
		}
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

	if chunk <= tcacheMaxChunk {
		tc := len(seq)
		if tc > tcacheCount {
			tc = tcacheCount
		}
		p.TcacheCount = tc
		// Tcache is per-thread LIFO: newest free is allocated first.
		for i := len(seq) - 1; i >= len(seq)-tc; i-- {
			add(seq[i], "tcache-lifo", "high")
		}
		older := seq[:len(seq)-tc]
		if chunk <= fastbinMaxChunk {
			// Fastbins are LIFO but only after tcache is exhausted.
			for i := len(older) - 1; i >= 0; i-- {
				add(older[i], "fastbin-lifo", "medium")
			}
		} else {
			// Smallbin-style free chunks are consumed FIFO.
			for _, e := range older {
				add(e, "smallbin-fifo", "medium")
			}
		}
		p.Notes = append(p.Notes,
			"model: glibc tcache LIFO, max 7 chunks",
			"model: fastbin LIFO for chunk <= 0x80; smallbin FIFO otherwise",
		)
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

// FreeSequence returns the tracked free order for one thread/size class.
func (m *Model) FreeSequence(tid uint32, chunkSize uint64) []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := m.freeSeq[freeKey{TID: tid, Chunk: chunkSize}]
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
