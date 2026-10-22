package heap

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"time"
)

// ThreadTLS identifies one stopped thread and its x86_64 TLS base.
type ThreadTLS struct {
	TID    uint32 `json:"tid"`
	FSBase uint64 `json:"fs_base"`
}

// IntrospectOptions controls a target allocator snapshot.
type IntrospectOptions struct {
	Reader   MemoryReader
	LibcPath string
	LibcBase uint64
	Regions  []Region
	Profile  Profile
	Threads  []ThreadTLS
}

// TcacheBin is one observed per-thread tcache bin. Entries are user pointers
// in allocation order (head first).
type TcacheBin struct {
	Index     int      `json:"index"`
	ChunkSize uint64   `json:"chunk_size,omitempty"`
	Remaining int      `json:"remaining,omitempty"`
	Count     int      `json:"count"`
	Entries   []uint64 `json:"entries"`
	Truncated bool     `json:"truncated,omitempty"`
}

// TcacheSnapshot is the observed tcache state for one thread.
type TcacheSnapshot struct {
	TID         uint32      `json:"tid"`
	FSBase      uint64      `json:"fs_base"`
	Address     uint64      `json:"tcache_addr,omitempty"`
	Layout      string      `json:"layout,omitempty"`
	FillCount   int         `json:"fill_count,omitempty"`
	Initialized bool        `json:"initialized"`
	Bins        []TcacheBin `json:"bins,omitempty"`
	Warnings    []string    `json:"warnings,omitempty"`
}

// ArenaBin is one observed fastbin, smallbin, largebin or unsorted bin.
type ArenaBin struct {
	Index     int      `json:"index"`
	Kind      string   `json:"kind"`
	ChunkSize uint64   `json:"chunk_size,omitempty"`
	Entries   []uint64 `json:"entries"`
	Truncated bool     `json:"truncated,omitempty"`
}

// ArenaSnapshot is the observed state of one glibc arena.
type ArenaSnapshot struct {
	Address   uint64     `json:"addr"`
	Main      bool       `json:"main"`
	Layout    string     `json:"layout,omitempty"`
	Top       uint64     `json:"top,omitempty"`
	SystemMem uint64     `json:"system_mem,omitempty"`
	Bins      []ArenaBin `json:"bins,omitempty"`
	Warnings  []string   `json:"warnings,omitempty"`
}

// Introspection is a point-in-time view of glibc's allocator structures.
type Introspection struct {
	ObservedAt time.Time        `json:"observed_at"`
	Libc       string           `json:"libc,omitempty"`
	LibcBase   uint64           `json:"libc_base,omitempty"`
	Layout     string           `json:"layout,omitempty"`
	Threads    []TcacheSnapshot `json:"threads"`
	Arenas     []ArenaSnapshot  `json:"arenas,omitempty"`
	Warnings   []string         `json:"warnings,omitempty"`
}

type tcacheLayout struct {
	Name          string
	Bins          int
	SlotSize      int
	EntriesOffset uint64
	Size          int
}

var (
	legacyTcacheLayout = tcacheLayout{
		Name: TcacheLayoutLegacy, Bins: 64, SlotSize: 1,
		EntriesOffset: 0x40, Size: 0x240,
	}
	modernTcacheLayout = tcacheLayout{
		Name: TcacheLayoutModern, Bins: 76, SlotSize: 2,
		EntriesOffset: 0x98, Size: 0x2f8,
	}
)

type arenaLayout struct {
	Name            string
	Fastbins        bool
	TopOffset       uint64
	BinsOffset      uint64
	FastbinsOffset  uint64
	SystemMemOffset uint64
}

func arenaLayoutsFor(p Profile) []arenaLayout {
	legacy := arenaLayout{
		Name: "fastbins", Fastbins: true,
		TopOffset: 0x60, BinsOffset: 0x70,
		FastbinsOffset: 0x10, SystemMemOffset: 0x888,
	}
	modern := arenaLayout{
		Name: "no-fastbins", Fastbins: false,
		TopOffset: 0x08, BinsOffset: 0x18,
		SystemMemOffset: 0x830,
	}
	if p.Fastbins {
		return []arenaLayout{legacy, modern}
	}
	return []arenaLayout{modern, legacy}
}

func tcacheLayoutsFor(p Profile) []tcacheLayout {
	if p.TcacheLayout == TcacheLayoutModern {
		return []tcacheLayout{modernTcacheLayout, legacyTcacheLayout}
	}
	return []tcacheLayout{legacyTcacheLayout, modernTcacheLayout}
}

// Introspect reads glibc's tcache and arena state from a stopped target. It
// never fails outright: unsupported or unreadable allocators return a snapshot
// with warnings so callers can fall back to the event-derived model.
func Introspect(opts IntrospectOptions) Introspection {
	now := time.Now()
	out := Introspection{
		ObservedAt: now,
		Libc:       opts.LibcPath,
		LibcBase:   opts.LibcBase,
	}
	observedLayout := ""
	if opts.Reader == nil {
		out.Warnings = append(out.Warnings, "no target memory reader")
		return out
	}
	if !opts.Profile.Tcache {
		out.Warnings = append(out.Warnings, "allocator profile has no tcache")
	}

	offsets, err := tlsRelocationOffsets(opts.LibcPath)
	if err != nil {
		out.Warnings = append(out.Warnings, "tcache TLS relocations: "+err.Error())
	}

	threads := opts.Threads
	if len(threads) == 0 {
		out.Warnings = append(out.Warnings, "no stopped threads supplied")
	}
	for _, th := range threads {
		snap := TcacheSnapshot{TID: th.TID, FSBase: th.FSBase}
		if th.FSBase == 0 {
			snap.Warnings = append(snap.Warnings, "thread has no TLS base")
			out.Threads = append(out.Threads, snap)
			continue
		}
		if len(offsets) == 0 {
			snap.Warnings = append(snap.Warnings, "libc exposes no R_X86_64_TPOFF64 relocations")
			out.Threads = append(out.Threads, snap)
			continue
		}
		addr, layout, candidate, score, fill := locateTcache(opts, th.FSBase, offsets)
		if addr == 0 || score < 1 {
			snap.Warnings = append(snap.Warnings, "tcache TLS slot not found")
			out.Threads = append(out.Threads, snap)
			continue
		}
		snap.Address = addr
		snap.Layout = layout.Name
		snap.FillCount = fill
		if snap.FillCount == 0 {
			snap.FillCount = opts.Profile.TcacheCount
		}
		snap.Bins = candidate
		snap.Initialized = len(candidate) > 0 || score > 1
		out.Threads = append(out.Threads, snap)
		if observedLayout == "" {
			observedLayout = layout.Name
		}
	}
	if observedLayout != "" {
		out.Layout = observedLayout
		// If a version override disagrees with the live tcache layout, use
		// the observed layout for arena field offsets as well.
		opts.Profile.TcacheLayout = observedLayout
	} else {
		out.Layout = opts.Profile.TcacheLayout
	}

	out.Arenas = introspectArenas(opts)
	return out
}

// tlsRelocationOffsets returns the GOT slots used by initial-exec TLS
// references in the target libc. The tcache pointer is one of these slots.
func tlsRelocationOffsets(path string) ([]uint64, error) {
	if path == "" {
		return nil, fmt.Errorf("empty libc path")
	}
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := make(map[uint64]bool)
	var out []uint64
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_RELA {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for off := 0; off+24 <= len(data); off += 24 {
			info := binary.LittleEndian.Uint64(data[off+8:])
			if uint32(info) != uint32(elf.R_X86_64_TPOFF64) {
				continue
			}
			rOffset := binary.LittleEndian.Uint64(data[off:])
			if !seen[rOffset] {
				seen[rOffset] = true
				out = append(out, rOffset)
			}
		}
	}
	return out, nil
}

func locateTcache(opts IntrospectOptions, fsBase uint64, offsets []uint64) (uint64, tcacheLayout, []TcacheBin, int, int) {
	var bestAddr uint64
	var bestLayout tcacheLayout
	var bestBins []TcacheBin
	bestScore := -1
	bestFill := 0
	for _, rOffset := range offsets {
		if rOffset == 0 {
			continue
		}
		slotAddr := opts.LibcBase + rOffset
		raw, ok := read64(opts.Reader, slotAddr)
		if !ok {
			if os.Getenv("GFS_INTROSPECT_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "introspect: read GOT %#x failed\n", slotAddr)
			}
			continue
		}
		tlsOff := int64(raw)
		varAddr := uint64(int64(fsBase) + tlsOff)
		if os.Getenv("GFS_INTROSPECT_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "introspect: got=%#x tls=%d var=%#x\n",
				slotAddr, tlsOff, varAddr)
		}
		if !regionMapped(opts.Regions, varAddr) {
			continue
		}
		ptr, ok := read64(opts.Reader, varAddr)
		if !ok || ptr == 0 || ptr%16 != 0 || !regionMapped(opts.Regions, ptr) {
			continue
		}
		if os.Getenv("GFS_INTROSPECT_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "introspect: tcache ptr=%#x mapped=%v\n",
				ptr, regionMapped(opts.Regions, ptr))
		}
		for _, layout := range tcacheLayoutsFor(opts.Profile) {
			bins, score, fill := readTcache(opts, ptr, layout)
			if os.Getenv("GFS_INTROSPECT_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "introspect: layout=%s score=%d bins=%d fill=%d\n",
					layout.Name, score, len(bins), fill)
			}
			if score > bestScore {
				bestAddr, bestLayout, bestBins, bestScore, bestFill = ptr, layout, bins, score, fill
			}
		}
	}
	return bestAddr, bestLayout, bestBins, bestScore, bestFill
}

func readTcache(opts IntrospectOptions, addr uint64, layout tcacheLayout) ([]TcacheBin, int, int) {
	raw, err := opts.Reader(addr, layout.Size)
	if err != nil || len(raw) < layout.Size {
		return nil, -1, 0
	}
	score := 1 // a structurally valid, possibly empty tcache
	fill := 0
	bins := make([]TcacheBin, 0, layout.Bins)
	for i := 0; i < layout.Bins; i++ {
		var slots int
		if layout.SlotSize == 1 {
			slots = int(raw[i])
			if slots > 64 {
				return nil, -1, 0
			}
		} else {
			slots = int(binary.LittleEndian.Uint16(raw[i*2:]))
			if slots > 4096 {
				return nil, -1, 0
			}
			if slots > fill {
				fill = slots
			}
		}
		entryOff := int(layout.EntriesOffset) + i*8
		if entryOff+8 > len(raw) {
			return nil, -1, 0
		}
		head := binary.LittleEndian.Uint64(raw[entryOff:])
		if head == 0 {
			continue
		}
		if !plausibleUserPointer(opts.Regions, head) {
			return nil, -1, 0
		}
		entries, truncated := bestTcacheList(opts.Reader, opts.Regions, head, 64)
		if len(entries) == 0 {
			return nil, -1, 0
		}
		bin := TcacheBin{
			Index: i, Count: len(entries), Entries: entries, Truncated: truncated,
		}
		if layout.SlotSize == 1 {
			bin.Remaining = int(raw[i])
		} else {
			bin.Remaining = slots
		}
		if i < 64 {
			bin.ChunkSize = uint64(i)*16 + 32
		} else {
			bin.ChunkSize = observedChunkSize(opts.Reader, entries)
		}
		bins = append(bins, bin)
		score += 8 + len(entries)
	}
	// A real tcache_perthread_struct is a live allocation with a chunk header.
	// The inactive dummy in libc .bss has no such header. This extra evidence
	// disambiguates an empty tcache from unrelated TLS pointers.
	if tcacheAllocation(opts.Reader, addr, layout.Size) {
		score += 16
	}
	return bins, score, fill
}

func tcacheAllocation(reader MemoryReader, addr uint64, minSize int) bool {
	if addr < 32 {
		return false
	}
	raw, ok := read64(reader, addr-8)
	if !ok {
		return false
	}
	size := raw &^ 7
	return size >= uint64(minSize) && size%0x10 == 0 && size < 1<<40
}

// bestTcacheList tries both raw and safe-linking interpretations. A version
// override may disagree with the live libc, and a wrong decode usually yields
// a short or invalid chain, so the longer valid chain is the better match.
func bestTcacheList(reader MemoryReader, regions []Region, head uint64, limit int) ([]uint64, bool) {
	raw, rawTrunc := readTcacheList(reader, regions, head, false, limit)
	safe, safeTrunc := readTcacheList(reader, regions, head, true, limit)
	if len(safe) > len(raw) {
		return safe, safeTrunc
	}
	return raw, rawTrunc
}

func readTcacheList(reader MemoryReader, regions []Region, head uint64, safe bool, limit int) ([]uint64, bool) {
	var out []uint64
	seen := make(map[uint64]bool)
	cur := head
	for len(out) < limit {
		if cur == 0 || seen[cur] || !plausibleUserPointer(regions, cur) {
			break
		}
		seen[cur] = true
		out = append(out, cur)
		raw, ok := read64(reader, cur)
		if !ok {
			break
		}
		next := raw
		if safe {
			next = raw ^ (cur >> 12)
		}
		cur = next
	}
	if len(out) == limit {
		return out, true
	}
	return out, false
}

func observedChunkSize(reader MemoryReader, entries []uint64) uint64 {
	if len(entries) == 0 || entries[0] < 16 {
		return 0
	}
	raw, ok := read64(reader, entries[0]-8)
	if !ok {
		return 0
	}
	size := raw &^ 7
	if size < 0x20 || size%0x10 != 0 {
		return 0
	}
	return size
}

func plausibleUserPointer(regions []Region, addr uint64) bool {
	if addr == 0 || addr%16 != 0 {
		return false
	}
	return regionMapped(regions, addr)
}

func introspectArenas(opts IntrospectOptions) []ArenaSnapshot {
	if opts.Reader == nil {
		return nil
	}
	var out []ArenaSnapshot
	seen := make(map[uint64]bool)

	var mainSnap *ArenaSnapshot
	mainScore := 0
	for _, layout := range arenaLayoutsFor(opts.Profile) {
		mainAddr, score := locateMainArena(opts, layout)
		if mainAddr == 0 || seen[mainAddr] || score <= mainScore {
			continue
		}
		snap, ok := readArena(opts, mainAddr, layout, true)
		if !ok {
			continue
		}
		seen[mainAddr] = true
		if os.Getenv("GFS_INTROSPECT_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "introspect: main arena %#x layout=%s bins=%d top=%#x score=%d\n",
				mainAddr, layout.Name, len(snap.Bins), snap.Top, score)
		}
		mainScore = score
		snapCopy := snap
		mainSnap = &snapCopy
	}
	if mainSnap != nil {
		out = append(out, *mainSnap)
	}

	for _, addr := range threadArenaAddresses(opts) {
		if addr == 0 || seen[addr] {
			continue
		}
		seen[addr] = true
		var best *ArenaSnapshot
		bestScore := 0
		for _, layout := range arenaLayoutsFor(opts.Profile) {
			snap, ok := readArena(opts, addr, layout, false)
			if !ok {
				continue
			}
			score := arenaScore(opts, addr, layout)
			if score > bestScore {
				snapCopy := snap
				best = &snapCopy
				bestScore = score
			}
		}
		if best != nil {
			out = append(out, *best)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Main != out[j].Main {
			return out[i].Main
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func locateMainArena(opts IntrospectOptions, layout arenaLayout) (uint64, int) {
	ranges := libcWritableRanges(opts.LibcPath, opts.LibcBase)
	if os.Getenv("GFS_INTROSPECT_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "introspect: libc writable ranges=%v layout=%s\n", ranges, layout.Name)
	}
	var bestAddr uint64
	bestScore := 0
	for _, r := range ranges {
		for addr := r[0]; addr+layout.BinsOffset+0x100 < r[1]; addr += 8 {
			top, ok := read64(opts.Reader, addr+layout.TopOffset)
			if !ok || top == 0 || top%16 != 0 || !regionMapped(opts.Regions, top) {
				continue
			}
			if !plausibleChunk(opts.Reader, top) {
				continue
			}
			score := arenaScore(opts, addr, layout)
			if os.Getenv("GFS_INTROSPECT_DEBUG") != "" && score > 0 {
				fmt.Fprintf(os.Stderr, "introspect: arena candidate=%#x top=%#x score=%d\n",
					addr, top, score)
			}
			if score > bestScore {
				bestAddr, bestScore = addr, score
			}
		}
	}
	if bestScore < 16 {
		return 0, bestScore
	}
	return bestAddr, bestScore
}

func libcWritableRanges(path string, base uint64) [][2]uint64 {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out [][2]uint64
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_W == 0 || p.Memsz == 0 {
			continue
		}
		start := base + p.Vaddr
		out = append(out, [2]uint64{start, start + p.Memsz})
	}
	return out
}

func arenaScore(opts IntrospectOptions, addr uint64, layout arenaLayout) int {
	score := 0
	binsBase := addr + layout.BinsOffset
	for i := 1; i < 128; i++ {
		fd, ok1 := read64(opts.Reader, binsBase+uint64(i-1)*16)
		bk, ok2 := read64(opts.Reader, binsBase+uint64(i-1)*16+8)
		if !ok1 || !ok2 {
			continue
		}
		binAddr := binsBase + uint64(i-1)*16
		sentinel := binAddr - 0x10
		if fd == sentinel && bk == sentinel {
			score += 2
			continue
		}
		if plausibleChunkPointer(opts.Reader, opts.Regions, fd) &&
			plausibleChunkPointer(opts.Reader, opts.Regions, bk) {
			score += 4
		}
	}
	if layout.Fastbins {
		fastBase := addr + layout.FastbinsOffset
		for i := 0; i < 10; i++ {
			p, ok := read64(opts.Reader, fastBase+uint64(i)*8)
			if !ok || p == 0 {
				continue
			}
			if plausibleChunk(opts.Reader, p) {
				score += 2
			}
		}
	}
	return score
}

func readArena(opts IntrospectOptions, addr uint64, layout arenaLayout, main bool) (ArenaSnapshot, bool) {
	snap := ArenaSnapshot{Address: addr, Main: main, Layout: layout.Name}
	top, ok := read64(opts.Reader, addr+layout.TopOffset)
	if !ok || top == 0 || !regionMapped(opts.Regions, top) || !plausibleChunk(opts.Reader, top) {
		return snap, false
	}
	snap.Top = top
	if mem, ok := read64(opts.Reader, addr+layout.SystemMemOffset); ok {
		snap.SystemMem = mem
	}
	binsBase := addr + layout.BinsOffset
	for i := 1; i < 128; i++ {
		binAddr := binsBase + uint64(i-1)*16
		fd, ok := read64(opts.Reader, binAddr)
		if !ok || fd == binAddr-0x10 {
			continue
		}
		entries, truncated := readArenaList(opts, binAddr)
		if len(entries) == 0 {
			continue
		}
		kind := "smallbin"
		if i == 1 {
			kind = "unsorted"
		} else if i >= 64 {
			kind = "largebin"
		}
		snap.Bins = append(snap.Bins, ArenaBin{
			Index: i, Kind: kind, ChunkSize: observedChunkSize(opts.Reader, entries),
			Entries: entries, Truncated: truncated,
		})
	}
	if layout.Fastbins {
		fastBase := addr + layout.FastbinsOffset
		for i := 0; i < 10; i++ {
			p, ok := read64(opts.Reader, fastBase+uint64(i)*8)
			if !ok || p == 0 {
				continue
			}
			entries, truncated := readFastbin(opts, p)
			if len(entries) > 0 {
				snap.Bins = append(snap.Bins, ArenaBin{
					Index: i, Kind: "fastbin", ChunkSize: uint64(i)*16 + 32,
					Entries: entries, Truncated: truncated,
				})
			}
		}
	}
	return snap, true
}

func readArenaList(opts IntrospectOptions, binAddr uint64) ([]uint64, bool) {
	var out []uint64
	seen := make(map[uint64]bool)
	cur, ok := read64(opts.Reader, binAddr) // bin->fd, newest first
	if !ok {
		return nil, false
	}
	for len(out) < 256 {
		if cur == binAddr-0x10 || cur == 0 || seen[cur] || !plausibleUserPointer(opts.Regions, cur) {
			break
		}
		seen[cur] = true
		out = append(out, cur)
		next, ok := read64(opts.Reader, cur) // chunk->fd
		if !ok {
			break
		}
		cur = next
	}
	return out, len(out) == 256
}

func readFastbin(opts IntrospectOptions, head uint64) ([]uint64, bool) {
	raw, rawTrunc := readFastbinMode(opts, head, false)
	safe, safeTrunc := readFastbinMode(opts, head, true)
	if len(safe) > len(raw) {
		return safe, safeTrunc
	}
	return raw, rawTrunc
}

func readFastbinMode(opts IntrospectOptions, head uint64, safe bool) ([]uint64, bool) {
	var out []uint64
	seen := make(map[uint64]bool)
	cur := head
	for len(out) < 256 {
		if cur == 0 || seen[cur] || !plausibleChunk(opts.Reader, cur) {
			break
		}
		seen[cur] = true
		out = append(out, cur+16)
		raw, ok := read64(opts.Reader, cur+16)
		if !ok {
			break
		}
		next := raw
		if safe {
			next = raw ^ ((cur + 16) >> 12)
		}
		cur = next
	}
	return out, len(out) == 256
}

func threadArenaAddresses(opts IntrospectOptions) []uint64 {
	var out []uint64
	for _, r := range opts.Regions {
		if r.Path != "" {
			continue
		}
		size := r.End - r.Start
		if size < 0x10000 || size > 0x4400000 {
			continue
		}
		arPtr, ok1 := read64(opts.Reader, r.Start)
		prev, ok2 := read64(opts.Reader, r.Start+8)
		heapSize, ok3 := read64(opts.Reader, r.Start+16)
		mprotectSize, ok4 := read64(opts.Reader, r.Start+24)
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
		if arPtr < 0x1000 || !regionMapped(opts.Regions, arPtr) {
			continue
		}
		if prev != 0 && !regionMapped(opts.Regions, prev) {
			continue
		}
		out = append(out, arPtr)
	}
	return out
}

func plausibleChunk(reader MemoryReader, addr uint64) bool {
	if addr == 0 || addr%16 != 0 {
		return false
	}
	raw, ok := read64(reader, addr+8)
	if !ok {
		return false
	}
	size := raw &^ 7
	return size >= 0x20 && size%0x10 == 0 && size < 1<<40
}

func plausibleChunkPointer(reader MemoryReader, regions []Region, user uint64) bool {
	if user == 0 {
		return false
	}
	if user%16 != 0 || !regionMapped(regions, user) {
		return false
	}
	raw, ok := read64(reader, user-8)
	if !ok {
		return false
	}
	size := raw &^ 7
	return size >= 0x20 && size%0x10 == 0 && size < 1<<40
}
