package heap

import (
	"sort"
	"sync"
	"time"

	"gofengshui/core"
)

// TimelineConfig controls how allocation history is split into windows.
type TimelineConfig struct {
	WindowEvents int `json:"window_events"`
	WindowMS     int `json:"window_ms"`
	MaxWindows   int `json:"max_windows"`
}

// DefaultTimelineConfig returns the default window sizing.
func DefaultTimelineConfig() TimelineConfig {
	return TimelineConfig{WindowEvents: 1000, WindowMS: 250, MaxWindows: 4096}
}

func (c TimelineConfig) normalized() TimelineConfig {
	if c.WindowEvents <= 0 {
		c.WindowEvents = 1000
	}
	if c.WindowMS <= 0 {
		c.WindowMS = 250
	}
	if c.MaxWindows <= 0 {
		c.MaxWindows = 4096
	}
	return c
}

func (c TimelineConfig) duration() time.Duration {
	return time.Duration(c.WindowMS) * time.Millisecond
}

// ClassWindow is one chunk-size class inside a timeline window.
type ClassWindow struct {
	ChunkSize  uint64  `json:"chunk_size"`
	Live       int     `json:"live"`
	Freed      int     `json:"freed"`
	Alloc      int     `json:"alloc"`
	Free       int     `json:"free"`
	LiveBytes  uint64  `json:"live_bytes"`
	FreedBytes uint64  `json:"freed_bytes"`
	AllocBytes uint64  `json:"alloc_bytes"`
	FreeBytes  uint64  `json:"free_bytes"`
	LiveShare  float64 `json:"live_share,omitempty"`
	ByteShare  float64 `json:"byte_share,omitempty"`
}

// ThreadWindow summarizes one thread inside a timeline window.
type ThreadWindow struct {
	TID        uint32        `json:"tid"`
	Live       int           `json:"live"`
	Freed      int           `json:"freed"`
	Alloc      int           `json:"alloc"`
	Free       int           `json:"free"`
	LiveBytes  uint64        `json:"live_bytes"`
	AllocBytes uint64        `json:"alloc_bytes"`
	Classes    []ClassWindow `json:"classes,omitempty"`
}

// SiteWindow summarizes allocations attributed to one stack ID.
type SiteWindow struct {
	StackID    int32  `json:"stack_id"`
	Live       int    `json:"live"`
	Alloc      int    `json:"alloc"`
	Free       int    `json:"free"`
	LiveBytes  uint64 `json:"live_bytes"`
	AllocBytes uint64 `json:"alloc_bytes"`
}

// ReuseWindow counts address reuse observed inside a window.
type ReuseWindow struct {
	Count     int `json:"count"`
	SameClass int `json:"same_class"`
}

// RateWindow contains per-second event rates for a window.
type RateWindow struct {
	Events      float64 `json:"events"`
	Allocs      float64 `json:"allocs"`
	Frees       float64 `json:"frees"`
	Reallocs    float64 `json:"reallocs"`
	BytesPerSec float64 `json:"bytes_per_sec"`
}

// TimelineWindow is one bounded slice of heap activity. Live fields describe
// the heap state at the end of the window; Alloc/Free/Freed fields describe
// activity during the window.
type TimelineWindow struct {
	ID         uint64          `json:"id"`
	Trigger    string          `json:"trigger"`
	SeqFrom    uint64          `json:"seq_from"`
	SeqTo      uint64          `json:"seq_to"`
	KTimeFrom  uint64          `json:"ktime_from,omitempty"`
	KTimeTo    uint64          `json:"ktime_to,omitempty"`
	WallFrom   time.Time       `json:"wall_from"`
	WallTo     time.Time       `json:"wall_to"`
	DurationMS int64           `json:"duration_ms"`
	Events     int             `json:"events"`
	Allocs     int             `json:"allocs"`
	Frees      int             `json:"frees"`
	Reallocs   int             `json:"reallocs"`
	Mmaps      int             `json:"mmaps"`
	Munmaps    int             `json:"munmaps"`
	AllocFails int             `json:"alloc_fails"`
	Live       int             `json:"live"`
	Freed      int             `json:"freed"`
	Classes    []ClassWindow   `json:"classes,omitempty"`
	Threads    []ThreadWindow  `json:"threads,omitempty"`
	Sites      []SiteWindow    `json:"sites,omitempty"`
	Findings   map[string]int  `json:"findings,omitempty"`
	Content    *ContentSummary `json:"content,omitempty"`
	Reuse      ReuseWindow     `json:"reuse"`
	Rates      RateWindow      `json:"rates"`
}

// Timeline is a concurrency-safe ring of heap-activity windows.
type Timeline struct {
	mu sync.Mutex

	cfg       TimelineConfig
	seq       uint64
	nextID    uint64
	completed uint64

	windows []TimelineWindow
	current *timelineBuilder

	live map[uint64]timelineLive
	seen map[uint64]timelineSeen

	liveTotal       int
	liveClasses     map[uint64]int
	liveClassBytes  map[uint64]uint64
	liveThreads     map[uint32]map[uint64]int
	liveThreadBytes map[uint32]map[uint64]uint64
	liveSites       map[int32]int
	liveSiteBytes   map[int32]uint64
}

type timelineLive struct {
	class   uint64
	tid     uint32
	stackID int32
}

type timelineSeen struct {
	count int
	class uint64
}

type timelineBuilder struct {
	id      uint64
	trigger string

	seqFrom   uint64
	seqTo     uint64
	ktimeFrom uint64
	ktimeTo   uint64
	wallFrom  time.Time
	wallTo    time.Time

	events     int
	allocs     int
	frees      int
	reallocs   int
	mmaps      int
	munmaps    int
	allocFails int
	freed      int
	allocBytes uint64

	classes  map[uint64]*ClassWindow
	threads  map[uint32]*ThreadWindow
	sites    map[int32]*SiteWindow
	findings map[string]int
	content  *ContentSummary
	reuse    ReuseWindow
}

// NewTimeline creates an empty collector.
func NewTimeline(cfg TimelineConfig) *Timeline {
	t := &Timeline{cfg: cfg.normalized()}
	t.resetState()
	return t
}

func (t *Timeline) resetState() {
	t.live = make(map[uint64]timelineLive)
	t.seen = make(map[uint64]timelineSeen)
	t.liveClasses = make(map[uint64]int)
	t.liveClassBytes = make(map[uint64]uint64)
	t.liveThreads = make(map[uint32]map[uint64]int)
	t.liveThreadBytes = make(map[uint32]map[uint64]uint64)
	t.liveSites = make(map[int32]int)
	t.liveSiteBytes = make(map[int32]uint64)
}

// Config returns the active timeline configuration.
func (t *Timeline) Config() TimelineConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

// SetConfig replaces the window sizing. Existing completed windows are kept.
func (t *Timeline) SetConfig(cfg TimelineConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg = cfg.normalized()
	if len(t.windows) > t.cfg.MaxWindows {
		t.windows = t.windows[len(t.windows)-t.cfg.MaxWindows:]
	}
}

// Observe folds one event into the timeline and returns closed windows.
func (t *Timeline) Observe(ev core.Event) []TimelineWindow {
	return t.observe(ev, nil)
}

// ObserveFindings folds an event and its new detector findings into the
// timeline. Findings are attached before a window can close.
func (t *Timeline) ObserveFindings(ev core.Event, findings []string) []TimelineWindow {
	return t.observe(ev, findings)
}

// AddContent merges a content sample into the current window.
func (t *Timeline) AddContent(summary ContentSummary) {
	if summary.Samples == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current == nil {
		return
	}
	if t.current.content == nil {
		cp := summary
		t.current.content = &cp
		return
	}
	merged := MergeContent(t.current.content, &summary)
	t.current.content = &merged
}

// AddFinding attaches a finding ID to the current window.
func (t *Timeline) AddFinding(id string) {
	if id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current != nil {
		t.current.findings[id]++
	}
}

func (t *Timeline) observe(ev core.Event, findings []string) []TimelineWindow {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.seq++
	wall := ev.Timestamp
	if wall.IsZero() {
		wall = time.Now()
	}

	var closed []TimelineWindow
	if t.current != nil && t.current.events > 0 &&
		t.cfg.duration() > 0 && wall.Sub(t.current.wallFrom) >= t.cfg.duration() {
		if w, ok := t.closeLocked("time"); ok {
			closed = append(closed, w)
		}
	}
	if t.current == nil {
		t.nextID++
		t.current = newTimelineBuilder(t.nextID, t.seq, wall)
	}

	t.applyLocked(ev, wall)
	for _, id := range findings {
		if id != "" {
			t.current.findings[id]++
		}
	}

	if t.current.events >= t.cfg.WindowEvents {
		if w, ok := t.closeLocked("events"); ok {
			closed = append(closed, w)
		}
	}
	return closed
}

// Flush closes the current window and returns it, if non-empty.
func (t *Timeline) Flush() []TimelineWindow {
	t.mu.Lock()
	defer t.mu.Unlock()
	if w, ok := t.closeLocked("flush"); ok {
		return []TimelineWindow{w}
	}
	return nil
}

// Completed returns the number of windows closed since construction or Reset.
func (t *Timeline) Completed() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.completed
}

// Windows returns a copy of completed windows.
func (t *Timeline) Windows() []TimelineWindow {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TimelineWindow, len(t.windows))
	copy(out, t.windows)
	return out
}

// Snapshot returns completed windows plus the current partial window.
func (t *Timeline) Snapshot() []TimelineWindow {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TimelineWindow, len(t.windows), len(t.windows)+1)
	copy(out, t.windows)
	if t.current != nil && t.current.events > 0 {
		out = append(out, t.buildWindow(t.current, "current"))
	}
	return out
}

// Reset clears all accumulated timeline state.
func (t *Timeline) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq = 0
	t.nextID = 0
	t.completed = 0
	t.windows = nil
	t.current = nil
	t.resetState()
}

func newTimelineBuilder(id, seq uint64, wall time.Time) *timelineBuilder {
	return &timelineBuilder{
		id:       id,
		seqFrom:  seq,
		seqTo:    seq,
		wallFrom: wall,
		wallTo:   wall,
		classes:  make(map[uint64]*ClassWindow),
		threads:  make(map[uint32]*ThreadWindow),
		sites:    make(map[int32]*SiteWindow),
		findings: make(map[string]int),
	}
}

func (t *Timeline) applyLocked(ev core.Event, wall time.Time) {
	b := t.current
	b.events++
	b.seqTo = t.seq
	if ev.KTime != 0 {
		if b.ktimeFrom == 0 {
			b.ktimeFrom = ev.KTime
		}
		b.ktimeTo = ev.KTime
	}
	if wall.Before(b.wallFrom) {
		b.wallFrom = wall
	}
	if wall.After(b.wallTo) {
		b.wallTo = wall
	}

	switch ev.Type {
	case core.EventAlloc:
		t.applyAllocLocked(ev)
	case core.EventFree, core.EventDoubleFree, core.EventInvalidFree:
		t.applyFreeLocked(ev)
	case core.EventAllocFail:
		b.allocFails++
	case core.EventMmap:
		b.mmaps++
	case core.EventMunmap:
		b.munmaps++
	}
}

func eventChunkClass(ev core.Event) uint64 {
	if ev.Size != 0 {
		return ev.Size
	}
	if ev.ReqSize != 0 {
		return RequestChunkSize(ev.ReqSize)
	}
	return 0
}

func (t *Timeline) applyAllocLocked(ev core.Event) {
	if ev.Addr == 0 {
		return
	}
	b := t.current
	class := eventChunkClass(ev)
	b.allocs++

	if core.AllocOp(ev.Arg2) == core.OpRealloc && ev.Arg1 != 0 {
		b.reallocs++
		if ev.Arg1 == ev.Addr {
			t.applyInPlaceReallocLocked(ev, class)
			return
		}
		t.freeAddrLocked(ev.Arg1, ev, false)
	}
	t.addLiveLocked(ev, class)
}

func (t *Timeline) applyInPlaceReallocLocked(ev core.Event, class uint64) {
	b := t.current
	old, ok := t.live[ev.Addr]
	if !ok {
		t.addLiveLocked(ev, class)
		return
	}

	cw := b.class(class)
	cw.Alloc++
	cw.AllocBytes += class
	b.allocBytes += class
	t.threadAllocLocked(ev.TID, class)
	if ev.StackID != 0 {
		site := t.siteLocked(ev.StackID)
		site.Alloc++
		site.AllocBytes += class
	}
	if seen, ok := t.seen[ev.Addr]; ok {
		seen.class = class
		t.seen[ev.Addr] = seen
	}

	if old.class == class {
		return
	}
	t.liveClassRemove(old.class)
	t.liveClassAdd(class)
	t.threadLiveRemove(old.tid, old.class)
	t.threadLiveAdd(ev.TID, class)
	if old.stackID != 0 {
		t.siteLiveRemove(old.stackID, old.class)
	}
	if ev.StackID != 0 {
		t.siteLiveAdd(ev.StackID, class)
	}
	t.live[ev.Addr] = timelineLive{class: class, tid: ev.TID, stackID: ev.StackID}
}

func (t *Timeline) addLiveLocked(ev core.Event, class uint64) {
	b := t.current
	if old, ok := t.live[ev.Addr]; ok {
		t.removeLiveLocked(ev.Addr, old)
	}

	cw := b.class(class)
	cw.Alloc++
	cw.AllocBytes += class
	b.allocBytes += class
	t.threadAllocLocked(ev.TID, class)
	if ev.StackID != 0 {
		site := t.siteLocked(ev.StackID)
		site.Alloc++
		site.AllocBytes += class
	}

	t.liveTotal++
	t.liveClassAdd(class)
	t.threadLiveAdd(ev.TID, class)
	if ev.StackID != 0 {
		t.siteLiveAdd(ev.StackID, class)
	}

	seen := t.seen[ev.Addr]
	if seen.count > 0 {
		b.reuse.Count++
		if seen.class == class {
			b.reuse.SameClass++
		}
	}
	seen.count++
	seen.class = class
	t.seen[ev.Addr] = seen
	t.live[ev.Addr] = timelineLive{class: class, tid: ev.TID, stackID: ev.StackID}
}

func (t *Timeline) applyFreeLocked(ev core.Event) {
	t.freeAddrLocked(ev.Addr, ev, true)
}

func (t *Timeline) freeAddrLocked(addr uint64, ev core.Event, useEventClass bool) {
	b := t.current
	class := eventChunkClass(ev)
	old, live := t.live[addr]
	if live {
		if old.class != 0 {
			class = old.class
		}
		t.removeLiveLocked(addr, old)
	} else if useEventClass {
		class = eventChunkClass(ev)
	}

	cw := b.class(class)
	cw.Freed++
	cw.Free++
	cw.FreedBytes += class
	cw.FreeBytes += class
	b.frees++
	b.freed++

	tw := t.threadLocked(ev.TID)
	tw.Freed++
	tw.Free++
	twc := threadClass(tw, class)
	twc.Freed++
	twc.Free++
	twc.FreedBytes += class
	twc.FreeBytes += class

	if ev.StackID != 0 {
		site := t.siteLocked(ev.StackID)
		site.Free++
	}
}

func (t *Timeline) removeLiveLocked(addr uint64, old timelineLive) {
	if _, ok := t.live[addr]; !ok {
		return
	}
	delete(t.live, addr)
	if t.liveTotal > 0 {
		t.liveTotal--
	}
	t.liveClassRemove(old.class)
	t.threadLiveRemove(old.tid, old.class)
	if old.stackID != 0 {
		t.siteLiveRemove(old.stackID, old.class)
	}
}

func (t *Timeline) liveClassAdd(class uint64) {
	t.liveClasses[class]++
	t.liveClassBytes[class] += class
}

func (t *Timeline) liveClassRemove(class uint64) {
	if t.liveClasses[class] <= 1 {
		delete(t.liveClasses, class)
	} else {
		t.liveClasses[class]--
	}
	if t.liveClassBytes[class] <= class {
		delete(t.liveClassBytes, class)
	} else {
		t.liveClassBytes[class] -= class
	}
}

func (t *Timeline) threadLiveAdd(tid uint32, class uint64) {
	counts := t.liveThreads[tid]
	if counts == nil {
		counts = make(map[uint64]int)
		t.liveThreads[tid] = counts
	}
	bytes := t.liveThreadBytes[tid]
	if bytes == nil {
		bytes = make(map[uint64]uint64)
		t.liveThreadBytes[tid] = bytes
	}
	counts[class]++
	bytes[class] += class
}

func (t *Timeline) threadLiveRemove(tid uint32, class uint64) {
	counts := t.liveThreads[tid]
	if counts != nil {
		if counts[class] <= 1 {
			delete(counts, class)
		} else {
			counts[class]--
		}
		if len(counts) == 0 {
			delete(t.liveThreads, tid)
		}
	}
	bytes := t.liveThreadBytes[tid]
	if bytes != nil {
		if bytes[class] <= class {
			delete(bytes, class)
		} else {
			bytes[class] -= class
		}
		if len(bytes) == 0 {
			delete(t.liveThreadBytes, tid)
		}
	}
}

func (t *Timeline) siteLiveAdd(stackID int32, class uint64) {
	t.liveSites[stackID]++
	t.liveSiteBytes[stackID] += class
}

func (t *Timeline) siteLiveRemove(stackID int32, class uint64) {
	if t.liveSites[stackID] <= 1 {
		delete(t.liveSites, stackID)
	} else {
		t.liveSites[stackID]--
	}
	if t.liveSiteBytes[stackID] <= class {
		delete(t.liveSiteBytes, stackID)
	} else {
		t.liveSiteBytes[stackID] -= class
	}
}

func (t *Timeline) threadLocked(tid uint32) *ThreadWindow {
	tw := t.current.threads[tid]
	if tw == nil {
		tw = &ThreadWindow{TID: tid}
		t.current.threads[tid] = tw
	}
	return tw
}

func (t *Timeline) threadAllocLocked(tid uint32, class uint64) {
	tw := t.threadLocked(tid)
	tw.Alloc++
	tw.AllocBytes += class
	cw := threadClass(tw, class)
	cw.Alloc++
	cw.AllocBytes += class
}

func (t *Timeline) siteLocked(stackID int32) *SiteWindow {
	sw := t.current.sites[stackID]
	if sw == nil {
		sw = &SiteWindow{StackID: stackID}
		t.current.sites[stackID] = sw
	}
	return sw
}

func (b *timelineBuilder) class(size uint64) *ClassWindow {
	cw := b.classes[size]
	if cw == nil {
		cw = &ClassWindow{ChunkSize: size}
		b.classes[size] = cw
	}
	return cw
}

func threadClass(tw *ThreadWindow, size uint64) *ClassWindow {
	for i := range tw.Classes {
		if tw.Classes[i].ChunkSize == size {
			return &tw.Classes[i]
		}
	}
	tw.Classes = append(tw.Classes, ClassWindow{ChunkSize: size})
	return &tw.Classes[len(tw.Classes)-1]
}

func (t *Timeline) closeLocked(trigger string) (TimelineWindow, bool) {
	if t.current == nil || t.current.events == 0 {
		return TimelineWindow{}, false
	}
	w := t.buildWindow(t.current, trigger)
	t.completed++
	t.windows = append(t.windows, w)
	if len(t.windows) > t.cfg.MaxWindows {
		t.windows = t.windows[len(t.windows)-t.cfg.MaxWindows:]
	}
	t.current = nil
	return w, true
}

func (t *Timeline) buildWindow(b *timelineBuilder, trigger string) TimelineWindow {
	w := TimelineWindow{
		ID:         b.id,
		Trigger:    trigger,
		SeqFrom:    b.seqFrom,
		SeqTo:      b.seqTo,
		KTimeFrom:  b.ktimeFrom,
		KTimeTo:    b.ktimeTo,
		WallFrom:   b.wallFrom,
		WallTo:     b.wallTo,
		Events:     b.events,
		Allocs:     b.allocs,
		Frees:      b.frees,
		Reallocs:   b.reallocs,
		Mmaps:      b.mmaps,
		Munmaps:    b.munmaps,
		AllocFails: b.allocFails,
		Live:       t.liveTotal,
		Freed:      b.freed,
		Reuse:      b.reuse,
	}

	classSet := make(map[uint64]bool, len(b.classes)+len(t.liveClasses))
	for size := range b.classes {
		classSet[size] = true
	}
	for size := range t.liveClasses {
		classSet[size] = true
	}
	totalBytes := uint64(0)
	for _, bytes := range t.liveClassBytes {
		totalBytes += bytes
	}
	w.Classes = make([]ClassWindow, 0, len(classSet))
	for size := range classSet {
		var cw ClassWindow
		if activity := b.classes[size]; activity != nil {
			cw = *activity
		}
		cw.ChunkSize = size
		cw.Live = t.liveClasses[size]
		cw.LiveBytes = t.liveClassBytes[size]
		if t.liveTotal > 0 {
			cw.LiveShare = float64(cw.Live) / float64(t.liveTotal)
		}
		if totalBytes > 0 {
			cw.ByteShare = float64(cw.LiveBytes) / float64(totalBytes)
		}
		w.Classes = append(w.Classes, cw)
	}
	sort.Slice(w.Classes, func(i, j int) bool {
		return w.Classes[i].ChunkSize < w.Classes[j].ChunkSize
	})

	threadSet := make(map[uint32]bool, len(b.threads)+len(t.liveThreads))
	for tid := range b.threads {
		threadSet[tid] = true
	}
	for tid := range t.liveThreads {
		threadSet[tid] = true
	}
	w.Threads = make([]ThreadWindow, 0, len(threadSet))
	for tid := range threadSet {
		var tw ThreadWindow
		if activity := b.threads[tid]; activity != nil {
			tw = *activity
			tw.Classes = append([]ClassWindow(nil), activity.Classes...)
		}
		tw.TID = tid
		counts := t.liveThreads[tid]
		bytes := t.liveThreadBytes[tid]
		tw.Live = 0
		tw.LiveBytes = 0
		for size, count := range counts {
			tw.Live += count
			tw.LiveBytes += bytes[size]
		}
		for size, count := range counts {
			cw := threadClass(&tw, size)
			cw.Live = count
			cw.LiveBytes = bytes[size]
		}
		sort.Slice(tw.Classes, func(i, j int) bool {
			return tw.Classes[i].ChunkSize < tw.Classes[j].ChunkSize
		})
		w.Threads = append(w.Threads, tw)
	}
	sort.Slice(w.Threads, func(i, j int) bool { return w.Threads[i].TID < w.Threads[j].TID })

	siteSet := make(map[int32]bool, len(b.sites)+len(t.liveSites))
	for id := range b.sites {
		siteSet[id] = true
	}
	for id := range t.liveSites {
		siteSet[id] = true
	}
	w.Sites = make([]SiteWindow, 0, len(siteSet))
	for id := range siteSet {
		var sw SiteWindow
		if activity := b.sites[id]; activity != nil {
			sw = *activity
		}
		sw.StackID = id
		sw.Live = t.liveSites[id]
		sw.LiveBytes = t.liveSiteBytes[id]
		w.Sites = append(w.Sites, sw)
	}
	sort.Slice(w.Sites, func(i, j int) bool { return w.Sites[i].StackID < w.Sites[j].StackID })

	if len(b.findings) > 0 {
		w.Findings = make(map[string]int, len(b.findings))
		for id, count := range b.findings {
			w.Findings[id] = count
		}
	}
	if b.content != nil {
		cp := *b.content
		w.Content = &cp
	}

	duration := b.wallTo.Sub(b.wallFrom)
	if duration < 0 {
		duration = 0
	}
	w.DurationMS = duration.Milliseconds()
	seconds := duration.Seconds()
	if b.ktimeFrom != 0 && b.ktimeTo > b.ktimeFrom {
		seconds = float64(b.ktimeTo-b.ktimeFrom) / float64(time.Second)
	}
	if seconds > 0 {
		w.Rates = RateWindow{
			Events:      float64(b.events) / seconds,
			Allocs:      float64(b.allocs) / seconds,
			Frees:       float64(b.frees) / seconds,
			Reallocs:    float64(b.reallocs) / seconds,
			BytesPerSec: float64(b.allocBytes) / seconds,
		}
	}
	return w
}

// ReplayTimeline folds a list of events into a new timeline.
func ReplayTimeline(events []core.Event, cfg TimelineConfig) *Timeline {
	t := NewTimeline(cfg)
	for _, ev := range events {
		t.Observe(ev)
	}
	t.Flush()
	return t
}
