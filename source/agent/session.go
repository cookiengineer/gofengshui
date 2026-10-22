package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gofengshui/source/core"
	"gofengshui/source/debugger"
	"gofengshui/source/detect"
	"gofengshui/source/disasm"
	"gofengshui/source/ebpf"
	"gofengshui/source/export"
	"gofengshui/source/heap"
	"gofengshui/source/proto"
	"gofengshui/source/symbols"
	"gofengshui/source/transport"
)

// StreamEvent is the payload of a protocol event frame.
type StreamEvent struct {
	Kind    string         `json:"kind"`
	Event   *core.Event    `json:"event,omitempty"`
	Finding *core.Finding  `json:"finding,omitempty"`
	Stop    *debugger.Stop `json:"stop,omitempty"`
	Sink    *SinkHit       `json:"sink,omitempty"`
	ROP     *ROPResult     `json:"rop,omitempty"`
	Marker  string         `json:"marker,omitempty"`
	Message string         `json:"message,omitempty"`
}

type subscriber struct {
	conn *transport.Conn
	ch   chan *proto.Frame
	done chan struct{}
	once sync.Once
}

// Marker is a host-visible phase marker in the timeline.
type Marker struct {
	Label string    `json:"label"`
	Seq   uint64    `json:"seq"`
	TS    time.Time `json:"ts"`
}

// Session owns a target, an eBPF tracer, a ptrace tracer and a heap model.
type Session struct {
	id       string
	agent    *Agent
	cfg      core.Config
	target   core.Target
	resolver *symbols.Resolver
	tracer   *debugger.Tracer
	bpf      *ebpf.Tracer
	engine   *detect.Engine
	model    *heap.Model
	files    []*os.File

	mu       sync.Mutex
	subs     map[uint64]*subscriber
	nextSub  uint64
	seq      uint64
	history  []*proto.Frame
	eventLog []*proto.Frame
	closed   bool
	done     chan struct{}

	stops chan debugger.Stop

	markers  []Marker
	sink     *SinkInfo
	hijack   *HijackState
	rop      *ROPState
	lastROP  *ROPResult
	lastSink *SinkHit
	lastStop *debugger.Stop
	ropDone  chan *ROPResult
	started  time.Time
}

func detectEngine(m *heap.Model) *detect.Engine { return detect.New(m) }

func (s *Session) start() {
	go s.pump()
}

func (s *Session) pump() {
	var events <-chan core.Event
	var bpfErrs <-chan error
	if s.bpf != nil {
		events = s.bpf.Events()
		bpfErrs = s.bpf.Errors()
	}
	tracerStops := s.tracer.Stops()
	tracerErrs := s.tracer.Errors()
	for {
		select {
		case <-s.done:
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			s.broadcast("event", StreamEvent{Kind: "event", Event: &ev})
			for _, f := range s.engine.Observe(ev) {
				fc := f
				s.broadcast("finding", StreamEvent{Kind: "finding", Finding: &fc})
			}
		case err, ok := <-bpfErrs:
			if !ok {
				bpfErrs = nil
				continue
			}
			s.broadcast("error", StreamEvent{Kind: "error", Message: "ebpf: " + err.Error()})
		case st, ok := <-tracerStops:
			if !ok {
				tracerStops = nil
				continue
			}
			s.handleStop(st)
		case err, ok := <-tracerErrs:
			if !ok {
				tracerErrs = nil
				continue
			}
			s.broadcast("error", StreamEvent{Kind: "error", Message: "ptrace: " + err.Error()})
		}
	}
}

func (s *Session) handleStop(st debugger.Stop) {
	s.mu.Lock()
	s.lastStop = &st
	s.mu.Unlock()
	s.broadcast("stop", StreamEvent{Kind: "stop", Stop: &st})

	select {
	case s.stops <- st:
	default:
	}

	s.hijackStop(st)
	s.mu.Lock()
	rop := s.rop
	sink := s.sink
	s.mu.Unlock()
	if rop != nil {
		s.ropStop(st)
		return
	}
	if sink != nil && st.Breakpoint != nil && st.Breakpoint.Addr == sink.Addr {
		hit := s.captureSink(st)
		if hit != nil {
			s.mu.Lock()
			s.lastSink = hit
			s.mu.Unlock()
			s.broadcast("sink", StreamEvent{Kind: "sink", Sink: hit})
		}
	}
}

func (s *Session) broadcast(kind string, payload StreamEvent) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.seq++
	payload.Kind = kind
	frame := proto.EventFrame(s.id, s.seq, payload)
	s.history = append(s.history, frame)
	if len(s.history) > 20000 {
		s.history = s.history[len(s.history)-10000:]
	}
	s.eventLog = append(s.eventLog, frame)
	if len(s.eventLog) > 100000 {
		s.eventLog = s.eventLog[len(s.eventLog)-50000:]
	}
	subs := make([]*subscriber, 0, len(s.subs))
	for _, sub := range s.subs {
		subs = append(subs, sub)
	}
	s.mu.Unlock()

	for _, sub := range subs {
		select {
		case sub.ch <- frame:
		default:
		}
	}
}

func (s *Session) subscribe(conn *transport.Conn, since uint64) uint64 {
	s.mu.Lock()
	s.nextSub++
	id := s.nextSub
	sub := &subscriber{conn: conn, ch: make(chan *proto.Frame, 8192), done: make(chan struct{})}
	s.subs[id] = sub
	for _, f := range s.history {
		if f.Seq > since {
			select {
			case sub.ch <- f:
			default:
			}
		}
	}
	s.mu.Unlock()
	go s.subWriter(sub)
	return id
}

func (s *Session) subWriter(sub *subscriber) {
	for {
		select {
		case f := <-sub.ch:
			if err := sub.conn.Write(f); err != nil {
				s.removeSub(sub)
				return
			}
		case <-sub.done:
			return
		case <-s.done:
			return
		}
	}
}

func (s *Session) removeSub(sub *subscriber) {
	sub.once.Do(func() { close(sub.done) })
	s.mu.Lock()
	for id, x := range s.subs {
		if x == sub {
			delete(s.subs, id)
		}
	}
	s.mu.Unlock()
}

// Handle dispatches one session-bound request.
func (s *Session) Handle(ctx context.Context, conn *transport.Conn, f *proto.Frame) {
	switch f.Method {
	case proto.MethodSessionStatus:
		s.status(conn, f)
	case proto.MethodEventsSubscribe:
		var p struct {
			Since uint64 `json:"since"`
		}
		_ = f.DecodeParams(&p)
		id := s.subscribe(conn, p.Since)
		s.reply(conn, f, map[string]any{"subscriber": id, "seq": s.currentSeq()}, nil)
	case proto.MethodHeapQuery:
		s.heapQuery(conn, f)
	case proto.MethodHeapSnapshot:
		s.heapSnapshot(conn, f)
	case proto.MethodMemRead:
		s.memRead(conn, f)
	case proto.MethodMemWrite:
		s.memWrite(conn, f)
	case proto.MethodRegsGet:
		s.regsGet(conn, f)
	case proto.MethodStackGet:
		s.stackGet(conn, f)
	case proto.MethodBreakSet:
		s.breakSet(conn, f)
	case proto.MethodBreakClear:
		s.breakClear(conn, f)
	case proto.MethodWatchSet:
		s.watchSet(conn, f)
	case proto.MethodWatchClear:
		s.watchClear(conn, f)
	case proto.MethodPause:
		s.pause(conn, f)
	case proto.MethodResume:
		s.resume(conn, f)
	case proto.MethodStep:
		s.step(conn, f)
	case proto.MethodMark:
		s.mark(conn, f)
	case proto.MethodSinkRegister:
		s.sinkRegister(conn, f)
	case proto.MethodHijackWatch:
		s.hijackWatch(conn, f)
	case proto.MethodRopArm:
		s.ropArm(conn, f)
	case proto.MethodWait:
		s.wait(conn, f)
	case proto.MethodAssert:
		s.assert(conn, f)
	case proto.MethodExport:
		s.exportSession(conn, f)
	default:
		s.reply(conn, f, nil, &proto.Error{Code: "unknown_method", Message: f.Method})
	}
}

func (s *Session) reply(conn *transport.Conn, f *proto.Frame, result any, err *proto.Error) {
	if err != nil {
		_ = conn.Write(proto.ErrorFrame(f.ID, err.Code, err.Message))
		return
	}
	fr, e := proto.Result(f.ID, result)
	if e != nil {
		_ = conn.Write(proto.ErrorFrame(f.ID, "marshal", e.Error()))
		return
	}
	_ = conn.Write(fr)
}

func (s *Session) currentSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

func (s *Session) status(conn *transport.Conn, f *proto.Frame) {
	s.mu.Lock()
	last := s.lastStop
	sink := s.sink
	rop := s.lastROP
	s.mu.Unlock()
	s.reply(conn, f, map[string]any{
		"session":   s.id,
		"target":    s.target,
		"config":    s.cfg,
		"stats":     s.model.Stats(),
		"last_stop": last,
		"sink":      sink,
		"rop":       rop,
		"uptime":    time.Since(s.started).String(),
	}, nil)
}

func (s *Session) heapQuery(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Addr  uint64 `json:"addr"`
		ID    uint64 `json:"id"`
		Live  bool   `json:"live"`
		Limit int    `json:"limit"`
	}
	_ = f.DecodeParams(&p)
	if p.ID != 0 {
		a, ok := s.model.QueryID(p.ID)
		if !ok {
			s.reply(conn, f, nil, &proto.Error{Code: "not_found", Message: "allocation not found"})
			return
		}
		s.reply(conn, f, a, nil)
		return
	}
	if p.Addr != 0 {
		a, ok := s.model.Query(p.Addr)
		if !ok {
			s.reply(conn, f, nil, &proto.Error{Code: "not_found", Message: "address not tracked"})
			return
		}
		s.reply(conn, f, a, nil)
		return
	}
	allocs := s.model.Allocations(p.Live)
	if p.Limit > 0 && len(allocs) > p.Limit {
		allocs = allocs[:p.Limit]
	}
	s.reply(conn, f, map[string]any{
		"allocations": allocs,
		"tombstones":  s.model.Tombstones(),
		"mappings":    s.model.Mappings(),
		"stats":       s.model.Stats(),
	}, nil)
}

func (s *Session) heapSnapshot(conn *transport.Conn, f *proto.Frame) {
	s.reply(conn, f, map[string]any{
		"target":      s.target,
		"allocations": s.model.Allocations(false),
		"tombstones":  s.model.Tombstones(),
		"mappings":    s.model.Mappings(),
		"stats":       s.model.Stats(),
		"findings":    s.engine.Recent(),
	}, nil)
}

func (s *Session) memRead(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		TID  int    `json:"tid"`
		Addr uint64 `json:"addr"`
		Size int    `json:"size"`
	}
	_ = f.DecodeParams(&p)
	if p.Size <= 0 || p.Size > 1<<20 {
		s.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: "invalid size"})
		return
	}
	data, err := s.tracer.ReadMemory(p.Addr, p.Size)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "read_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, map[string]any{"addr": p.Addr, "data": hex.EncodeToString(data)}, nil)
}

func (s *Session) memWrite(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Addr uint64 `json:"addr"`
		Data string `json:"data"`
	}
	_ = f.DecodeParams(&p)
	data, err := hex.DecodeString(p.Data)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: err.Error()})
		return
	}
	if err := s.tracer.WriteMemory(p.Addr, data); err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "write_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, map[string]any{"addr": p.Addr, "size": len(data)}, nil)
}

func (s *Session) regsGet(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		TID int `json:"tid"`
	}
	_ = f.DecodeParams(&p)
	regs, err := s.tracer.GetRegisters(p.TID)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "regs_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, regs, nil)
}

func (s *Session) stackGet(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		TID   int `json:"tid"`
		Words int `json:"words"`
	}
	_ = f.DecodeParams(&p)
	if p.Words <= 0 {
		p.Words = 16
	}
	regs, err := s.tracer.GetRegisters(p.TID)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "regs_failed", Message: err.Error()})
		return
	}
	data, err := s.tracer.ReadMemory(regs.RSP, p.Words*8)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "read_failed", Message: err.Error()})
		return
	}
	words := make([]uint64, 0, p.Words)
	for i := 0; i+8 <= len(data); i += 8 {
		var v uint64
		for j := 7; j >= 0; j-- {
			v = v<<8 | uint64(data[i+j])
		}
		words = append(words, v)
	}
	s.reply(conn, f, map[string]any{"rsp": regs.RSP, "words": words}, nil)
}

func (s *Session) breakSet(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Addr     uint64 `json:"addr"`
		Symbol   string `json:"symbol"`
		Module   string `json:"module"`
		Hardware *bool  `json:"hardware"`
	}
	_ = f.DecodeParams(&p)
	addr := p.Addr
	if addr == 0 {
		if p.Symbol == "" {
			s.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: "addr or symbol required"})
			return
		}
		a, err := s.resolveSymbol(p.Module, p.Symbol)
		if err != nil {
			s.reply(conn, f, nil, &proto.Error{Code: "symbol", Message: err.Error()})
			return
		}
		addr = a
	}
	hw := true
	if p.Hardware != nil {
		hw = *p.Hardware
	}
	bp, err := s.tracer.SetBreakpoint(addr, p.Symbol, hw)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "break_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, bp, nil)
}

func (s *Session) breakClear(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Addr   uint64 `json:"addr"`
		Symbol string `json:"symbol"`
		Module string `json:"module"`
	}
	_ = f.DecodeParams(&p)
	addr := p.Addr
	if addr == 0 && p.Symbol != "" {
		a, err := s.resolveSymbol(p.Module, p.Symbol)
		if err != nil {
			s.reply(conn, f, nil, &proto.Error{Code: "symbol", Message: err.Error()})
			return
		}
		addr = a
	}
	if err := s.tracer.ClearBreakpoint(addr); err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "break_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, map[string]any{"cleared": addr}, nil)
}

func (s *Session) watchSet(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Addr    uint64 `json:"addr"`
		Size    uint64 `json:"size"`
		Type    string `json:"type"`
		AllocID uint64 `json:"alloc_id"`
	}
	_ = f.DecodeParams(&p)
	if p.AllocID != 0 && p.Addr == 0 {
		a, ok := s.model.QueryID(p.AllocID)
		if !ok {
			s.reply(conn, f, nil, &proto.Error{Code: "not_found", Message: "allocation not found"})
			return
		}
		p.Addr = a.Addr
		if p.Size == 0 {
			p.Size = a.ChunkSize
		}
	}
	if p.Size == 0 {
		p.Size = 8
	}
	typ := debugger.WatchType(p.Type)
	if typ == "" {
		typ = debugger.WatchAccess
	}
	wp, err := s.tracer.SetWatchpoint(p.Addr, p.Size, typ, p.AllocID)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "watch_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, wp, nil)
}

func (s *Session) watchClear(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		ID uint64 `json:"id"`
	}
	_ = f.DecodeParams(&p)
	if err := s.tracer.ClearWatchpoint(p.ID); err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "watch_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, map[string]any{"cleared": p.ID}, nil)
}

func (s *Session) pause(conn *transport.Conn, f *proto.Frame) {
	if err := s.tracer.Pause(); err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "pause_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, map[string]any{"paused": true}, nil)
}

func (s *Session) resume(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		TID int `json:"tid"`
	}
	_ = f.DecodeParams(&p)
	if err := s.tracer.Continue(p.TID); err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "resume_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, map[string]any{"resumed": true}, nil)
}

func (s *Session) step(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		TID   int `json:"tid"`
		Count int `json:"count"`
	}
	_ = f.DecodeParams(&p)
	if p.TID == 0 {
		p.TID = s.tracer.PID()
	}
	if p.Count <= 0 {
		p.Count = 1
	}
	if p.Count == 1 {
		if err := s.tracer.SingleStep(p.TID); err != nil {
			s.reply(conn, f, nil, &proto.Error{Code: "step_failed", Message: err.Error()})
			return
		}
		s.reply(conn, f, map[string]any{"stepping": p.TID, "count": 1}, nil)
		return
	}
	go func() {
		for i := 0; i < p.Count; i++ {
			if err := s.tracer.SingleStep(p.TID); err != nil {
				return
			}
			select {
			case <-s.stops:
			case <-time.After(2 * time.Second):
				return
			case <-s.done:
				return
			}
		}
	}()
	s.reply(conn, f, map[string]any{"stepping": p.TID, "count": p.Count}, nil)
}

func (s *Session) mark(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Label string `json:"label"`
	}
	_ = f.DecodeParams(&p)
	s.mu.Lock()
	s.seq++
	m := Marker{Label: p.Label, Seq: s.seq, TS: time.Now()}
	s.markers = append(s.markers, m)
	s.mu.Unlock()
	s.broadcast("marker", StreamEvent{Kind: "marker", Marker: p.Label})
	s.reply(conn, f, m, nil)
}

func (s *Session) wait(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Type      string `json:"type"`
		ID        string `json:"id"`
		Name      string `json:"name"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	_ = f.DecodeParams(&p)
	timeout := time.Duration(p.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		sink := s.lastSink
		rop := s.lastROP
		s.mu.Unlock()
		if p.Type == "sink" && sink != nil && (p.Name == "" || sink.Name == p.Name) {
			s.reply(conn, f, map[string]any{"matched": true, "sink": sink}, nil)
			return
		}
		if p.Type == "rop" && rop != nil {
			s.reply(conn, f, map[string]any{"matched": true, "rop": rop}, nil)
			return
		}
		if p.Type == "finding" || p.Type == "" {
			for _, finding := range s.engine.Recent() {
				if p.ID == "" || finding.ID == p.ID {
					s.reply(conn, f, map[string]any{"matched": true, "finding": finding}, nil)
					return
				}
			}
		}
		if time.Now().After(deadline) {
			s.reply(conn, f, map[string]any{"matched": false, "timeout": true}, nil)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *Session) assert(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Assertions []detect.Assertion `json:"assertions"`
	}
	_ = f.DecodeParams(&p)
	results := make([]map[string]any, 0, len(p.Assertions))
	all := true
	for _, a := range p.Assertions {
		ok, msg := s.engine.Check(a)
		if a.Type == "sink" {
			s.mu.Lock()
			sink := s.lastSink
			s.mu.Unlock()
			ok = sink != nil && (a.Symbol == "" || sink.Name == a.Symbol)
			if !ok {
				msg = "sink not reached"
			}
			if ok && len(a.Regs) > 0 {
				for name, want := range a.Regs {
					if got := sink.Register(name); got != want {
						ok = false
						msg = fmt.Sprintf("register %s: got 0x%x want 0x%x", name, got, want)
					}
				}
			}
		}
		if a.Type == "rop" {
			s.mu.Lock()
			rop := s.lastROP
			s.mu.Unlock()
			ok = rop != nil && rop.Verified
			if !ok {
				msg = "ROP chain not verified"
			}
		}
		if !ok {
			all = false
		}
		results = append(results, map[string]any{"assertion": a, "ok": ok, "message": msg})
	}
	s.reply(conn, f, map[string]any{"ok": all, "results": results}, nil)
}

func (s *Session) exportSession(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Dir string `json:"dir"`
	}
	_ = f.DecodeParams(&p)
	if p.Dir == "" {
		p.Dir = filepath.Join("build", "reports", s.id)
	}
	s.mu.Lock()
	frames := make([]*proto.Frame, len(s.eventLog))
	copy(frames, s.eventLog)
	rop := s.lastROP
	sink := s.lastSink
	markers := append([]Marker(nil), s.markers...)
	s.mu.Unlock()

	res := map[string]any{}
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "export_failed", Message: err.Error()})
		return
	}
	if err := export.JSONL(filepath.Join(p.Dir, "events.jsonl"), frames); err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "export_failed", Message: err.Error()})
		return
	}
	res["events"] = filepath.Join(p.Dir, "events.jsonl")
	if err := export.JSON(filepath.Join(p.Dir, "heap.json"), map[string]any{
		"allocations": s.model.Allocations(false),
		"tombstones":  s.model.Tombstones(),
		"mappings":    s.model.Mappings(),
		"stats":       s.model.Stats(),
		"findings":    s.engine.Recent(),
	}); err == nil {
		res["heap"] = filepath.Join(p.Dir, "heap.json")
	}
	if rop != nil {
		if err := export.JSON(filepath.Join(p.Dir, "rop.json"), rop); err == nil {
			res["rop"] = filepath.Join(p.Dir, "rop.json")
		}
	}
	if err := export.JSON(filepath.Join(p.Dir, "summary.json"), map[string]any{
		"session": s.id, "target": s.target, "config": s.cfg,
		"stats": s.model.Stats(), "sink": sink, "rop": rop, "markers": markers,
	}); err == nil {
		res["summary"] = filepath.Join(p.Dir, "summary.json")
	}
	if err := export.Report(filepath.Join(p.Dir, "report.md"), s.id, s.target, s.model.Stats(), sink, rop, s.engine.Recent()); err == nil {
		res["report"] = filepath.Join(p.Dir, "report.md")
	}
	s.reply(conn, f, res, nil)
}

func (s *Session) resolveSymbol(module, name string) (uint64, error) {
	if s.resolver == nil {
		return 0, fmt.Errorf("no resolver")
	}
	sym, m, ok := s.resolver.Name(module, name)
	if !ok {
		return 0, fmt.Errorf("symbol %s not found", name)
	}
	return m.RuntimeAddr(sym), nil
}

func (s *Session) symbolize(addr uint64) (string, string, uint64, bool) {
	if s.resolver == nil {
		return "", "", 0, false
	}
	info := s.resolver.Addr(addr)
	if info.ModulePath == "" {
		return "", "", 0, false
	}
	return filepath.Base(info.ModulePath), info.Symbol, info.Offset, info.Symbol != ""
}

func (s *Session) executable(addr uint64) bool {
	if s.resolver == nil {
		return false
	}
	m := s.resolver.ModuleFor(addr)
	if m == nil {
		return false
	}
	for _, mm := range m.Maps {
		if mm.Contains(addr) {
			return len(mm.Perm) >= 3 && mm.Perm[2] == 'x'
		}
	}
	return false
}

func (s *Session) readMemory(addr uint64, size int) ([]byte, error) {
	return s.tracer.ReadMemory(addr, size)
}

func (s *Session) chain(base uint64, words int) ([]disasm.ChainEntry, error) {
	data, err := s.tracer.ReadMemory(base, words*8)
	if err != nil {
		return nil, err
	}
	values := make([]uint64, 0, words)
	for i := 0; i+8 <= len(data); i += 8 {
		var v uint64
		for j := 7; j >= 0; j-- {
			v = v<<8 | uint64(data[i+j])
		}
		values = append(values, v)
	}
	return disasm.ValidateChain(base, values, s.symbolize, s.executable, s.readMemory), nil
}

// Close tears down the session.
func (s *Session) Close(kill bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	subs := make([]*subscriber, 0, len(s.subs))
	for _, sub := range s.subs {
		subs = append(subs, sub)
	}
	s.subs = make(map[uint64]*subscriber)
	s.mu.Unlock()

	close(s.done)
	for _, sub := range subs {
		sub.once.Do(func() { close(sub.done) })
	}
	if s.bpf != nil {
		_ = s.bpf.Close()
	}
	if s.tracer != nil {
		_ = s.tracer.Close(kill)
	}
	for _, f := range s.files {
		_ = f.Close()
	}
}

// MarshalEvent is a helper for tests and exports.
func MarshalEvent(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ID returns the session identifier.
func (s *Session) ID() string { return s.id }

// Target returns the resolved target description.
func (s *Session) Target() core.Target { return s.target }

// Seq returns the current event sequence.
func (s *Session) Seq() uint64 { return s.currentSeq() }

// Subscribe attaches a protocol connection to the session event stream.
func (s *Session) Subscribe(conn *transport.Conn, since uint64) uint64 {
	return s.subscribe(conn, since)
}

// WaitExit waits for the target to exit.
func (s *Session) WaitExit(timeout time.Duration) bool {
	if s.tracer == nil {
		return true
	}
	return s.tracer.WaitExit(timeout)
}

// Model exposes the heap model for library users.
func (s *Session) Model() *heap.Model { return s.model }

// Engine exposes the detector engine for library users.
func (s *Session) Engine() *detect.Engine { return s.engine }

// ContinueAll resumes every known thread.
func (s *Session) ContinueAll() error { return s.tracer.Continue(0) }

// PauseTarget interrupts every known thread.
func (s *Session) PauseTarget() error { return s.tracer.Pause() }

// WorkDir returns the process working directory used for reports.
func (s *Session) WorkDir() string {
	wd, _ := os.Getwd()
	return wd
}

// Export writes session artifacts to dir.
func (s *Session) Export(dir string) error {
	if dir == "" {
		dir = filepath.Join("build", "reports", s.id)
	}
	s.mu.Lock()
	frames := make([]*proto.Frame, len(s.eventLog))
	copy(frames, s.eventLog)
	rop := s.lastROP
	sink := s.lastSink
	markers := append([]Marker(nil), s.markers...)
	s.mu.Unlock()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := export.JSONL(filepath.Join(dir, "events.jsonl"), frames); err != nil {
		return err
	}
	if err := export.JSON(filepath.Join(dir, "heap.json"), map[string]any{
		"allocations": s.model.Allocations(false),
		"tombstones":  s.model.Tombstones(),
		"mappings":    s.model.Mappings(),
		"stats":       s.model.Stats(),
		"findings":    s.engine.Recent(),
	}); err != nil {
		return err
	}
	if rop != nil {
		if err := export.JSON(filepath.Join(dir, "rop.json"), rop); err != nil {
			return err
		}
	}
	if err := export.JSON(filepath.Join(dir, "summary.json"), map[string]any{
		"session": s.id, "target": s.target, "config": s.cfg,
		"stats": s.model.Stats(), "sink": sink, "rop": rop, "markers": markers,
	}); err != nil {
		return err
	}
	return export.Report(filepath.Join(dir, "report.md"), s.id, s.target, s.model.Stats(), sink, rop, s.engine.Recent())
}

// WaitStop waits for a ptrace stop matching pred.
func (s *Session) WaitStop(timeout time.Duration, pred func(debugger.Stop) bool) (debugger.Stop, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.After(timeout)
	for {
		select {
		case st := <-s.stops:
			if pred == nil || pred(st) {
				return st, nil
			}
		case <-deadline:
			return debugger.Stop{}, fmt.Errorf("timed out waiting for stop")
		case <-s.done:
			return debugger.Stop{}, fmt.Errorf("session closed")
		}
	}
}

// BreakSymbol installs a breakpoint on a symbol.
func (s *Session) BreakSymbol(symbol string) (*debugger.Breakpoint, error) {
	addr, err := s.resolveSymbol("", symbol)
	if err != nil {
		return nil, err
	}
	return s.tracer.SetBreakpoint(addr, symbol, true)
}

// BreakAddress installs a hardware breakpoint at a raw address.
func (s *Session) BreakAddress(addr uint64, symbol string) (*debugger.Breakpoint, error) {
	return s.tracer.SetBreakpoint(addr, symbol, true)
}

// ClearBreak removes a breakpoint by address.
func (s *Session) ClearBreak(addr uint64) error { return s.tracer.ClearBreakpoint(addr) }

// SymbolAddress resolves a symbol to its runtime address.
func (s *Session) SymbolAddress(symbol string) (uint64, error) {
	return s.resolveSymbol("", symbol)
}
