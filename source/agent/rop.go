package agent

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gofengshui/core"
	"gofengshui/debugger"
	"gofengshui/disasm"
	"gofengshui/proto"
	"gofengshui/transport"
)

// SinkInfo is a registered sink function.
type SinkInfo struct {
	Name       string            `json:"name"`
	Module     string            `json:"module,omitempty"`
	Addr       uint64            `json:"addr"`
	Breakpoint uint64            `json:"breakpoint_id"`
	Regs       map[string]uint64 `json:"expected_regs,omitempty"`
	ChainBase  uint64            `json:"chain_base,omitempty"`
	ChainLen   int               `json:"chain_len,omitempty"`
	Timestamp  time.Time         `json:"ts"`
}

// SinkHit is captured when the registered sink executes.
type SinkHit struct {
	Name      string              `json:"name"`
	Addr      uint64              `json:"addr"`
	RIP       uint64              `json:"rip"`
	Regs      core.Registers      `json:"regs"`
	Stack     []uint64            `json:"stack,omitempty"`
	Chain     []disasm.ChainEntry `json:"chain,omitempty"`
	Timestamp time.Time           `json:"ts"`
}

// Register returns a register value by name.
func (h *SinkHit) Register(name string) uint64 {
	switch strings.ToLower(name) {
	case "rax":
		return h.Regs.RAX
	case "rbx":
		return h.Regs.RBX
	case "rcx":
		return h.Regs.RCX
	case "rdx":
		return h.Regs.RDX
	case "rsi":
		return h.Regs.RSI
	case "rdi":
		return h.Regs.RDI
	case "rbp":
		return h.Regs.RBP
	case "rsp":
		return h.Regs.RSP
	case "r8":
		return h.Regs.R8
	case "r9":
		return h.Regs.R9
	case "r10":
		return h.Regs.R10
	case "r11":
		return h.Regs.R11
	case "r12":
		return h.Regs.R12
	case "r13":
		return h.Regs.R13
	case "r14":
		return h.Regs.R14
	case "r15":
		return h.Regs.R15
	case "rip":
		return h.Regs.RIP
	default:
		return 0
	}
}

// HijackState watches a saved-RIP/function-pointer slot.
type HijackState struct {
	WatchID   uint64 `json:"watch_id"`
	Slot      uint64 `json:"slot"`
	SinkAddr  uint64 `json:"sink_addr"`
	StartAddr uint64 `json:"start_addr,omitempty"`
	ChainBase uint64 `json:"chain_base,omitempty"`
	ChainLen  int    `json:"chain_len,omitempty"`
	MaxSteps  int    `json:"max_steps"`
	TID       int    `json:"tid"`
}

// ROPStep is one executed control transfer during a chain trace.
type ROPStep struct {
	Index  int            `json:"index"`
	RIP    uint64         `json:"rip"`
	RSP    uint64         `json:"rsp"`
	Module string         `json:"module,omitempty"`
	Symbol string         `json:"symbol,omitempty"`
	Offset uint64         `json:"offset,omitempty"`
	Regs   core.Registers `json:"regs"`
	Gadget *disasm.Gadget `json:"gadget,omitempty"`
}

// ROPState tracks an in-progress chain trace.
type ROPState struct {
	SinkAddr  uint64 `json:"sink_addr"`
	Start     uint64 `json:"start,omitempty"`
	ChainBase uint64 `json:"chain_base,omitempty"`
	ChainLen  int    `json:"chain_len,omitempty"`
	MaxSteps  int    `json:"max_steps"`
	TID       int    `json:"tid"`

	Tracing bool      `json:"tracing"`
	Steps   []ROPStep `json:"steps"`
	StartBP uint64    `json:"start_bp,omitempty"`
	Started time.Time `json:"started"`
}

// ROPValidation records the individual checks that decided whether a trace is
// accepted as a ROP chain.
type ROPValidation struct {
	SinkReached  bool     `json:"sink_reached"`
	StartValid   bool     `json:"start_valid"`
	ControlFlow  bool     `json:"control_flow"`
	ChainChecked bool     `json:"chain_checked"`
	ChainValid   bool     `json:"chain_valid"`
	Issues       []string `json:"issues,omitempty"`
}

// ROPResult is the validated/finished chain trace.
type ROPResult struct {
	Sink       *SinkHit            `json:"sink,omitempty"`
	Steps      []ROPStep           `json:"steps"`
	Chain      []disasm.ChainEntry `json:"chain,omitempty"`
	Validation *ROPValidation      `json:"validation,omitempty"`
	Verified   bool                `json:"verified"`
	Error      string              `json:"error,omitempty"`
	Timestamp  time.Time           `json:"ts"`
}

type sinkParams struct {
	Symbol    string            `json:"symbol"`
	Module    string            `json:"module"`
	Addr      uint64            `json:"addr"`
	Name      string            `json:"name"`
	Regs      map[string]uint64 `json:"regs"`
	ChainBase uint64            `json:"chain_base"`
	ChainLen  int               `json:"chain_len"`
}

func (s *Session) sinkRegister(conn *transport.Conn, f *proto.Frame) {
	var p sinkParams
	_ = f.DecodeParams(&p)
	addr := p.Addr
	if addr == 0 {
		if p.Symbol == "" {
			s.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: "symbol or addr required"})
			return
		}
		a, err := s.resolveSymbol(p.Module, p.Symbol)
		if err != nil {
			s.reply(conn, f, nil, &proto.Error{Code: "symbol", Message: err.Error()})
			return
		}
		addr = a
	}
	name := p.Name
	if name == "" {
		name = p.Symbol
	}
	s.mu.Lock()
	old := s.sink
	s.mu.Unlock()
	if old != nil {
		_ = s.tracer.ClearBreakpoint(old.Addr)
	}
	bp, err := s.tracer.SetBreakpoint(addr, name, true)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "sink_failed", Message: err.Error()})
		return
	}
	info := &SinkInfo{
		Name: name, Module: p.Module, Addr: addr, Breakpoint: bp.ID,
		Regs: p.Regs, ChainBase: p.ChainBase, ChainLen: p.ChainLen,
		Timestamp: time.Now(),
	}
	s.mu.Lock()
	s.sink = info
	s.mu.Unlock()
	s.reply(conn, f, info, nil)
}

// HijackParams configures a saved-RIP/function-pointer watch.
type HijackParams struct {
	Slot      uint64 `json:"slot"`
	Size      uint64 `json:"size"`
	Type      string `json:"type"`
	Sink      string `json:"sink"`
	SinkAddr  uint64 `json:"sink_addr"`
	ChainBase uint64 `json:"chain_base"`
	ChainLen  int    `json:"chain_len"`
	MaxSteps  int    `json:"max_steps"`
	TID       int    `json:"tid"`
}

func (s *Session) hijackWatch(conn *transport.Conn, f *proto.Frame) {
	var p HijackParams
	_ = f.DecodeParams(&p)
	h, wp, err := s.WatchHijack(p)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "watch_failed", Message: err.Error()})
		return
	}
	s.reply(conn, f, map[string]any{"hijack": h, "watchpoint": wp}, nil)
}

// WatchHijack installs the hijack watchpoint and arms automatic ROP tracing.
func (s *Session) WatchHijack(p HijackParams) (*HijackState, *debugger.Watchpoint, error) {
	if p.Slot == 0 {
		return nil, nil, fmt.Errorf("slot required")
	}
	if p.Size == 0 {
		p.Size = 8
	}
	sinkAddr := p.SinkAddr
	if sinkAddr == 0 {
		s.mu.Lock()
		if s.sink != nil {
			sinkAddr = s.sink.Addr
		}
		s.mu.Unlock()
	}
	if sinkAddr == 0 && p.Sink != "" {
		a, err := s.resolveSymbol("", p.Sink)
		if err != nil {
			return nil, nil, err
		}
		sinkAddr = a
	}
	if sinkAddr == 0 {
		return nil, nil, fmt.Errorf("sink or sink_addr required")
	}
	typ := debugger.WatchType(p.Type)
	if typ == "" {
		typ = debugger.WatchAccess
	}
	wp, err := s.tracer.SetWatchpoint(p.Slot, p.Size, typ, 0)
	if err != nil {
		return nil, nil, err
	}
	if p.MaxSteps <= 0 {
		p.MaxSteps = 512
	}
	if p.ChainLen <= 0 {
		p.ChainLen = 64
	}
	h := &HijackState{
		WatchID: wp.ID, Slot: p.Slot, SinkAddr: sinkAddr,
		ChainBase: p.ChainBase, ChainLen: p.ChainLen, MaxSteps: p.MaxSteps,
		TID: p.TID,
	}
	s.mu.Lock()
	s.hijack = h
	s.mu.Unlock()
	return h, wp, nil
}

func (s *Session) ropArm(conn *transport.Conn, f *proto.Frame) {
	var p struct {
		Sink        string `json:"sink"`
		SinkAddr    uint64 `json:"sink_addr"`
		Start       uint64 `json:"start"`
		StartSymbol string `json:"start_symbol"`
		ChainBase   uint64 `json:"chain_base"`
		ChainLen    int    `json:"chain_len"`
		MaxSteps    int    `json:"max_steps"`
		TID         int    `json:"tid"`
	}
	_ = f.DecodeParams(&p)
	sinkAddr := p.SinkAddr
	if sinkAddr == 0 {
		s.mu.Lock()
		if s.sink != nil {
			sinkAddr = s.sink.Addr
		}
		s.mu.Unlock()
	}
	if sinkAddr == 0 && p.Sink != "" {
		a, err := s.resolveSymbol("", p.Sink)
		if err != nil {
			s.reply(conn, f, nil, &proto.Error{Code: "symbol", Message: err.Error()})
			return
		}
		sinkAddr = a
	}
	if sinkAddr == 0 {
		s.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: "sink address required"})
		return
	}
	if p.Start == 0 && p.StartSymbol != "" {
		a, err := s.resolveSymbol("", p.StartSymbol)
		if err != nil {
			s.reply(conn, f, nil, &proto.Error{Code: "symbol", Message: err.Error()})
			return
		}
		p.Start = a
	}
	if p.Start == 0 {
		s.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: "start or start_symbol required; use hijack.watch for automatic start"})
		return
	}
	if p.Start == sinkAddr {
		s.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: "start must differ from the sink address"})
		return
	}
	if p.MaxSteps <= 0 {
		p.MaxSteps = 512
	}
	if p.ChainLen <= 0 {
		p.ChainLen = 64
	}
	state := &ROPState{
		SinkAddr: sinkAddr, Start: p.Start, ChainBase: p.ChainBase,
		ChainLen: p.ChainLen, MaxSteps: p.MaxSteps, TID: p.TID,
		Started: time.Now(),
	}
	bp, err := s.tracer.SetBreakpoint(p.Start, "rop_start", true)
	if err != nil {
		s.reply(conn, f, nil, &proto.Error{Code: "rop_failed", Message: err.Error()})
		return
	}
	state.StartBP = bp.ID
	s.mu.Lock()
	s.rop = state
	s.mu.Unlock()
	s.reply(conn, f, map[string]any{"rop": state, "start_breakpoint": bp}, nil)
}

func (s *Session) hijackStop(st debugger.Stop) {
	if st.Watchpoint == nil {
		return
	}
	s.mu.Lock()
	h := s.hijack
	rop := s.rop
	s.mu.Unlock()
	if h == nil || h.WatchID != st.Watchpoint.ID || rop != nil {
		return
	}
	data, err := s.tracer.ReadMemory(h.Slot, 8)
	if err != nil || len(data) < 8 {
		return
	}
	var value uint64
	for i := 7; i >= 0; i-- {
		value = value<<8 | uint64(data[i])
	}
	if !s.executable(value) {
		// A write to the slot before the hijack. Continue running.
		_ = s.tracer.Continue(st.TID)
		return
	}
	if !s.atControlTransfer(st, value) {
		// The slot was overwritten with an executable address before it was
		// consumed. Break on that address and start tracing when it runs.
		bp, err := s.tracer.SetBreakpoint(value, "hijack_start", true)
		if err != nil {
			_ = s.tracer.Continue(st.TID)
			return
		}
		_ = s.tracer.ClearWatchpoint(h.WatchID)
		_ = s.tracer.PauseOthers(st.TID)
		state := &ROPState{
			SinkAddr: h.SinkAddr, Start: value, ChainBase: h.ChainBase,
			ChainLen: h.ChainLen, MaxSteps: h.MaxSteps, TID: st.TID,
			Started: time.Now(), StartBP: bp.ID,
		}
		s.mu.Lock()
		s.hijack = nil
		s.rop = state
		s.mu.Unlock()
		_ = s.tracer.Continue(st.TID)
		s.broadcast("rop_armed", StreamEvent{Kind: "rop_armed", Message: fmt.Sprintf("slot 0x%x written with 0x%x", h.Slot, value)})
		return
	}
	state := &ROPState{
		SinkAddr: h.SinkAddr, Start: value, ChainBase: h.ChainBase,
		ChainLen: h.ChainLen, MaxSteps: h.MaxSteps, TID: st.TID,
		Started: time.Now(), Tracing: true,
	}
	_ = s.tracer.ClearWatchpoint(h.WatchID)
	_ = s.tracer.PauseOthers(st.TID)
	s.mu.Lock()
	s.hijack = nil
	s.rop = state
	s.mu.Unlock()
	s.broadcast("rop_start", StreamEvent{Kind: "rop_start", Message: fmt.Sprintf("hijack slot 0x%x -> 0x%x", h.Slot, value)})
}

func (s *Session) atControlTransfer(st debugger.Stop, value uint64) bool {
	if st.Regs.RIP == value {
		return true
	}
	data, err := s.tracer.ReadMemory(st.Regs.RIP, 16)
	if err != nil || len(data) == 0 {
		return false
	}
	inst, err := disasm.Decode(data, st.Regs.RIP)
	if err != nil {
		return false
	}
	return disasm.IsControlTransfer(inst.Op)
}

func (s *Session) ropStop(st debugger.Stop) {
	s.mu.Lock()
	rop := s.rop
	s.mu.Unlock()
	if rop == nil {
		return
	}
	if os.Getenv("GFS_PTRACE_LOG") != "" {
		fmt.Fprintf(os.Stderr, "gfs-rop: stop reason=%s tid=%d rip=0x%x addr=0x%x tracing=%v steps=%d\n",
			st.Reason, st.TID, st.Regs.RIP, st.Address, rop.Tracing, len(rop.Steps))
	}

	if st.Reason == "signal" || st.Reason == "exit" {
		s.finishROP(rop, st, fmt.Sprintf("stopped before sink: %s signal=%d", st.Reason, st.Signal))
		return
	}

	if !rop.Tracing {
		if rop.Start != 0 && (st.Address == rop.Start || st.Regs.RIP == rop.Start) {
			rop.Tracing = true
			rop.TID = st.TID
			if rop.StartBP != 0 {
				_ = s.tracer.ClearBreakpoint(rop.Start)
				rop.StartBP = 0
			}
			_ = s.tracer.PauseOthers(st.TID)
			s.recordStep(rop, st)
			_ = s.tracer.SingleStep(st.TID)
		}
		return
	}

	s.recordStep(rop, st)
	if st.Address == rop.SinkAddr || st.Regs.RIP == rop.SinkAddr {
		s.finishROP(rop, st, "")
		return
	}
	if len(rop.Steps) >= rop.MaxSteps {
		s.finishROP(rop, st, "max steps exceeded")
		return
	}
	_ = s.tracer.SingleStep(st.TID)
}

func (s *Session) recordStep(rop *ROPState, st debugger.Stop) {
	step := ROPStep{Index: len(rop.Steps), RIP: st.Regs.RIP, RSP: st.Regs.RSP, Regs: st.Regs}
	if mod, sym, off, ok := s.symbolize(st.Regs.RIP); ok {
		step.Module, step.Symbol, step.Offset = mod, sym, off
	}
	if s.executable(st.Regs.RIP) {
		if code, err := s.tracer.ReadMemory(st.Regs.RIP, 32); err == nil {
			g := disasm.Classify(code, st.Regs.RIP)
			step.Gadget = &g
		}
	}
	rop.Steps = append(rop.Steps, step)
}

func (s *Session) finishROP(rop *ROPState, st debugger.Stop, reason string) {
	if os.Getenv("GFS_PTRACE_LOG") != "" {
		fmt.Fprintf(os.Stderr, "gfs-rop: finish reason=%q rip=0x%x steps=%d\n", reason, st.Regs.RIP, len(rop.Steps))
	}
	// A sink hit is only evidence when the trace actually stopped at the
	// sink. Failed traces (signal, exit, max steps) must not be reported as
	// sink hits, otherwise a crash before the sink could satisfy a sink
	// assertion.
	var sink *SinkHit
	if reason == "" {
		sink = s.captureSink(st)
	}
	var chain []disasm.ChainEntry
	if rop.ChainBase != 0 {
		words := rop.ChainLen
		if words <= 0 {
			words = 64
		}
		chain, _ = s.chain(rop.ChainBase, words)
	}
	if chain == nil && sink != nil {
		// A sink may have been registered with its own chain base. Use the
		// chain captured with the sink hit when the trace did not name one.
		chain = sink.Chain
	}
	// The chain window usually extends past the actual chain into unrelated
	// stack words. Report only the start -> sink segment so the exported
	// chain contains the executed chain and no decoding noise from stack
	// leftovers.
	chain = trimChainSegment(chain, rop.Start, rop.SinkAddr)
	if sink != nil {
		sink.Chain = chain
	}
	s.mu.Lock()
	registeredSink := s.sink
	s.mu.Unlock()
	chainExpected := rop.ChainBase != 0 ||
		(sink != nil && registeredSink != nil && registeredSink.ChainBase != 0)
	validation := validateROPTrace(rop.Start, rop.SinkAddr, sink, rop.Steps, chain, chainExpected, reason)
	result := &ROPResult{
		Sink: sink, Steps: rop.Steps, Chain: chain,
		Validation: validation, Timestamp: time.Now(),
	}
	result.Verified = validation.SinkReached && validation.StartValid &&
		validation.ControlFlow && validation.ChainValid
	if !result.Verified {
		if reason != "" {
			result.Error = reason
		} else if len(validation.Issues) > 0 {
			result.Error = strings.Join(validation.Issues, "; ")
		}
	}

	s.mu.Lock()
	if rop.StartBP != 0 {
		deleteBP := rop.Start
		s.mu.Unlock()
		_ = s.tracer.ClearBreakpoint(deleteBP)
		s.mu.Lock()
	}
	s.rop = nil
	s.lastROP = result
	if sink != nil {
		s.lastSink = sink
	}
	s.mu.Unlock()
	select {
	case s.ropDone <- result:
	default:
	}

	if sink != nil {
		s.broadcast("sink", StreamEvent{Kind: "sink", Sink: sink})
	}
	s.broadcast("rop", StreamEvent{Kind: "rop", ROP: result})
}

// validateROPTrace applies the structural checks used for ROP verification.
// It is deliberately independent of the tracer so it can be unit tested.
func validateROPTrace(start, sinkAddr uint64, sink *SinkHit, steps []ROPStep, chain []disasm.ChainEntry, chainExpected bool, reason string) *ROPValidation {
	v := &ROPValidation{}
	issue := func(format string, args ...any) {
		v.Issues = append(v.Issues, fmt.Sprintf(format, args...))
	}

	if reason != "" {
		issue("%s", reason)
	}
	v.SinkReached = reason == "" && sink != nil && sink.Addr == sinkAddr &&
		sink.RIP == sinkAddr && len(steps) > 0 && steps[len(steps)-1].RIP == sinkAddr
	if !v.SinkReached {
		issue("sink not reached")
	}

	switch {
	case start == 0:
		issue("start address missing")
	case sinkAddr == 0:
		issue("sink address missing")
	case start == sinkAddr:
		issue("start equals sink")
	case len(steps) < 2:
		issue("trace did not leave the start address")
	case steps[0].RIP != start:
		issue("first step 0x%x is not the start 0x%x", steps[0].RIP, start)
	default:
		v.StartValid = true
	}

	for i := 0; i < len(steps)-1; i++ {
		g := steps[i].Gadget
		if g != nil && (g.Ret || g.Call || g.Jump || g.Syscall) {
			v.ControlFlow = true
			break
		}
	}
	if !v.ControlFlow {
		issue("no control-transfer gadget observed before the sink")
	}

	v.ChainChecked = chainExpected || len(chain) > 0
	v.ChainValid = true
	if v.ChainChecked {
		if chainExpected && len(chain) == 0 {
			v.ChainValid = false
			issue("chain buffer could not be read")
		} else {
			// The chain window usually extends past the actual chain into
			// unrelated stack words. Only validate the first start -> sink
			// segment; surrounding words are data or another frame.
			startIdx := chainEntryIndex(chain, start, 0, true)
			if startIdx < 0 {
				startIdx = chainEntryIndex(chain, start, 0, false)
			}
			if startIdx < 0 {
				v.ChainValid = false
				issue("chain does not contain the start address")
			} else if !chain[startIdx].Executable {
				v.ChainValid = false
				issue("chain start address 0x%x is not executable", start)
			}

			from := 0
			if startIdx >= 0 {
				from = startIdx
			}
			sinkIdx := chainEntryIndex(chain, sinkAddr, from, true)
			if sinkIdx < 0 {
				sinkIdx = chainEntryIndex(chain, sinkAddr, from, false)
			}
			if sinkIdx < 0 {
				v.ChainValid = false
				issue("chain does not contain the sink address")
			} else if !chain[sinkIdx].Executable {
				v.ChainValid = false
				issue("chain sink address 0x%x is not executable", sinkAddr)
			}

			if startIdx >= 0 && sinkIdx >= startIdx {
				for i := startIdx; i <= sinkIdx; i++ {
					entry := chain[i]
					if entry.Value == 0 || !entry.Executable {
						continue
					}
					if entry.Error != "" || entry.Gadget == nil || !entry.Gadget.Valid {
						v.ChainValid = false
						issue("chain entry %d at 0x%x is not a valid gadget", entry.Index, entry.Value)
					}
				}
			}
		}
	}
	return v
}

// chainEntryIndex finds value in chain, optionally requiring it to be in an
// executable mapping. Search starts at from.
func chainEntryIndex(chain []disasm.ChainEntry, value uint64, from int, executable bool) int {
	for i := from; i < len(chain); i++ {
		if chain[i].Value != value {
			continue
		}
		if executable && !chain[i].Executable {
			continue
		}
		return i
	}
	return -1
}

// trimChainSegment returns the first executable start -> sink segment of a
// captured chain window. The original chain is returned when either address is
// missing so validation can report the specific failure.
func trimChainSegment(chain []disasm.ChainEntry, start, sink uint64) []disasm.ChainEntry {
	if len(chain) == 0 {
		return chain
	}
	startIdx := chainEntryIndex(chain, start, 0, true)
	if startIdx < 0 {
		startIdx = chainEntryIndex(chain, start, 0, false)
	}
	if startIdx < 0 {
		return chain
	}
	sinkIdx := chainEntryIndex(chain, sink, startIdx, true)
	if sinkIdx < 0 {
		sinkIdx = chainEntryIndex(chain, sink, startIdx, false)
	}
	if sinkIdx < startIdx {
		return chain
	}
	return chain[startIdx : sinkIdx+1]
}

// sinkReached reports whether the current stop is at the sink. A signal or
// failure stop elsewhere must never be attributed to the sink.
func sinkReached(addr uint64, st debugger.Stop) bool {
	if addr == 0 {
		return false
	}
	return st.Regs.RIP == addr || st.Address == addr
}

func (s *Session) captureSink(st debugger.Stop) *SinkHit {
	s.mu.Lock()
	info := s.sink
	ropState := s.rop
	s.mu.Unlock()
	if info == nil && ropState != nil {
		info = &SinkInfo{Name: "sink", Addr: ropState.SinkAddr, ChainBase: ropState.ChainBase, ChainLen: ropState.ChainLen}
	}
	if info == nil || !sinkReached(info.Addr, st) {
		return nil
	}
	hit := &SinkHit{
		Name: info.Name, Addr: info.Addr, RIP: st.Regs.RIP,
		Regs: st.Regs, Timestamp: time.Now(),
	}
	if data, err := s.tracer.ReadMemory(st.Regs.RSP, 16*8); err == nil {
		for i := 0; i+8 <= len(data); i += 8 {
			var v uint64
			for j := 7; j >= 0; j-- {
				v = v<<8 | uint64(data[i+j])
			}
			hit.Stack = append(hit.Stack, v)
		}
	}
	base := info.ChainBase
	length := info.ChainLen
	if base == 0 {
		s.mu.Lock()
		if s.rop != nil {
			base = s.rop.ChainBase
			length = s.rop.ChainLen
		}
		s.mu.Unlock()
	}
	if base != 0 {
		if length <= 0 {
			length = 64
		}
		if chain, err := s.chain(base, length); err == nil {
			hit.Chain = chain
		}
	}
	return hit
}

// RegisterSink resolves and installs a sink symbol.
func (s *Session) RegisterSink(symbol string) (*SinkInfo, error) {
	addr, err := s.resolveSymbol("", symbol)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	old := s.sink
	s.mu.Unlock()
	if old != nil {
		_ = s.tracer.ClearBreakpoint(old.Addr)
	}
	bp, err := s.tracer.SetBreakpoint(addr, symbol, true)
	if err != nil {
		return nil, err
	}
	info := &SinkInfo{Name: symbol, Addr: addr, Breakpoint: bp.ID, Timestamp: time.Now()}
	s.mu.Lock()
	s.sink = info
	s.mu.Unlock()
	return info, nil
}

// ArmROP starts chain validation from a start symbol or address.
func (s *Session) ArmROP(startSymbol string, start, chainBase uint64, chainLen, maxSteps int) (*ROPState, error) {
	if start == 0 && startSymbol != "" {
		a, err := s.resolveSymbol("", startSymbol)
		if err != nil {
			return nil, err
		}
		start = a
	}
	if start == 0 {
		return nil, fmt.Errorf("start address required")
	}
	s.mu.Lock()
	sinkAddr := uint64(0)
	if s.sink != nil {
		sinkAddr = s.sink.Addr
	}
	s.mu.Unlock()
	if sinkAddr == 0 {
		return nil, fmt.Errorf("register a sink first")
	}
	if start == sinkAddr {
		return nil, fmt.Errorf("start must differ from the sink address")
	}
	if chainLen <= 0 {
		chainLen = 64
	}
	if maxSteps <= 0 {
		maxSteps = 512
	}
	state := &ROPState{
		SinkAddr: sinkAddr, Start: start, ChainBase: chainBase,
		ChainLen: chainLen, MaxSteps: maxSteps, Started: time.Now(),
	}
	bp, err := s.tracer.SetBreakpoint(start, "rop_start", true)
	if err != nil {
		return nil, err
	}
	state.StartBP = bp.ID
	s.mu.Lock()
	s.rop = state
	s.mu.Unlock()
	return state, nil
}

// WaitROP waits for a completed ROP trace.
func (s *Session) WaitROP(timeout time.Duration) *ROPResult {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	select {
	case r := <-s.ropDone:
		return r
	case <-time.After(timeout):
		s.mu.Lock()
		r := s.lastROP
		s.mu.Unlock()
		return r
	case <-s.done:
		return nil
	}
}

// LastROP returns the most recent ROP result.
func (s *Session) LastROP() *ROPResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastROP
}

// LastSink returns the most recent sink hit.
func (s *Session) LastSink() *SinkHit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSink
}
