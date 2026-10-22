package agent

import (
	"strings"
	"testing"

	"gofengshui/core"
	"gofengshui/debugger"
	"gofengshui/disasm"
)

func ropTestStep(rip uint64, control bool) ROPStep {
	return ROPStep{
		RIP:    rip,
		Gadget: &disasm.Gadget{Address: rip, Valid: true, Ret: control},
	}
}

func ropTestChain(start, sink uint64) []disasm.ChainEntry {
	return []disasm.ChainEntry{
		{Index: 0, Value: 0x4141}, // data argument, not an address
		{Index: 1, Value: start, Executable: true, Gadget: &disasm.Gadget{Address: start, Valid: true, Ret: true}},
		{Index: 2, Value: 0x4242}, // data argument, not an address
		{Index: 3, Value: sink, Executable: true, Gadget: &disasm.Gadget{Address: sink, Valid: true}},
	}
}

func TestValidateROPTraceAcceptsHijackChain(t *testing.T) {
	const start, sink = uint64(0x1000), uint64(0x2000)
	steps := []ROPStep{ropTestStep(start, true), ropTestStep(sink, false)}
	hit := &SinkHit{Addr: sink, RIP: sink}

	v := validateROPTrace(start, sink, hit, steps, ropTestChain(start, sink), true, "")
	if !v.SinkReached || !v.StartValid || !v.ControlFlow || !v.ChainChecked || !v.ChainValid {
		t.Fatalf("expected valid trace, got %#v", v)
	}
	if len(v.Issues) != 0 {
		t.Fatalf("expected no issues, got %v", v.Issues)
	}
}

func TestValidateROPTraceWithoutChain(t *testing.T) {
	const start, sink = uint64(0x1000), uint64(0x2000)
	steps := []ROPStep{ropTestStep(start, true), ropTestStep(sink, false)}
	hit := &SinkHit{Addr: sink, RIP: sink}

	v := validateROPTrace(start, sink, hit, steps, nil, false, "")
	if !v.ChainValid {
		t.Fatalf("empty chain should not invalidate the trace: %#v", v)
	}
	if v.ChainChecked {
		t.Fatalf("empty chain must not be reported as checked: %#v", v)
	}
	if !v.SinkReached || !v.StartValid || !v.ControlFlow {
		t.Fatalf("expected valid trace without chain, got %#v", v)
	}
}

func TestValidateROPTraceIgnoresWordsOutsideChainSegment(t *testing.T) {
	const start, sink = uint64(0x1000), uint64(0x2000)
	steps := []ROPStep{ropTestStep(start, true), ropTestStep(sink, false)}
	hit := &SinkHit{Addr: sink, RIP: sink}

	chain := []disasm.ChainEntry{
		// A data word equal to the sink before the chain starts.
		{Index: 0, Value: sink},
		// Executable stack garbage before the start must be ignored.
		{Index: 1, Value: 0x3001, Executable: true, Gadget: &disasm.Gadget{Address: 0x3001, Valid: false, Error: "unrecognized instruction"}},
		{Index: 2, Value: 0x4141},
		{Index: 3, Value: start, Executable: true, Gadget: &disasm.Gadget{Address: start, Valid: true, Ret: true}},
		{Index: 4, Value: 0x4242},
		{Index: 5, Value: sink, Executable: true, Gadget: &disasm.Gadget{Address: sink, Valid: true}},
		// Executable stack garbage after the sink must also be ignored.
		{Index: 6, Value: 0x3002, Executable: true, Gadget: &disasm.Gadget{Address: 0x3002, Valid: false, Error: "unrecognized instruction"}},
	}

	v := validateROPTrace(start, sink, hit, steps, chain, true, "")
	if !v.ChainValid {
		t.Fatalf("chain outside the start-sink segment must be ignored: %#v", v)
	}
	if len(v.Issues) != 0 {
		t.Fatalf("unexpected issues: %v", v.Issues)
	}
}

func TestTrimChainSegment(t *testing.T) {
	const start, sink = uint64(0x1000), uint64(0x2000)
	chain := []disasm.ChainEntry{
		{Index: 0, Value: 0x4141},
		{Index: 1, Value: 0x3001, Executable: true, Gadget: &disasm.Gadget{Address: 0x3001, Valid: false}},
		{Index: 2, Value: start, Executable: true, Gadget: &disasm.Gadget{Address: start, Valid: true, Ret: true}},
		{Index: 3, Value: 0x4242},
		{Index: 4, Value: sink, Executable: true, Gadget: &disasm.Gadget{Address: sink, Valid: true}},
		{Index: 5, Value: 0x3002, Executable: true, Gadget: &disasm.Gadget{Address: 0x3002, Valid: false}},
	}
	got := trimChainSegment(chain, start, sink)
	if len(got) != 3 {
		t.Fatalf("trimmed chain length = %d, want 3: %#v", len(got), got)
	}
	if got[0].Value != start || got[1].Value != 0x4242 || got[2].Value != sink {
		t.Fatalf("unexpected trimmed chain: %#v", got)
	}

	if missing := trimChainSegment(chain, 0x9999, sink); len(missing) != len(chain) {
		t.Fatalf("missing start should keep the original chain, got %d entries", len(missing))
	}
	if missing := trimChainSegment(chain, start, 0x9999); len(missing) != len(chain) {
		t.Fatalf("missing sink should keep the original chain, got %d entries", len(missing))
	}
}

func TestValidateROPTraceRejectsInvalidTraces(t *testing.T) {
	const start, sink = uint64(0x1000), uint64(0x2000)
	hit := &SinkHit{Addr: sink, RIP: sink}
	goodSteps := []ROPStep{ropTestStep(start, true), ropTestStep(sink, false)}

	noSinkChain := ropTestChain(start, sink)[:3]
	noStartChain := append([]disasm.ChainEntry{ropTestChain(start, sink)[0]}, ropTestChain(start, sink)[3])
	badGadgetChain := []disasm.ChainEntry{
		{Index: 0, Value: 0x4141},
		{Index: 1, Value: start, Executable: true, Gadget: &disasm.Gadget{Address: start, Valid: true, Ret: true}},
		{Index: 2, Value: 0x3000, Executable: true, Gadget: &disasm.Gadget{Address: 0x3000, Valid: false, Error: "truncated"}},
		{Index: 3, Value: sink, Executable: true, Gadget: &disasm.Gadget{Address: sink, Valid: true}},
	}
	nonExecStartChain := ropTestChain(start, sink)
	nonExecStartChain[1].Executable = false
	nonExecStartChain[1].Gadget = nil
	nonExecSinkChain := ropTestChain(start, sink)
	nonExecSinkChain[3].Executable = false
	nonExecSinkChain[3].Gadget = nil

	tests := []struct {
		name          string
		start         uint64
		sinkAddr      uint64
		hit           *SinkHit
		steps         []ROPStep
		chain         []disasm.ChainEntry
		chainExpected bool
		reason        string
		wantIssue     string
	}{
		{
			name: "signal before sink", start: start, sinkAddr: sink, hit: nil,
			steps: goodSteps, reason: "stopped before sink: signal signal=11",
			wantIssue: "stopped before sink",
		},
		{
			name: "failure ignores a matching sink hit", start: start, sinkAddr: sink, hit: hit,
			steps: goodSteps, reason: "max steps exceeded", wantIssue: "sink not reached",
		},
		{
			name: "sink hit with mismatched last step", start: start, sinkAddr: sink, hit: hit,
			steps:     []ROPStep{ropTestStep(start, true), ropTestStep(0x1800, false)},
			wantIssue: "sink not reached",
		},
		{
			name: "max steps before sink", start: start, sinkAddr: sink, hit: nil,
			steps: goodSteps, reason: "max steps exceeded",
			wantIssue: "max steps exceeded",
		},
		{
			name: "start equals sink", start: sink, sinkAddr: sink, hit: hit,
			steps:     []ROPStep{ropTestStep(sink, true), ropTestStep(sink, false)},
			wantIssue: "start equals sink",
		},
		{
			name: "no steps", start: start, sinkAddr: sink, hit: hit,
			steps: nil, wantIssue: "trace did not leave the start address",
		},
		{
			name: "first step is not the start", start: start, sinkAddr: sink, hit: hit,
			steps:     []ROPStep{ropTestStep(0x1500, true), ropTestStep(sink, false)},
			wantIssue: "is not the start",
		},
		{
			name: "no control transfer", start: start, sinkAddr: sink, hit: hit,
			steps:     []ROPStep{ropTestStep(start, false), ropTestStep(sink, false)},
			wantIssue: "no control-transfer gadget",
		},
		{
			name: "chain missing sink", start: start, sinkAddr: sink, hit: hit,
			steps: goodSteps, chain: noSinkChain, chainExpected: true, wantIssue: "does not contain the sink",
		},
		{
			name: "chain missing start", start: start, sinkAddr: sink, hit: hit,
			steps: goodSteps, chain: noStartChain, chainExpected: true, wantIssue: "does not contain the start",
		},
		{
			name: "chain has invalid gadget", start: start, sinkAddr: sink, hit: hit,
			steps: goodSteps, chain: badGadgetChain, chainExpected: true, wantIssue: "not a valid gadget",
		},
		{
			name: "chain start not executable", start: start, sinkAddr: sink, hit: hit,
			steps: goodSteps, chain: nonExecStartChain, chainExpected: true, wantIssue: "start address",
		},
		{
			name: "chain sink not executable", start: start, sinkAddr: sink, hit: hit,
			steps: goodSteps, chain: nonExecSinkChain, chainExpected: true, wantIssue: "sink address",
		},
		{
			name: "chain unreadable", start: start, sinkAddr: sink, hit: hit,
			steps: goodSteps, chain: nil, chainExpected: true, wantIssue: "could not be read",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := validateROPTrace(tc.start, tc.sinkAddr, tc.hit, tc.steps, tc.chain, tc.chainExpected, tc.reason)
			found := false
			for _, issue := range v.Issues {
				if strings.Contains(issue, tc.wantIssue) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("missing issue %q in %v", tc.wantIssue, v.Issues)
			}
		})
	}
}

func TestSinkReached(t *testing.T) {
	tests := []struct {
		name string
		addr uint64
		stop debugger.Stop
		want bool
	}{
		{"rip matches", 0x1000, debugger.Stop{Regs: core.Registers{RIP: 0x1000}}, true},
		{"breakpoint address matches", 0x1000, debugger.Stop{Address: 0x1000, Regs: core.Registers{RIP: 0x1001}}, true},
		{"signal elsewhere", 0x1000, debugger.Stop{Regs: core.Registers{RIP: 0x2000}}, false},
		{"zero address", 0, debugger.Stop{Regs: core.Registers{RIP: 0}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sinkReached(tc.addr, tc.stop); got != tc.want {
				t.Fatalf("sinkReached = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCaptureSinkRejectsStopElsewhere(t *testing.T) {
	s := &Session{sink: &SinkInfo{Name: "gfs_sink", Addr: 0x2000}}
	hit := s.captureSink(debugger.Stop{
		Reason: "signal", Signal: 11,
		Regs: core.Registers{RIP: 0x3000},
	})
	if hit != nil {
		t.Fatalf("captureSink returned a hit for a stop elsewhere: %#v", hit)
	}
}

func TestFinishROPFailureDoesNotRecordSink(t *testing.T) {
	s := &Session{sink: &SinkInfo{Name: "gfs_sink", Addr: 0x2000}}
	rop := &ROPState{SinkAddr: 0x2000, Start: 0x1000, MaxSteps: 10}
	st := debugger.Stop{
		Reason: "signal", Signal: 11,
		Regs: core.Registers{RIP: 0x3000},
	}
	s.finishROP(rop, st, "stopped before sink: signal signal=11")

	res := s.lastROP
	if res == nil {
		t.Fatal("finishROP did not record a result")
	}
	if res.Verified {
		t.Fatal("failed trace must not be verified")
	}
	if res.Sink != nil {
		t.Fatalf("failed trace recorded a sink hit: %#v", res.Sink)
	}
	if s.lastSink != nil {
		t.Fatalf("failed trace set lastSink: %#v", s.lastSink)
	}
	if res.Validation == nil || res.Validation.SinkReached {
		t.Fatalf("unexpected validation result: %#v", res.Validation)
	}
	if !strings.Contains(res.Error, "stopped before sink") {
		t.Fatalf("error = %q, want failure reason", res.Error)
	}
}

func TestArmROPRejectsStartAtSink(t *testing.T) {
	s := &Session{sink: &SinkInfo{Name: "gfs_sink", Addr: 0x2000}}
	if _, err := s.ArmROP("", 0x2000, 0, 0, 0); err == nil {
		t.Fatal("expected ArmROP to reject a start address equal to the sink")
	}
}
