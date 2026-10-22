package disasm

import (
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// Instruction is a decoded x86_64 instruction.
type Instruction struct {
	Addr uint64    `json:"addr"`
	Len  int       `json:"len"`
	Text string    `json:"text"`
	Op   x86asm.Op `json:"-"`
}

// Gadget describes the first few instructions at a chain entry.
type Gadget struct {
	Address      uint64        `json:"address"`
	Bytes        []byte        `json:"bytes"`
	Instructions []Instruction `json:"instructions"`
	Pops         []string      `json:"pops,omitempty"`
	Ret          bool          `json:"ret"`
	Syscall      bool          `json:"syscall"`
	Call         bool          `json:"call"`
	Jump         bool          `json:"jump"`
	Pivot        bool          `json:"pivot"`
	Valid        bool          `json:"valid"`
	Error        string        `json:"error,omitempty"`
}

// Decode decodes one instruction.
func Decode(code []byte, addr uint64) (Instruction, error) {
	inst, err := x86asm.Decode(code, 64)
	if err != nil {
		return Instruction{}, err
	}
	return Instruction{
		Addr: addr,
		Len:  inst.Len,
		Text: x86asm.IntelSyntax(inst, addr, nil),
		Op:   inst.Op,
	}, nil
}

// Classify decodes up to eight instructions from a gadget entry.
func Classify(code []byte, addr uint64) Gadget {
	g := Gadget{Address: addr}
	if len(code) > 32 {
		code = code[:32]
	}
	g.Bytes = append([]byte(nil), code...)
	remaining := code
	cur := addr
	for i := 0; i < 8 && len(remaining) > 0; i++ {
		inst, err := x86asm.Decode(remaining, 64)
		if err != nil {
			g.Error = err.Error()
			break
		}
		g.Instructions = append(g.Instructions, Instruction{
			Addr: cur, Len: inst.Len, Text: x86asm.IntelSyntax(inst, cur, nil), Op: inst.Op,
		})
		switch inst.Op {
		case x86asm.RET:
			g.Ret = true
		case x86asm.SYSCALL, x86asm.SYSENTER, x86asm.INT:
			g.Syscall = true
		case x86asm.CALL:
			g.Call = true
		case x86asm.JMP:
			g.Jump = true
		case x86asm.POP:
			if len(inst.Args) > 0 {
				g.Pops = append(g.Pops, fmt.Sprint(inst.Args[0]))
			}
		case x86asm.LEAVE:
			g.Pivot = true
		case x86asm.XCHG:
			if len(inst.Args) == 2 && strings.Contains(strings.ToLower(fmt.Sprint(inst.Args[0])), "sp") {
				g.Pivot = true
			}
		case x86asm.MOV:
			if len(inst.Args) == 2 && strings.EqualFold(fmt.Sprint(inst.Args[0]), "rsp") {
				g.Pivot = true
			}
		}
		remaining = remaining[inst.Len:]
		cur += uint64(inst.Len)
		if g.Ret || g.Syscall {
			break
		}
	}
	g.Valid = len(g.Instructions) > 0
	return g
}

// IsControlTransfer reports whether op is a control-flow instruction.
func IsControlTransfer(op x86asm.Op) bool {
	switch op {
	case x86asm.RET, x86asm.CALL, x86asm.JMP, x86asm.SYSCALL,
		x86asm.SYSENTER, x86asm.INT, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
		return true
	default:
		return false
	}
}

// ChainEntry is one word of a candidate ROP chain.
type ChainEntry struct {
	Index      int     `json:"index"`
	Value      uint64  `json:"value"`
	Executable bool    `json:"executable"`
	Module     string  `json:"module,omitempty"`
	Symbol     string  `json:"symbol,omitempty"`
	SymbolOff  uint64  `json:"symbol_offset,omitempty"`
	Gadget     *Gadget `json:"gadget,omitempty"`
	Error      string  `json:"error,omitempty"`
}

// Symbolizer resolves an address to module/symbol text.
type Symbolizer func(addr uint64) (module, symbol string, off uint64, ok bool)

// MemoryReader reads target memory.
type MemoryReader func(addr uint64, size int) ([]byte, error)

// ExecutableFunc reports whether an address is in an executable mapping.
type ExecutableFunc func(addr uint64) bool

// ValidateChain resolves and classifies a candidate chain.
func ValidateChain(base uint64, words []uint64, sym Symbolizer, exec ExecutableFunc, mem MemoryReader) []ChainEntry {
	out := make([]ChainEntry, 0, len(words))
	for i, w := range words {
		e := ChainEntry{Index: i, Value: w}
		if w == 0 {
			out = append(out, e)
			continue
		}
		if sym != nil {
			if mod, s, off, ok := sym(w); ok {
				e.Module, e.Symbol, e.SymbolOff = mod, s, off
			}
		}
		if exec != nil {
			e.Executable = exec(w)
		}
		if e.Executable && mem != nil {
			code, err := mem(w, 32)
			if err != nil {
				e.Error = err.Error()
			} else {
				g := Classify(code, w)
				e.Gadget = &g
			}
		}
		out = append(out, e)
	}
	return out
}
