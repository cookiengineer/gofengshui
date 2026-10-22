package disasm

import "testing"

func TestClassifyPopRdiRet(t *testing.T) {
	code := []byte{0x5f, 0xc3}
	g := Classify(code, 0x1000)
	if !g.Valid || !g.Ret || len(g.Pops) != 1 || g.Pops[0] != "RDI" {
		t.Fatalf("unexpected gadget: %#v", g)
	}
}

func TestClassifySyscall(t *testing.T) {
	g := Classify([]byte{0x0f, 0x05, 0xc3}, 0x2000)
	if !g.Syscall {
		t.Fatalf("expected syscall: %#v", g)
	}
}

func TestClassifyLeavePivot(t *testing.T) {
	g := Classify([]byte{0xc9, 0xc3}, 0x3000)
	if !g.Pivot || !g.Ret {
		t.Fatalf("expected leave pivot: %#v", g)
	}
}
