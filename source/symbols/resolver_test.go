package symbols

import (
	"os"
	"testing"
)

func TestParseMapLine(t *testing.T) {
	m, ok := parseMapLine("7f00-7f10 r-xp 00001000 08:01 1234 /usr/lib/libc.so.6")
	if !ok {
		t.Fatal("parse failed")
	}
	if m.Start != 0x7f00 || m.End != 0x7f10 || m.Offset != 0x1000 || m.Inode != 1234 {
		t.Fatalf("unexpected mapping: %#v", m)
	}
	if m.Path != "/usr/lib/libc.so.6" {
		t.Fatalf("path = %q", m.Path)
	}
}

func TestRuntimeEntrySelf(t *testing.T) {
	// The test binary is a PIE executable; entry resolution must succeed.
	if _, err := RuntimeEntry(0); err == nil {
		t.Fatal("pid 0 should fail")
	}
}

func TestRuntimeEntryAndResolverSelf(t *testing.T) {
	pid := os.Getpid()
	entry, err := RuntimeEntry(pid)
	if err != nil {
		t.Fatalf("runtime entry: %v", err)
	}
	if entry == 0 {
		t.Fatal("zero entry point")
	}
	r, err := NewResolver(pid)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(r.Modules) == 0 {
		t.Fatal("no modules resolved")
	}
}
