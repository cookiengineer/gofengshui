package heap

import (
	"testing"

	"gofengshui/source/core"
)

func mustProfile(t *testing.T, version string) Profile {
	t.Helper()
	p, ok := ProfileForVersion(version)
	if !ok {
		t.Fatalf("invalid profile %q", version)
	}
	return p
}

func encodeNext(pos, next uint64, safe bool) uint64 {
	if safe {
		return next ^ (pos >> 12)
	}
	return next
}

func linkAlloc(t *testing.T, m *Model, addr, next uint64, flags uint32) []core.Finding {
	t.Helper()
	ev := evAt(core.EventAlloc, 1, addr, 0x20, 100)
	ev.Aux1 = encodeNext(addr, next, m.Profile().SafeLinking)
	ev.Flags = flags
	return m.Apply(ev)
}

func primeTcache(t *testing.T, m *Model, a, b uint64) {
	t.Helper()
	m.Apply(evAt(core.EventAlloc, 1, a, 0x20, 1))
	m.Apply(evAt(core.EventAlloc, 1, b, 0x20, 2))
	m.Apply(evAt(core.EventFree, 1, a, 0x20, 3))
	m.Apply(evAt(core.EventFree, 1, b, 0x20, 4))
}

func TestD7ValidTcacheChain(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.44"))
	m.SetRegions([]Region{{Start: 0x1000, End: 0x2000, Path: "[heap]"}})
	primeTcache(t, m, 0x1000, 0x1020)

	// Pop b; its next decodes to a, which is still in the free list.
	if fs := linkAlloc(t, m, 0x1020, 0x1000, core.EventFlagTcacheLink); len(fs) != 0 {
		t.Fatalf("unexpected findings for valid link: %#v", fs)
	}
	// Pop a; next is the end of the list.
	if fs := linkAlloc(t, m, 0x1000, 0, core.EventFlagTcacheLink); len(fs) != 0 {
		t.Fatalf("unexpected findings for end of chain: %#v", fs)
	}
}

func TestD7UnmappedPoison(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.44"))
	m.SetRegions([]Region{{Start: 0x1000, End: 0x2000, Path: "[heap]"}})
	primeTcache(t, m, 0x1000, 0x1020)

	if fs := linkAlloc(t, m, 0x1020, 0x1000, core.EventFlagTcacheLink); len(fs) != 0 {
		t.Fatalf("unexpected findings for valid link: %#v", fs)
	}
	fs := linkAlloc(t, m, 0x1000, 0x414141414141, core.EventFlagTcacheLink)
	if len(fs) != 1 || fs[0].ID != "D7" || fs[0].Severity != "high" {
		t.Fatalf("expected high D7, got %#v", fs)
	}
	if fs[0].Details["decoded"] != uint64(0x414141414141) {
		t.Fatalf("unexpected finding details: %#v", fs[0].Details)
	}
}

func TestD7MappedUntrackedAndUnaligned(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.44"))
	m.SetRegions([]Region{{Start: 0x1000, End: 0x2000, Path: "[heap]"}})
	primeTcache(t, m, 0x1000, 0x1020)
	linkAlloc(t, m, 0x1020, 0x1000, core.EventFlagTcacheLink)

	fs := linkAlloc(t, m, 0x1000, 0x1800, core.EventFlagTcacheLink)
	if len(fs) != 1 || fs[0].Severity != "medium" {
		t.Fatalf("expected mapped medium D7, got %#v", fs)
	}

	m2 := NewModelWithProfile(mustProfile(t, "2.44"))
	m2.SetRegions([]Region{{Start: 0x1000, End: 0x2000, Path: "[heap]"}})
	primeTcache(t, m2, 0x1000, 0x1020)
	linkAlloc(t, m2, 0x1020, 0x1000, core.EventFlagTcacheLink)
	fs = linkAlloc(t, m2, 0x1000, 0x1801, core.EventFlagTcacheLink)
	if len(fs) != 1 || fs[0].Severity != "high" {
		t.Fatalf("expected unaligned high D7, got %#v", fs)
	}
}

func TestD7PreSafeLinkingAndFlagGate(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.31"))
	m.SetRegions([]Region{{Start: 0x1000, End: 0x2000, Path: "[heap]"}})
	primeTcache(t, m, 0x1000, 0x1020)
	linkAlloc(t, m, 0x1020, 0x1000, core.EventFlagTcacheLink)
	fs := linkAlloc(t, m, 0x1000, 0x414141414141, core.EventFlagTcacheLink)
	if len(fs) != 1 || fs[0].ID != "D7" {
		t.Fatalf("expected pre-safe-linking D7, got %#v", fs)
	}

	m2 := NewModelWithProfile(mustProfile(t, "2.44"))
	m2.SetRegions([]Region{{Start: 0x1000, End: 0x2000, Path: "[heap]"}})
	primeTcache(t, m2, 0x1000, 0x1020)
	linkAlloc(t, m2, 0x1020, 0x1000, core.EventFlagTcacheLink)
	if fs := linkAlloc(t, m2, 0x1000, 0x414141414141, 0); len(fs) != 0 {
		t.Fatalf("expected no D7 without link flag, got %#v", fs)
	}
}
