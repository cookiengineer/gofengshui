package heap

import (
	"testing"

	"gofengshui/source/core"
)

func TestBuildRecipeFromFreeList(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))
	m.Apply(evAt(core.EventAlloc, 1, 0x1020, 0x20, 2))
	m.Apply(evAt(core.EventFree, 1, 0x1000, 0x20, 3))
	m.Apply(evAt(core.EventFree, 1, 0x1020, 0x20, 4))

	r := m.BuildRecipe(1, 0x18, 2)
	if len(r.Steps) != 2 || r.Missing != 0 {
		t.Fatalf("unexpected recipe: %#v", r)
	}
	if r.Steps[0].Expected != 0x1020 || r.Steps[1].Expected != 0x1000 {
		t.Fatalf("unexpected reclaim order: %#v", r.Steps)
	}
	if r.Steps[0].Action != "malloc" || r.Steps[0].Source != "tcache-lifo" {
		t.Fatalf("unexpected first step: %#v", r.Steps[0])
	}

	r = m.BuildRecipe(1, 0x18, 4)
	if len(r.Steps) != 4 || r.Missing != 2 {
		t.Fatalf("unexpected shortfall recipe: %#v", r)
	}
	if r.Steps[2].Expected != 0 || r.Steps[2].Action != "malloc" {
		t.Fatalf("unexpected fallback step: %#v", r.Steps[2])
	}
}

func TestBuildRecipeUsesLiveCandidates(t *testing.T) {
	m := NewModel()
	for i := 0; i < 4; i++ {
		m.Apply(evAt(core.EventAlloc, 1, uint64(0x1000+i*0x20), 0x20, int64(i+1)))
	}
	m.Apply(evAt(core.EventFree, 1, 0x1000, 0x20, 10))
	m.Apply(evAt(core.EventFree, 1, 0x1020, 0x20, 11))

	r := m.BuildRecipe(1, 0x18, 4)
	if len(r.Steps) != 4 || r.Missing != 0 {
		t.Fatalf("unexpected recipe: %#v", r)
	}
	if r.Steps[2].Action != "free" || r.Steps[2].Expected != 0x1040 {
		t.Fatalf("unexpected live-candidate step: %#v", r.Steps[2])
	}
	if len(r.LiveCandidates) != 2 {
		t.Fatalf("unexpected live candidates: %#v", r.LiveCandidates)
	}
}
