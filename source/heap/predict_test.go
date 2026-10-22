package heap

import (
	"testing"
	"time"

	"gofengshui/core"
)

func evAt(typ core.EventType, tid uint32, addr, size uint64, ts int64) core.Event {
	return core.Event{
		Timestamp: time.Unix(0, ts), Type: typ, PID: 1, TID: tid,
		Addr: addr, Size: size, ReqSize: size - 8,
	}
}

func TestRequestChunkSize(t *testing.T) {
	cases := []struct{ req, want uint64 }{
		{0, 0x20}, {1, 0x20}, {0x18, 0x20}, {0x19, 0x30},
		{0x20, 0x30}, {0x38, 0x40}, {0x410, 0x420},
	}
	for _, c := range cases {
		if got := RequestChunkSize(c.req); got != c.want {
			t.Errorf("RequestChunkSize(0x%x)=0x%x want 0x%x", c.req, got, c.want)
		}
	}
}

func TestPredictTcacheLIFOAndConsume(t *testing.T) {
	m := NewModel()
	addrs := []uint64{0x1000, 0x1020, 0x1040}
	for i, a := range addrs {
		m.Apply(evAt(core.EventAlloc, 1, a, 0x20, int64(i)))
	}
	for i, a := range addrs {
		m.Apply(evAt(core.EventFree, 1, a, 0x20, int64(10+i)))
	}
	p := m.Predict(1, 0x18, 8)
	if p.ChunkSize != 0x20 || p.TcacheCount != 3 || len(p.Candidates) != 3 {
		t.Fatalf("unexpected prediction: %#v", p)
	}
	want := []uint64{0x1040, 0x1020, 0x1000}
	for i, c := range p.Candidates {
		if c.Addr != want[i] || c.Source != "tcache-lifo" || c.Confidence != "high" {
			t.Fatalf("candidate %d = %#v, want addr 0x%x", i, c, want[i])
		}
	}
	// Allocating the tcache head must remove it from future predictions.
	m.Apply(evAt(core.EventAlloc, 1, 0x1040, 0x20, 20))
	p = m.Predict(1, 0x18, 8)
	if len(p.Candidates) != 2 || p.Candidates[0].Addr != 0x1020 || p.Candidates[1].Addr != 0x1000 {
		t.Fatalf("unexpected post-alloc prediction: %#v", p)
	}
}

func TestPredictTcacheOverflowFastbin(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.31"))
	for i := 0; i < 10; i++ {
		a := uint64(0x1000 + i*0x20)
		m.Apply(evAt(core.EventAlloc, 1, a, 0x20, int64(i)))
		m.Apply(evAt(core.EventFree, 1, a, 0x20, int64(100+i)))
	}
	p := m.Predict(1, 0x18, 16)
	if p.TcacheCount != 7 || len(p.Candidates) != 10 {
		t.Fatalf("unexpected prediction: %#v", p)
	}
	// first 7 frees fill tcache (newest first), the rest go to fastbin LIFO
	want := []uint64{
		0x10c0, 0x10a0, 0x1080, 0x1060, 0x1040, 0x1020, 0x1000,
		0x1120, 0x1100, 0x10e0,
	}
	for i, c := range p.Candidates {
		if c.Addr != want[i] {
			t.Fatalf("candidate %d = 0x%x want 0x%x", i, c.Addr, want[i])
		}
		if i < 7 && c.Source != "tcache-lifo" {
			t.Fatalf("candidate %d source = %s", i, c.Source)
		}
		if i >= 7 && c.Source != "fastbin-lifo" {
			t.Fatalf("candidate %d source = %s", i, c.Source)
		}
	}
}

func TestPredictTcache16NoFastbins(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.44"))
	const n = 20
	for i := 0; i < n; i++ {
		a := uint64(0x1000 + i*0x20)
		m.Apply(evAt(core.EventAlloc, 1, a, 0x20, int64(i)))
	}
	for i := 0; i < n; i++ {
		a := uint64(0x1000 + i*0x20)
		m.Apply(evAt(core.EventFree, 1, a, 0x20, int64(100+i)))
	}
	p := m.Predict(1, 0x18, 24)
	if p.TcacheCount != 16 || len(p.Candidates) != n {
		t.Fatalf("unexpected prediction: %#v", p)
	}
	// glibc 2.44 caches 16 chunks LIFO; the four oldest frees go to a
	// smallbin and are consumed FIFO.
	for i := 0; i < 16; i++ {
		want := uint64(0x1000 + (15-i)*0x20)
		if p.Candidates[i].Addr != want || p.Candidates[i].Source != "tcache-lifo" {
			t.Fatalf("candidate %d = %#v want 0x%x tcache-lifo", i, p.Candidates[i], want)
		}
	}
	for i := 16; i < n; i++ {
		want := uint64(0x1000 + i*0x20)
		if p.Candidates[i].Addr != want || p.Candidates[i].Source != "smallbin-fifo" {
			t.Fatalf("candidate %d = %#v want 0x%x smallbin-fifo", i, p.Candidates[i], want)
		}
	}
	for _, c := range p.Candidates {
		if c.Source == "fastbin-lifo" {
			t.Fatalf("glibc 2.44 prediction used a fastbin: %#v", c)
		}
	}
}

func TestPredictSmallbinFIFO(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.31"))
	for i := 0; i < 10; i++ {
		a := uint64(0x2000 + i*0x90)
		m.Apply(evAt(core.EventAlloc, 1, a, 0x90, int64(i)))
		m.Apply(evAt(core.EventFree, 1, a, 0x90, int64(100+i)))
	}
	p := m.Predict(1, 0x88, 16)
	if p.TcacheCount != 7 {
		t.Fatalf("tcache count = %d", p.TcacheCount)
	}
	// first 7 frees fill tcache (newest first); older chunks are smallbin FIFO
	if p.Candidates[0].Addr != 0x2000+6*0x90 {
		t.Fatalf("first candidate = 0x%x", p.Candidates[0].Addr)
	}
	if p.Candidates[7].Addr != 0x2000+7*0x90 || p.Candidates[7].Source != "smallbin-fifo" {
		t.Fatalf("first older candidate = %#v", p.Candidates[7])
	}
}

func TestPredictTIDIsolationAndMerge(t *testing.T) {
	m := NewModel()
	m.Apply(evAt(core.EventAlloc, 1, 0x3000, 0x20, 1))
	m.Apply(evAt(core.EventAlloc, 2, 0x3020, 0x20, 2))
	m.Apply(evAt(core.EventFree, 1, 0x3000, 0x20, 10))
	m.Apply(evAt(core.EventFree, 2, 0x3020, 0x20, 11))
	if p := m.Predict(1, 0x18, 8); len(p.Candidates) != 1 || p.Candidates[0].Addr != 0x3000 {
		t.Fatalf("tid 1 prediction: %#v", p)
	}
	if p := m.Predict(2, 0x18, 8); len(p.Candidates) != 1 || p.Candidates[0].Addr != 0x3020 {
		t.Fatalf("tid 2 prediction: %#v", p)
	}
	p := m.Predict(0, 0x18, 8)
	if len(p.Candidates) != 2 || p.Candidates[0].Addr != 0x3020 || p.Candidates[1].Addr != 0x3000 {
		t.Fatalf("merged prediction: %#v", p)
	}
}

func TestPredictNoFreeChunks(t *testing.T) {
	m := NewModel()
	p := m.Predict(1, 0x18, 8)
	if len(p.Candidates) != 0 || p.FreePool != 0 {
		t.Fatalf("unexpected prediction: %#v", p)
	}
}

func TestPredictRealChunkSizes(t *testing.T) {
	m := NewModel()
	ev := core.Event{
		Timestamp: time.Unix(0, 1), Type: core.EventAlloc, PID: 1, TID: 7,
		Addr: 0x1000, Size: 0x40, ReqSize: 0x38,
	}
	m.Apply(ev)
	ev.Timestamp = time.Unix(0, 2)
	ev.Type = core.EventFree
	m.Apply(ev)
	p := m.Predict(7, 0x38, 8)
	if len(p.Candidates) != 1 || p.Candidates[0].Addr != 0x1000 {
		t.Fatalf("expected real-size free to match prediction: %#v", p)
	}
}

func TestPredictProfileAware(t *testing.T) {
	m := NewModelWithProfile(mustProfile(t, "2.44"))
	m.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))
	m.Apply(evAt(core.EventFree, 1, 0x1000, 0x20, 2))
	p := m.Predict(1, 0x18, 8)
	if p.Glibc != "2.44" || !p.SafeLinking || !p.Tcache || p.TcacheCount != 1 {
		t.Fatalf("unexpected profile in prediction: %#v", p)
	}

	old := NewModelWithProfile(mustProfile(t, "2.25"))
	old.Apply(evAt(core.EventAlloc, 1, 0x1000, 0x20, 1))
	old.Apply(evAt(core.EventFree, 1, 0x1000, 0x20, 2))
	p = old.Predict(1, 0x18, 8)
	if p.Glibc != "2.25" || p.SafeLinking || p.Tcache || p.TcacheCount != 0 {
		t.Fatalf("unexpected no-tcache prediction: %#v", p)
	}
	if len(p.Candidates) != 1 || p.Candidates[0].Source != "fastbin-lifo" {
		t.Fatalf("expected fastbin candidate: %#v", p)
	}
}
