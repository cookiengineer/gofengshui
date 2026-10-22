package heap

import (
	"encoding/binary"
	"testing"
)

type testMemory map[uint64][]byte

func (m testMemory) read(addr uint64, size int) ([]byte, error) {
	out := make([]byte, size)
	for i := 0; i < size; i++ {
		page, ok := m[(addr+uint64(i))&^0xff]
		if !ok {
			return nil, errTestUnmapped
		}
		out[i] = page[(addr+uint64(i))&0xff]
	}
	return out, nil
}

var errTestUnmapped = &testError{"unmapped"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func put64(m testMemory, addr, v uint64) {
	page := (addr &^ 0xff)
	b := m[page]
	if b == nil {
		b = make([]byte, 0x100)
		m[page] = b
	}
	binary.LittleEndian.PutUint64(b[addr&0xff:], v)
}

func put16(m testMemory, addr uint64, v uint16) {
	page := (addr &^ 0xff)
	b := m[page]
	if b == nil {
		b = make([]byte, 0x100)
		m[page] = b
	}
	binary.LittleEndian.PutUint16(b[addr&0xff:], v)
}

func put8(m testMemory, addr uint64, v byte) {
	page := (addr &^ 0xff)
	b := m[page]
	if b == nil {
		b = make([]byte, 0x100)
		m[page] = b
	}
	b[addr&0xff] = v
}

func TestReadTcacheModernLayout(t *testing.T) {
	mem := testMemory{}
	tcache := uint64(0x10000)
	for off := uint64(0); off < uint64(modernTcacheLayout.Size); off += 0x100 {
		put8(mem, tcache+off, 0)
	}
	// Three cached 0x20 chunks, newest at 0x20220.
	put16(mem, tcache, 13) // num_slots remaining
	put64(mem, tcache+modernTcacheLayout.EntriesOffset, 0x20220)
	put64(mem, 0x20220, 0x20120^(0x20220>>12))
	put64(mem, 0x20120, 0x20020^(0x20120>>12))
	put64(mem, 0x20020, 0)
	for _, addr := range []uint64{0x20020, 0x20120, 0x20220} {
		put64(mem, addr-8, 0x21)
	}
	opts := IntrospectOptions{
		Reader:  mem.read,
		Regions: []Region{{Start: 0x10000, End: 0x30000}},
		Profile: mustProfile(t, "2.44"),
	}
	if b, err := mem.read(tcache, int(modernTcacheLayout.Size)); err != nil || len(b) != int(modernTcacheLayout.Size) {
		t.Fatalf("reader: %v len=%d", err, len(b))
	}
	bins, score, _ := readTcache(opts, tcache, modernTcacheLayout)
	if score < 0 || len(bins) != 1 {
		t.Fatalf("bins=%#v score=%d", bins, score)
	}
	bin := bins[0]
	if bin.Index != 0 || bin.ChunkSize != 0x20 || bin.Count != 3 ||
		bin.Remaining != 13 {
		t.Fatalf("unexpected bin: %#v", bin)
	}
	if len(bin.Entries) != 3 || bin.Entries[0] != 0x20220 ||
		bin.Entries[1] != 0x20120 || bin.Entries[2] != 0x20020 {
		t.Fatalf("unexpected entries: %#v", bin.Entries)
	}
}

func TestReadTcacheLegacyLayout(t *testing.T) {
	mem := testMemory{}
	tcache := uint64(0x10000)
	for off := uint64(0); off < uint64(legacyTcacheLayout.Size); off += 0x100 {
		put8(mem, tcache+off, 0)
	}
	put8(mem, tcache, 2) // counts[0]
	put64(mem, tcache+legacyTcacheLayout.EntriesOffset, 0x20120)
	put64(mem, 0x20120, 0x20020)
	put64(mem, 0x20020, 0)
	for _, addr := range []uint64{0x20020, 0x20120} {
		put64(mem, addr-8, 0x21)
	}
	opts := IntrospectOptions{
		Reader:  mem.read,
		Regions: []Region{{Start: 0x10000, End: 0x30000}},
		Profile: mustProfile(t, "2.31"),
	}
	bins, score, _ := readTcache(opts, tcache, legacyTcacheLayout)
	if score < 0 || len(bins) != 1 {
		t.Fatalf("bins=%#v score=%d", bins, score)
	}
	if bins[0].Count != 2 || bins[0].Remaining != 2 ||
		len(bins[0].Entries) != 2 || bins[0].Entries[0] != 0x20120 {
		t.Fatalf("unexpected legacy bin: %#v", bins[0])
	}
}

func TestReadTcacheRejectsBadPointer(t *testing.T) {
	mem := testMemory{}
	tcache := uint64(0x10000)
	for off := uint64(0); off < uint64(modernTcacheLayout.Size); off += 0x100 {
		put8(mem, tcache+off, 0)
	}
	put16(mem, tcache, 16)
	put64(mem, tcache+modernTcacheLayout.EntriesOffset, 0x99990)
	opts := IntrospectOptions{
		Reader:  mem.read,
		Regions: []Region{{Start: 0x10000, End: 0x30000}},
		Profile: mustProfile(t, "2.44"),
	}
	if _, score, _ := readTcache(opts, tcache, modernTcacheLayout); score >= 0 {
		t.Fatalf("expected invalid tcache, score=%d", score)
	}
}
