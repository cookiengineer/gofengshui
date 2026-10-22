package ebpf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"gofengshui/core"
)

func TestIsSelfEvent(t *testing.T) {
	agent := core.Event{Comm: "gofengshui", Type: core.EventMemAccess}
	if !isSelfEvent(agent, "gofengshui") {
		t.Fatal("agent event was not recognized")
	}
	if isSelfEvent(core.Event{Comm: "target"}, "gofengshui") {
		t.Fatal("target event was treated as an agent event")
	}
	if isSelfEvent(agent, "") {
		t.Fatal("empty agent comm must not match")
	}
	if isSelfEvent(core.Event{Comm: "gofengshui", Type: core.EventOOM}, "gofengshui") {
		t.Fatal("kernel OOM events must never be filtered as self-events")
	}
}

func TestEmbeddedObjectParses(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		t.Fatalf("parse embedded bpf object: %v", err)
	}
	requiredMaps := []string{"events", "allocs", "tombstones", "stacks", "stats", "config"}
	for _, name := range requiredMaps {
		if spec.Maps[name] == nil {
			t.Errorf("missing map %s", name)
		}
	}
	requiredProgs := []string{
		"gfs_malloc_enter", "gfs_malloc_return",
		"gfs_calloc_enter", "gfs_calloc_return",
		"gfs_realloc_enter", "gfs_realloc_return",
		"gfs_free_enter", "gfs_sys_enter", "gfs_sys_exit",
	}
	for _, name := range requiredProgs {
		if spec.Programs[name] == nil {
			t.Errorf("missing program %s", name)
		}
	}
}

func TestStructSizesMatchC(t *testing.T) {
	if got := binary.Size(bpfEvent{}); got != 116 {
		t.Fatalf("bpfEvent size = %d, want 116", got)
	}
	if got := binary.Size(bpfConfig{}); got != 24 {
		t.Fatalf("bpfConfig size = %d, want 24", got)
	}
	if got := binary.Size(bpfAlloc{}); got != 64 {
		t.Fatalf("bpfAlloc size = %d, want 64", got)
	}
	if got := binary.Size(bpfTomb{}); got != 32 {
		t.Fatalf("bpfTomb size = %d, want 32", got)
	}
}

func TestDecodeEvent(t *testing.T) {
	be := bpfEvent{
		Timestamp: 123, Addr: 0x1000, Size: 0x20, ReqSize: 0x18,
		Type: uint32(core.EventAlloc), PID: 42, TID: 43,
	}
	copy(be.Comm[:], "test")
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &be); err != nil {
		t.Fatal(err)
	}
	ev, err := decodeEvent(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if ev.KTime != 123 || ev.Addr != 0x1000 || ev.Type != core.EventAlloc {
		t.Fatalf("unexpected event: %#v", ev)
	}
	if ev.Comm != "test" || ev.PID != 42 || ev.TID != 43 {
		t.Fatalf("unexpected metadata: %#v", ev)
	}
}

func TestStatsJSONTags(t *testing.T) {
	b, err := json.Marshal(Stats{Events: 1, Drops: 0, Allocs: 2, Frees: 3, Checks: 4})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"events":1`, `"drops":0`, `"allocs":2`, `"frees":3`, `"checks":4`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("stats JSON %s missing %s", b, want)
		}
	}
}
