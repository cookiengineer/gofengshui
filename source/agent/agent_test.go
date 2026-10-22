package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"gofengshui/source/core"
	"gofengshui/source/debugger"
	"gofengshui/source/heap"
	"gofengshui/source/proto"
	"gofengshui/source/transport"
)

func TestHello(t *testing.T) {
	ag := New()
	var out bytes.Buffer
	conn := transport.NewConn(bytes.NewReader(nil), &out)
	req := &proto.Frame{Version: proto.Version, Type: proto.TypeHello, ID: 1}
	ag.Handle(context.Background(), conn, req)

	var resp proto.Frame
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("decode response: %v (%q)", err, out.String())
	}
	if resp.Type != proto.TypeResult || resp.ID != 1 {
		t.Fatalf("unexpected response: %#v", resp)
	}
	var result struct {
		Version int      `json:"version"`
		Methods []string `json:"methods"`
	}
	if err := resp.DecodeResult(&result); err != nil {
		t.Fatal(err)
	}
	if result.Version != proto.Version || len(result.Methods) < 10 {
		t.Fatalf("unexpected hello result: %#v", result)
	}
}

func TestNormalizeArgs(t *testing.T) {
	got := NormalizeArgs([]string{"a", "", " b ", "c"})
	if len(got) != 3 || got[2] != "c" {
		t.Fatalf("unexpected args: %#v", got)
	}
}

func TestHeapPredictHandler(t *testing.T) {
	m := heap.NewModel()
	now := time.Now()
	m.Apply(core.Event{Timestamp: now, Type: core.EventAlloc, PID: 1, TID: 7, Addr: 0x1000, Size: 0x20, ReqSize: 0x18})
	m.Apply(core.Event{Timestamp: now.Add(time.Millisecond), Type: core.EventFree, PID: 1, TID: 7, Addr: 0x1000, Size: 0x20})
	s := &Session{model: m}
	params, _ := json.Marshal(map[string]any{"tid": 7, "size": 0x18})
	f := &proto.Frame{Version: proto.Version, Type: proto.TypeRequest, ID: 5, Method: proto.MethodHeapPredict, Params: params}
	var out bytes.Buffer
	conn := transport.NewConn(bytes.NewReader(nil), &out)
	s.heapPredict(conn, f)
	var resp proto.Frame
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("decode response: %v (%q)", err, out.String())
	}
	if resp.Type != proto.TypeResult {
		t.Fatalf("unexpected response: %#v", resp)
	}
	var p heap.Prediction
	if err := resp.DecodeResult(&p); err != nil {
		t.Fatal(err)
	}
	if len(p.Candidates) != 1 || p.Candidates[0].Addr != 0x1000 || p.Candidates[0].Source != "tcache-lifo" {
		t.Fatalf("unexpected prediction: %#v", p)
	}
}

type fakeWatcher struct {
	addr, size, allocID uint64
	typ                 debugger.WatchType
}

func (f *fakeWatcher) SetWatchpoint(addr, size uint64, typ debugger.WatchType, allocID uint64) (*debugger.Watchpoint, error) {
	f.addr, f.size, f.typ, f.allocID = addr, size, typ, allocID
	return &debugger.Watchpoint{ID: 1, Addr: addr, Size: size, Type: typ, AllocID: allocID}, nil
}
func (f *fakeWatcher) ClearWatchpoint(uint64) error { return nil }

func TestWatchAllocationByID(t *testing.T) {
	m := heap.NewModel()
	now := time.Now()
	m.Apply(core.Event{Timestamp: now, Type: core.EventAlloc, PID: 1, TID: 1, Addr: 0x5000, Size: 0x30, ReqSize: 0x28})
	a := m.Allocations(true)[0]
	fw := &fakeWatcher{}
	s := &Session{model: m, watcher: fw}
	params, _ := json.Marshal(map[string]any{"alloc_id": a.ID, "type": "write"})
	f := &proto.Frame{Version: proto.Version, Type: proto.TypeRequest, ID: 7, Method: proto.MethodWatchSet, Params: params}
	var out bytes.Buffer
	conn := transport.NewConn(bytes.NewReader(nil), &out)
	s.watchSet(conn, f)
	if fw.addr != 0x5000 || fw.size != 8 || fw.typ != debugger.WatchWrite || fw.allocID != a.ID {
		t.Fatalf("unexpected watch request: %#v", fw)
	}
	var resp proto.Frame
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Type != proto.TypeResult {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestSubscribeReplayCursor(t *testing.T) {
	var buf bytes.Buffer
	conn := transport.NewConn(bytes.NewReader(nil), &buf)
	s := &Session{
		id:   "s1",
		subs: make(map[uint64]*subscriber),
		done: make(chan struct{}),
		history: []*proto.Frame{
			proto.EventFrame("s1", 1, map[string]any{"kind": "marker", "marker": "one"}),
			proto.EventFrame("s1", 2, map[string]any{"kind": "marker", "marker": "two"}),
			proto.EventFrame("s1", 3, map[string]any{"kind": "marker", "marker": "three"}),
		},
	}
	s.subscribe(conn, 1)
	time.Sleep(100 * time.Millisecond)
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 replayed frames, got %d: %q", len(lines), buf.String())
	}
	if !bytes.Contains(lines[0], []byte(`"seq":2`)) || !bytes.Contains(lines[1], []byte(`"seq":3`)) {
		t.Fatalf("unexpected replay order: %q", buf.String())
	}
}

func TestRefreshResolverSelf(t *testing.T) {
	s := &Session{target: core.Target{PID: os.Getpid()}}
	if err := s.RefreshResolver(); err != nil {
		t.Fatal(err)
	}
	r := s.getResolver()
	if r == nil || len(r.Modules) == 0 {
		t.Fatal("refresh did not resolve modules")
	}
}

func TestFaultAccessNames(t *testing.T) {
	cases := map[int32]string{1: "not-mapped", 2: "protection", 0x80: "kernel", 99: "unknown"}
	for code, want := range cases {
		if got := faultAccess(code); got != want {
			t.Fatalf("faultAccess(%d) = %q, want %q", code, got, want)
		}
	}
}
