package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"gofengshui/source/core"
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
