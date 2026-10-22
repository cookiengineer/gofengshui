package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

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
