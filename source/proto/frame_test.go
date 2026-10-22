package proto

import (
	"bytes"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	codec := NewCodec(&buf, &buf)
	req, err := Request(7, MethodHeapQuery, map[string]any{"addr": 0x1234})
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.Write(req); err != nil {
		t.Fatal(err)
	}
	got, err := codec.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 7 || got.Method != MethodHeapQuery || got.Type != TypeRequest {
		t.Fatalf("unexpected frame: %#v", got)
	}
	var p struct {
		Addr uint64 `json:"addr"`
	}
	if err := got.DecodeParams(&p); err != nil {
		t.Fatal(err)
	}
	if p.Addr != 0x1234 {
		t.Fatalf("addr = 0x%x", p.Addr)
	}
}

func TestErrorFrame(t *testing.T) {
	f := ErrorFrame(3, "bad", "nope")
	if f.Type != TypeError || f.Error == nil || f.Error.Code != "bad" {
		t.Fatalf("unexpected frame: %#v", f)
	}
}
