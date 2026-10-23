package checks

import (
	"testing"
	"time"

	"gofengshui/core"
)

func TestParseFramesAndFindings(t *testing.T) {
	data := []byte(`{"v":1,"type":"event","session":"s1","seq":1,"event":{"kind":"finding","finding":{"id":"D2","severity":"high","message":"uaf"}}}` + "\n" +
		`{"v":1,"type":"result","id":7,"result":{"ok":true}}` + "\n")
	frames, err := ParseFrames(data)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("got %d frames", len(frames))
	}
	f := RequireFinding(t, frames, "D2")
	if f.Message != "uaf" {
		t.Fatalf("finding message = %q", f.Message)
	}
	result := RequireResult(t, frames, 7)
	var value struct {
		OK bool `json:"ok"`
	}
	DecodeResult(t, result, &value)
	if !value.OK {
		t.Fatal("result ok=false")
	}
}

func TestRequireNoFindings(t *testing.T) {
	data := []byte(`{"v":1,"type":"event","event":{"kind":"event","event":{"type":1,"addr":4096}}}` + "\n")
	frames, err := ParseFrames(data)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	RequireNoFindings(t, frames)
	ev := RequireEvent(t, frames, core.EventAlloc)
	if ev.Addr != 4096 {
		t.Fatalf("event addr = %d", ev.Addr)
	}
}

func TestEventually(t *testing.T) {
	count := 0
	Eventually(t, time.Second, time.Millisecond, func() bool {
		count++
		return count >= 3
	}, "counter")
}
