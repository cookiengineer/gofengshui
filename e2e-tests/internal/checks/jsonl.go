package checks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"gofengshui/core"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type StreamEvent struct {
	Kind    string          `json:"kind"`
	Event   *core.Event     `json:"event"`
	Finding *core.Finding   `json:"finding"`
	Marker  string          `json:"marker"`
	Message string          `json:"message"`
	Stop    json.RawMessage `json:"stop"`
	Sink    json.RawMessage `json:"sink"`
	ROP     json.RawMessage `json:"rop"`
}

type Frame struct {
	Version int             `json:"v"`
	Type    string          `json:"type"`
	ID      uint64          `json:"id"`
	Session string          `json:"session"`
	Seq     uint64          `json:"seq"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *Error          `json:"error"`
	Event   *StreamEvent    `json:"event"`
}

type Request struct {
	Version int    `json:"v"`
	Type    string `json:"type"`
	ID      uint64 `json:"id"`
	Session string `json:"session,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

func ParseFrames(data []byte) ([]Frame, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var out []Frame
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var f Frame
		if err := json.Unmarshal(line, &f); err != nil {
			return out, err
		}
		out = append(out, f)
	}
	return out, scanner.Err()
}

func LoadFrames(t testing.TB, path string) []Frame {
	t.Helper()
	data := RequireFile(t, path)
	frames, err := ParseFrames(data)
	if err != nil {
		t.Fatalf("parse frames %s: %v", path, err)
	}
	return frames
}

func Findings(frames []Frame) []core.Finding {
	var out []core.Finding
	for _, f := range frames {
		if f.Event != nil && f.Event.Finding != nil {
			out = append(out, *f.Event.Finding)
		}
	}
	return out
}

func FindingIDs(frames []Frame) []string {
	findings := Findings(frames)
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}

func RequireFinding(t testing.TB, frames []Frame, id string) core.Finding {
	t.Helper()
	for _, f := range Findings(frames) {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s missing; got %s", id, Summary(FindingIDs(frames)))
	return core.Finding{}
}

func RequireNoFindings(t testing.TB, frames []Frame) {
	t.Helper()
	if ids := FindingIDs(frames); len(ids) > 0 {
		t.Fatalf("unexpected findings: %s", Summary(ids))
	}
}

func RequireEvent(t testing.TB, frames []Frame, typ core.EventType) core.Event {
	t.Helper()
	for _, f := range frames {
		if f.Event != nil && f.Event.Event != nil && f.Event.Event.Type == typ {
			return *f.Event.Event
		}
		if f.Event != nil && f.Event.Finding != nil && f.Event.Finding.Event != nil && f.Event.Finding.Event.Type == typ {
			return *f.Event.Finding.Event
		}
	}
	t.Fatalf("event type %s missing", typ)
	return core.Event{}
}

func RequireResult(t testing.TB, frames []Frame, id uint64) Frame {
	t.Helper()
	for _, f := range frames {
		if f.Type == "result" && f.ID == id {
			return f
		}
		if f.Type == "error" && f.ID == id && f.Error != nil {
			t.Fatalf("request %d failed: %s: %s", id, f.Error.Code, f.Error.Message)
		}
	}
	t.Fatalf("result for request %d missing", id)
	return Frame{}
}

func LoadStreamEvents(t testing.TB, path string) []StreamEvent {
	t.Helper()
	data := RequireFile(t, path)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var out []StreamEvent
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev StreamEvent
		if err := json.Unmarshal(line, &ev); err == nil && ev.Kind != "" {
			out = append(out, ev)
		}
	}
	return out
}

func LoadJSONLFile(t testing.TB, path string) []Frame {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	frames, err := ParseFrames(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return frames
}
