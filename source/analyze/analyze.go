// Package analyze replays exported event streams into heap timelines.
package analyze

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"gofengshui/core"
	"gofengshui/heap"
	"gofengshui/proto"
)

type frameEnvelope struct {
	Type  string          `json:"type"`
	Event json.RawMessage `json:"event"`
}

type streamEvent struct {
	Kind  string      `json:"kind"`
	Event *core.Event `json:"event"`
}

// LoadEvents reads core events from an exported events.jsonl file.
func LoadEvents(path string) ([]core.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var events []core.Event
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		ev, ok, err := decodeLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if ok {
			events = append(events, ev)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func decodeLine(line []byte) (core.Event, bool, error) {
	var env frameEnvelope
	if err := json.Unmarshal(line, &env); err == nil && env.Type != "" {
		switch env.Type {
		case proto.TypeEvent:
			if len(env.Event) == 0 {
				return core.Event{}, false, nil
			}
			var se streamEvent
			if err := json.Unmarshal(env.Event, &se); err == nil && se.Event != nil {
				if se.Kind == "" || se.Kind == "event" {
					return *se.Event, true, nil
				}
				return core.Event{}, false, nil
			}
			var ev core.Event
			if err := json.Unmarshal(env.Event, &ev); err == nil && ev.Type != 0 {
				return ev, true, nil
			}
			return core.Event{}, false, nil
		case proto.TypeResult, proto.TypeError, proto.TypeHello:
			return core.Event{}, false, nil
		}
	}

	var ev core.Event
	if err := json.Unmarshal(line, &ev); err == nil && ev.Type != 0 {
		return ev, true, nil
	}
	return core.Event{}, false, fmt.Errorf("unrecognized event line")
}

// TimelineFile loads an event file and builds a timeline.
func TimelineFile(path string, cfg heap.TimelineConfig) (*heap.Timeline, int, error) {
	events, err := LoadEvents(path)
	if err != nil {
		return nil, 0, err
	}
	return heap.ReplayTimeline(events, cfg), len(events), nil
}
