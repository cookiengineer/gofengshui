package proto

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const Version = 1

const (
	TypeHello   = "hello"
	TypeRequest = "request"
	TypeResult  = "result"
	TypeError   = "error"
	TypeEvent   = "event"
)

// Protocol methods.
const (
	MethodSessionCreate   = "session.create"
	MethodSessionClose    = "session.close"
	MethodSessionStatus   = "session.status"
	MethodEventsSubscribe = "events.subscribe"
	MethodHeapQuery       = "heap.query"
	MethodHeapSnapshot    = "heap.snapshot"
	MethodHeapAnalyze     = "heap.analyze"
	MethodMemRead         = "mem.read"
	MethodMemWrite        = "mem.write"
	MethodRegsGet         = "regs.get"
	MethodStackGet        = "stack.get"
	MethodBreakSet        = "break.set"
	MethodBreakClear      = "break.clear"
	MethodWatchSet        = "watch.set"
	MethodWatchClear      = "watch.clear"
	MethodPause           = "pause"
	MethodResume          = "resume"
	MethodStep            = "step"
	MethodMark            = "mark"
	MethodSinkRegister    = "sink.register"
	MethodHijackWatch     = "hijack.watch"
	MethodRopArm          = "rop.arm"
	MethodWait            = "wait"
	MethodAssert          = "assert"
	MethodExport          = "export"
)

// Event names used in event frames.
const (
	EventAlloc   = "alloc"
	EventFree    = "free"
	EventFinding = "finding"
	EventStop    = "stop"
	EventSink    = "sink"
	EventROP     = "rop"
	EventSession = "session"
	EventIO      = "io"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

// Frame is one newline-delimited JSON protocol message.
type Frame struct {
	Version int             `json:"v,omitempty"`
	Type    string          `json:"type"`
	ID      uint64          `json:"id,omitempty"`
	Session string          `json:"session,omitempty"`
	Seq     uint64          `json:"seq,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	Event   any             `json:"event,omitempty"`
}

func Request(id uint64, method string, params any) (*Frame, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return &Frame{Version: Version, Type: TypeRequest, ID: id, Method: method, Params: raw}, nil
}

func Result(id uint64, result any) (*Frame, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Frame{Version: Version, Type: TypeResult, ID: id, Result: raw}, nil
}

func ErrorFrame(id uint64, code, message string) *Frame {
	return &Frame{Version: Version, Type: TypeError, ID: id, Error: &Error{Code: code, Message: message}}
}

func EventFrame(session string, seq uint64, event any) *Frame {
	return &Frame{Version: Version, Type: TypeEvent, Session: session, Seq: seq, Event: event}
}

func (f *Frame) DecodeParams(v any) error {
	if len(f.Params) == 0 {
		return nil
	}
	return json.Unmarshal(f.Params, v)
}

func (f *Frame) DecodeResult(v any) error {
	if len(f.Result) == 0 {
		return nil
	}
	return json.Unmarshal(f.Result, v)
}

var ErrClosed = errors.New("protocol connection closed")

// Codec reads and writes newline-delimited JSON frames.
type Codec struct {
	r  *bufio.Reader
	w  io.Writer
	mu sync.Mutex
}

func NewCodec(r io.Reader, w io.Writer) *Codec {
	return &Codec{r: bufio.NewReaderSize(r, 64*1024), w: w}
}

func (c *Codec) Read() (*Frame, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, ErrClosed
		}
		if !errors.Is(err, io.EOF) {
			return nil, err
		}
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil, fmt.Errorf("empty protocol frame")
	}
	var f Frame
	if err := json.Unmarshal(line, &f); err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}
	if f.Type == "" {
		return nil, fmt.Errorf("frame has no type")
	}
	return &f, nil
}

func (c *Codec) Write(f *Frame) error {
	if f.Version == 0 {
		f.Version = Version
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(append(data, '\n')); err != nil {
		return err
	}
	if flusher, ok := c.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}
