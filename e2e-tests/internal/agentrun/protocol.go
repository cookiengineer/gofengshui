package agentrun

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"gofengshui/e2e/internal/checks"
)

type Client struct {
	conn   net.Conn
	reader *bufio.Reader
	nextID uint64
}

func Dial(t testing.TB, socket string, timeout time.Duration) *Client {
	t.Helper()
	conn, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		t.Fatalf("dial %s: %v", socket, err)
	}
	c := &Client{conn: conn, reader: bufio.NewReaderSize(conn, 256*1024)}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (c *Client) Send(t testing.TB, method string, params any, session string) uint64 {
	t.Helper()
	c.nextID++
	req := checks.Request{
		Version: 1,
		Type:    "request",
		ID:      c.nextID,
		Session: session,
		Method:  method,
		Params:  params,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal %s: %v", method, err)
	}
	data = append(data, '\n')
	if _, err := c.conn.Write(data); err != nil {
		t.Fatalf("write %s: %v", method, err)
	}
	return c.nextID
}

func (c *Client) Read(t testing.TB, timeout time.Duration) checks.Frame {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var f checks.Frame
	if err := json.Unmarshal(line, &f); err != nil {
		t.Fatalf("decode frame: %v\n%s", err, string(line))
	}
	return f
}

func (c *Client) Call(t testing.TB, method string, params any, session string, timeout time.Duration) checks.Frame {
	t.Helper()
	id := c.Send(t, method, params, session)
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out waiting for %s result", method)
		}
		f := c.Read(t, remaining)
		if f.Type == "error" && f.ID == id {
			msg := "unknown error"
			if f.Error != nil {
				msg = f.Error.Code + ": " + f.Error.Message
			}
			t.Fatalf("%s failed: %s", method, msg)
		}
		if f.Type == "result" && f.ID == id {
			return f
		}
	}
}

func (c *Client) WaitFor(t testing.TB, label string, timeout time.Duration, pred func(checks.Frame) bool) checks.Frame {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out waiting for %s", label)
		}
		f := c.Read(t, remaining)
		if pred(f) {
			return f
		}
	}
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func RequireEventFinding(t testing.TB, f checks.Frame, id string) {
	t.Helper()
	if f.Event == nil || f.Event.Finding == nil || f.Event.Finding.ID != id {
		t.Fatalf("expected finding %s in frame, got %s", id, string(mustJSON(f)))
	}
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf("%v", err))
	}
	return data
}
