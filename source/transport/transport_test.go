package transport

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"gofengshui/proto"
)

type helloHandler struct{}

func (helloHandler) Handle(_ context.Context, conn *Conn, f *proto.Frame) {
	res, _ := proto.Result(f.ID, map[string]any{"ok": true})
	_ = conn.Write(res)
}

func TestServeUnix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gfs.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- ServeUnix(ctx, path, helloHandler{}) }()

	var c net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err = net.Dial("unix", path)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	codec := proto.NewCodec(c, c)
	req, _ := proto.Request(9, "hello", nil)
	if err := codec.Write(req); err != nil {
		t.Fatal(err)
	}
	f, err := codec.Read()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != proto.TypeResult || f.ID != 9 {
		t.Fatalf("unexpected response: %#v", f)
	}
	_ = c.Close()
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}
