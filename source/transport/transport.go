package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"gofengshui/source/proto"
)

// Conn is a framed protocol connection.
type Conn struct {
	codec *proto.Codec
	mu    sync.Mutex
	err   error
}

func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{codec: proto.NewCodec(r, w)}
}

func (c *Conn) Read() (*proto.Frame, error) { return c.codec.Read() }

func (c *Conn) Write(f *proto.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if err := c.codec.Write(f); err != nil {
		c.err = err
	}
	return c.err
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = proto.ErrClosed
	}
	return nil
}

// Handler processes one framed request. Implementations write results and
// may stream events through the same connection.
type Handler interface {
	Handle(ctx context.Context, conn *Conn, f *proto.Frame)
}

// ServeStdio runs one protocol session over stdin/stdout.
func ServeStdio(ctx context.Context, h Handler) error {
	conn := NewConn(os.Stdin, os.Stdout)
	return serveLoop(ctx, h, conn)
}

func serveLoop(ctx context.Context, h Handler, conn *Conn) error {
	for {
		f, err := conn.Read()
		if err != nil {
			if errors.Is(err, proto.ErrClosed) {
				return nil
			}
			return err
		}
		if f.Type != proto.TypeHello && f.Type != proto.TypeRequest {
			_ = conn.Write(proto.ErrorFrame(f.ID, "bad_type", "expected request frame"))
			continue
		}
		h.Handle(ctx, conn, f)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// ServeUnix accepts connections on a unix socket until ctx is cancelled.
func ServeUnix(ctx context.Context, path string, h Handler) error {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen %s: %w", path, err)
	}
	defer ln.Close()
	defer os.Remove(path)
	_ = os.Chmod(path, 0o600)

	var active sync.Map
	go func() {
		<-ctx.Done()
		ln.Close()
		active.Range(func(k, _ any) bool {
			if c, ok := k.(net.Conn); ok {
				_ = c.Close()
			}
			return true
		})
	}()

	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			break
		}
		active.Store(c, struct{}{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer active.Delete(c)
			defer c.Close()
			conn := NewConn(c, c)
			_ = serveLoop(ctx, h, conn)
		}()
	}
	wg.Wait()
	return nil
}
