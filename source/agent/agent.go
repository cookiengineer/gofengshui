package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"gofengshui/source/core"
	"gofengshui/source/debugger"
	"gofengshui/source/ebpf"
	"gofengshui/source/heap"
	"gofengshui/source/proto"
	"gofengshui/source/symbols"
	"gofengshui/source/transport"
)

// Agent manages protocol sessions.
type Agent struct {
	mu       sync.Mutex
	sessions map[string]*Session
	next     uint64
}

func New() *Agent {
	return &Agent{sessions: make(map[string]*Session)}
}

// Handle implements transport.Handler.
func (a *Agent) Handle(ctx context.Context, conn *transport.Conn, f *proto.Frame) {
	if f.Type == proto.TypeHello {
		a.reply(conn, f, map[string]any{
			"version": proto.Version,
			"agent":   "gofengshui",
			"methods": methods(),
		}, nil)
		return
	}

	switch f.Method {
	case proto.MethodSessionCreate:
		a.handleCreate(conn, f)
	case proto.MethodSessionClose:
		a.handleClose(conn, f)
	default:
		id := requestSession(f)
		if id == "" {
			a.reply(conn, f, nil, &proto.Error{Code: "no_session", Message: "request has no session"})
			return
		}
		a.mu.Lock()
		s := a.sessions[id]
		a.mu.Unlock()
		if s == nil {
			a.reply(conn, f, nil, &proto.Error{Code: "no_session", Message: "unknown session " + id})
			return
		}
		s.Handle(ctx, conn, f)
	}
}

func methods() []string {
	return []string{
		proto.MethodSessionCreate, proto.MethodSessionClose, proto.MethodSessionStatus,
		proto.MethodEventsSubscribe, proto.MethodHeapQuery, proto.MethodHeapSnapshot,
		proto.MethodMemRead, proto.MethodMemWrite, proto.MethodRegsGet, proto.MethodStackGet,
		proto.MethodBreakSet, proto.MethodBreakClear, proto.MethodWatchSet, proto.MethodWatchClear,
		proto.MethodPause, proto.MethodResume, proto.MethodStep, proto.MethodMark,
		proto.MethodSinkRegister, proto.MethodHijackWatch, proto.MethodRopArm,
		proto.MethodWait, proto.MethodAssert, proto.MethodExport,
	}
}

func (a *Agent) reply(conn *transport.Conn, f *proto.Frame, result any, err *proto.Error) {
	if err != nil {
		_ = conn.Write(proto.ErrorFrame(f.ID, err.Code, err.Message))
		return
	}
	fr, e := proto.Result(f.ID, result)
	if e != nil {
		_ = conn.Write(proto.ErrorFrame(f.ID, "marshal", e.Error()))
		return
	}
	_ = conn.Write(fr)
}

func requestSession(f *proto.Frame) string {
	if f.Session != "" {
		return f.Session
	}
	var p struct {
		Session string `json:"session"`
	}
	_ = f.DecodeParams(&p)
	return p.Session
}

// CreateParams configures a new session.
type CreateParams struct {
	Mode   string      `json:"mode"`
	Path   string      `json:"path"`
	Args   []string    `json:"args"`
	Env    []string    `json:"env"`
	Dir    string      `json:"dir"`
	PID    int         `json:"pid"`
	Follow bool        `json:"follow"`
	Pause  bool        `json:"pause"`
	Stdout string      `json:"stdout"`
	Stderr string      `json:"stderr"`
	Config core.Config `json:"config"`
}

func (a *Agent) handleCreate(conn *transport.Conn, f *proto.Frame) {
	var p CreateParams
	if err := f.DecodeParams(&p); err != nil {
		a.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: err.Error()})
		return
	}
	if p.Mode == "" {
		p.Mode = "spawn"
	}
	if p.Mode != "spawn" && p.Mode != "attach" {
		a.reply(conn, f, nil, &proto.Error{Code: "bad_params", Message: "mode must be spawn or attach"})
		return
	}
	s, err := a.Start(p)
	if err != nil {
		a.reply(conn, f, nil, &proto.Error{Code: "create_failed", Message: err.Error()})
		return
	}
	a.reply(conn, f, map[string]any{
		"session": s.ID(),
		"target":  s.Target(),
		"config":  s.cfg,
		"paused":  p.Pause,
	}, nil)
}

// Start creates and starts a session without protocol framing.
func (a *Agent) Start(p CreateParams) (*Session, error) {
	if p.Mode == "" {
		p.Mode = "spawn"
	}
	cfg := p.Config
	if !cfg.Heap && !cfg.Syscalls && !cfg.UAF && !cfg.Stacks && !cfg.Detectors &&
		!cfg.NoEBPF && !cfg.NoLibc {
		cfg = core.DefaultConfig()
	}
	s, err := a.createSession(p, cfg)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.next++
	id := sessionID(a.next)
	a.sessions[id] = s
	a.mu.Unlock()
	s.id = id
	s.start()
	if p.Pause {
		_ = s.tracer.Pause()
		s.tracer.WaitStopped(2 * time.Second)
	} else {
		_ = s.tracer.Continue(0)
	}
	return s, nil
}

func sessionID(n uint64) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("s%x%s", n, hex.EncodeToString(b[:]))
}

func (a *Agent) createSession(p CreateParams, cfg core.Config) (*Session, error) {
	s := &Session{
		agent:   a,
		cfg:     cfg,
		model:   heap.NewModel(),
		stops:   make(chan debugger.Stop, 256),
		done:    make(chan struct{}),
		subs:    make(map[uint64]*subscriber),
		started: time.Now(),
	}
	s.engine = detectEngine(s.model)

	switch p.Mode {
	case "spawn":
		var stdout, stderr io.Writer = io.Discard, io.Discard
		var files []*os.File
		if p.Stdout != "" {
			fh, err := os.Create(p.Stdout)
			if err != nil {
				return nil, err
			}
			files = append(files, fh)
			stdout = fh
		}
		if p.Stderr != "" {
			fh, err := os.Create(p.Stderr)
			if err != nil {
				for _, f := range files {
					f.Close()
				}
				return nil, err
			}
			files = append(files, fh)
			stderr = fh
		}
		tr, err := debugger.Launch(debugger.LaunchOptions{
			Path: p.Path, Args: p.Args, Env: p.Env, Dir: p.Dir,
			Stdout: stdout, Stderr: stderr, Follow: p.Follow,
		})
		if err != nil {
			for _, f := range files {
				f.Close()
			}
			return nil, err
		}
		s.tracer = tr
		s.files = files

		// The first stop is the exec stop. Resolve the executable entry point,
		// stop there once so libc and the dynamic loader are mapped, then
		// attach eBPF before the program reaches main.
		if _, err := tr.NextStop(5 * time.Second); err != nil {
			_ = tr.Kill()
			return nil, fmt.Errorf("wait for exec stop: %w", err)
		}
		if entry, err := symbols.RuntimeEntry(tr.PID()); err == nil {
			if _, bpErr := tr.SetBreakpoint(entry, "_start", true); bpErr == nil {
				_ = tr.Continue(0)
				if _, err := tr.NextStop(3 * time.Second); err == nil {
					_ = tr.ClearBreakpoint(entry)
				} else {
					_ = tr.ClearBreakpoint(entry)
				}
			} else {
				_ = tr.Continue(0)
			}
		} else {
			_ = tr.Continue(0)
		}

	case "attach":
		if p.PID <= 0 {
			return nil, errors.New("attach mode requires pid")
		}
		tr, err := debugger.Attach(p.PID, p.Follow)
		if err != nil {
			return nil, err
		}
		s.tracer = tr
	}

	target, resolver, err := resolveTarget(s.tracer.PID())
	if err != nil {
		_ = s.tracer.Kill()
		return nil, err
	}
	s.target = target
	s.resolver = resolver
	if cfg.PID == 0 && target.InitPID != 0 {
		cfg.PID = target.InitPID
	}
	if cfg.CgroupID == 0 && target.CgroupID != 0 {
		cfg.CgroupID = target.CgroupID
	}
	s.cfg = cfg

	if cfg.NoEBPF || os.Getenv("GFS_NO_EBPF") == "1" {
		return s, nil
	}
	tracer, err := ebpf.New(cfg, target)
	if err != nil {
		_ = s.tracer.Close(true)
		return nil, err
	}
	if err := tracer.Attach(); err != nil {
		tracer.Close()
		_ = s.tracer.Close(true)
		return nil, fmt.Errorf("attach ebpf: %w", err)
	}
	s.bpf = tracer
	return s, nil
}

func resolveTarget(pid int) (core.Target, *symbols.Resolver, error) {
	info, err := symbols.ResolveTarget(pid)
	if err != nil {
		return core.Target{}, nil, err
	}
	res, err := symbols.NewResolver(pid)
	if err != nil {
		return core.Target{}, nil, err
	}
	t := core.Target{
		PID: pid, InitPID: info.InitPID, CgroupID: info.CgroupID,
		ExePath: info.ExePath, LibcPath: info.LibcPath,
		LibcBase: info.LibcBase, ExeBase: info.ExeBase,
		Arch: core.ArchX86_64, Compatible: info.LibcPath != "",
	}
	return t, res, nil
}

func (a *Agent) handleClose(conn *transport.Conn, f *proto.Frame) {
	id := requestSession(f)
	var p struct {
		Session string `json:"session"`
		Kill    bool   `json:"kill"`
	}
	_ = f.DecodeParams(&p)
	if id == "" {
		id = p.Session
	}
	a.mu.Lock()
	s := a.sessions[id]
	delete(a.sessions, id)
	a.mu.Unlock()
	if s == nil {
		a.reply(conn, f, nil, &proto.Error{Code: "no_session", Message: "unknown session " + id})
		return
	}
	s.Close(p.Kill)
	a.reply(conn, f, map[string]any{"closed": id}, nil)
}

// Sessions returns the number of active sessions.
func (a *Agent) Sessions() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessions)
}

// SessionIDs returns active session IDs.
func (a *Agent) SessionIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.sessions))
	for id := range a.sessions {
		out = append(out, id)
	}
	return out
}

// Trim removes a session without protocol handling (used by tests).
func (a *Agent) Trim(id string) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
}

// ErrUnknownMode is returned for invalid session modes.
var ErrUnknownMode = errors.New("unknown session mode")

// NormalizeArgs keeps empty argv elements out of the exec list.
func NormalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.TrimSpace(a) != "" {
			out = append(out, a)
		}
	}
	return out
}
