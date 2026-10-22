package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gofengshui/source/agent"
	"gofengshui/source/core"
	"gofengshui/source/debugger"
	"gofengshui/source/detect"
	"gofengshui/source/proto"
	"gofengshui/source/transport"
)

const Version = "0.1.0"

// Main runs the command-line interface and returns an exit code.
func Main(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Printf("gofengshui %s\n", Version)
		return 0
	case "run":
		err = cmdRun(args[1:], "spawn")
	case "attach":
		err = cmdRun(args[1:], "attach")
	case "validate":
		err = cmdValidate(args[1:])
	case "agent", "serve":
		err = cmdAgent(args[1:])
	case "stdio":
		err = cmdStdio()
	case "ctl":
		err = cmdCtl(args[1:])
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `gofengshui - glibc heap feng shui and exploit validation

Usage:
  gofengshui run [flags] -- <program> [args...]
  gofengshui attach --pid <pid> [flags]
  gofengshui validate [flags] -- <program> [args...]
  gofengshui agent --socket /run/gofengshui.sock
  gofengshui stdio
  gofengshui ctl --socket <path> --method <method> [--params JSON] [--events]

Flags for run/attach:
  --pid N            attach to N instead of spawning
  --pause            stop at the first controlled point
  --jsonl            serve the JSONL protocol on stdin/stdout
  --follow           follow fork/vfork (threads are always traced)
  --report DIR       export a report when the target exits
  --stdout PATH      target stdout file
  --stderr PATH      target stderr file
  --no-heap          disable allocator uprobes
  --no-syscalls      disable raw syscall tracing
  --no-stacks        disable user stack capture
  --no-detectors     disable detector findings
  --no-libc          disable libc uprobe attachment
  --no-ebpf          diagnostic: run ptrace only, without eBPF
  --backfill         scan the main heap when attaching (default true)
  --glibc-version    override detected glibc version (e.g. 2.31)
  --watch-freed      watch recently freed chunks for direct UAF writes
  --expect-findings  comma-separated detector IDs that must be present
  --expect-no-findings  fail if any finding is produced
  --expect-regs      validate sink registers (e.g. rdi=0x4141)
`)
}

func configFlags(fs *flag.FlagSet) (*core.Config, *bool, *bool, *bool, *string, *string, *string) {
	cfg := core.DefaultConfig()
	fs.BoolVar(&cfg.Heap, "heap", true, "enable allocator tracing")
	fs.BoolVar(&cfg.Syscalls, "syscalls", true, "enable syscall tracing")
	fs.BoolVar(&cfg.UAF, "uaf", true, "enable UAF checks")
	fs.BoolVar(&cfg.Stacks, "stacks", true, "enable user stack capture")
	fs.BoolVar(&cfg.Detectors, "detectors", true, "enable detector findings")
	fs.BoolVar(&cfg.NoLibc, "no-libc", false, "disable libc uprobe attachment")
	fs.BoolVar(&cfg.NoEBPF, "no-ebpf", false, "diagnostic: run ptrace only, without eBPF")
	fs.BoolVar(&cfg.Backfill, "backfill", true, "scan the main heap when attaching")
	fs.StringVar(&cfg.GlibcVersion, "glibc-version", "", "override detected glibc version (e.g. 2.31)")
	fs.BoolVar(&cfg.WatchFreed, "watch-freed", false, "watch recently freed chunks for direct UAF writes")
	pause := fs.Bool("pause", false, "pause before continuing the target")
	jsonl := fs.Bool("jsonl", false, "serve JSONL protocol on stdin/stdout")
	follow := fs.Bool("follow", false, "follow clone/fork/vfork")
	report := fs.String("report", "", "export report directory on exit")
	stdout := fs.String("stdout", "", "target stdout file")
	stderr := fs.String("stderr", "", "target stderr file")
	return &cfg, pause, jsonl, follow, report, stdout, stderr
}

func cmdRun(args []string, mode string) error {
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pid := fs.Int("pid", 0, "pid to attach to")
	expectFindings := fs.String("expect-findings", "", "comma-separated detector IDs that must be present")
	expectNoFindings := fs.Bool("expect-no-findings", false, "fail if any finding is produced")
	cfg, pause, jsonl, follow, report, stdout, stderr := configFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()

	params := agent.CreateParams{
		Mode: mode, PID: *pid, Pause: *pause, Follow: *follow,
		Config: *cfg, Stdout: *stdout, Stderr: *stderr,
	}
	if mode == "spawn" {
		if len(rest) == 0 {
			return errors.New("missing target program")
		}
		params.Path = rest[0]
		params.Args = rest
	} else if *pid <= 0 {
		return errors.New("attach requires --pid")
	}

	ag := agent.New()
	s, err := ag.Start(params)
	if err != nil {
		return err
	}
	kill := mode == "spawn"
	defer s.Close(kill)

	fmt.Fprintf(os.Stderr, "gofengshui: session %s target pid=%d init_pid=%d cgroup=%d exe=%s libc=%s allocator=%s\n",
		s.ID(), s.Target().PID, s.Target().InitPID, s.Target().CgroupID, s.Target().ExePath, s.Target().LibcPath, s.Model().Profile())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *jsonl {
		conn := transport.NewConn(os.Stdin, os.Stdout)
		s.Subscribe(conn, 0)
		for {
			f, err := conn.Read()
			if err != nil {
				if errors.Is(err, proto.ErrClosed) {
					break
				}
				return err
			}
			s.Handle(ctx, conn, f)
		}
		return checkFindings(s.Engine(), *expectFindings, *expectNoFindings)
	}

	conn := transport.NewConn(strings.NewReader(""), os.Stdout)
	s.Subscribe(conn, 0)

	if *pause {
		fmt.Fprintln(os.Stderr, "target paused; press Enter to continue")
		_, _ = fmt.Fscanln(os.Stdin)
		if err := s.ContinueAll(); err != nil {
			return err
		}
	}

	done := make(chan struct{})
	go func() {
		s.WaitExit(0)
		close(done)
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
	time.Sleep(100 * time.Millisecond)

	if err := checkFindings(s.Engine(), *expectFindings, *expectNoFindings); err != nil {
		return err
	}

	if *report != "" {
		if err := s.Export(*report); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", *report)
	}
	return nil
}

func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	socket := fs.String("socket", "/run/gofengshui.sock", "unix socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ag := agent.New()
	fmt.Fprintf(os.Stderr, "gofengshui: listening on %s\n", *socket)
	return transport.ServeUnix(ctx, *socket, ag)
}

func cmdStdio() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return transport.ServeStdio(ctx, agent.New())
}

func cmdCtl(args []string) error {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	socket := fs.String("socket", "/run/gofengshui.sock", "unix socket path")
	method := fs.String("method", "", "protocol method")
	params := fs.String("params", "{}", "JSON params")
	session := fs.String("session", "", "session id")
	events := fs.Bool("events", false, "stream events after the result")
	until := fs.String("until", "", "stop streaming on finding:D2, sink, rop, marker or stop")
	maxEvents := fs.Int("max-events", 0, "stop after N events (0 = unlimited)")
	closeSession := fs.Bool("close", false, "close the session on exit")
	timeout := fs.Duration("timeout", 30*time.Second, "request/stream timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *method == "" {
		return errors.New("--method is required")
	}
	if !json.Valid([]byte(*params)) {
		return errors.New("--params is not valid JSON")
	}
	raw := json.RawMessage(*params)

	conn, err := net.DialTimeout("unix", *socket, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	codec := proto.NewCodec(conn, conn)
	deadline := time.Now().Add(*timeout)
	_ = conn.SetDeadline(deadline)

	req, err := proto.Request(1, *method, raw)
	if err != nil {
		return err
	}
	req.Session = *session
	if err := codec.Write(req); err != nil {
		return err
	}

	sessionID := *session
	resultSeen := false
	subscribed := *method == proto.MethodEventsSubscribe
	eventCount := 0
	for {
		f, err := codec.Read()
		if err != nil {
			return err
		}
		switch f.Type {
		case proto.TypeError:
			if f.ID == req.ID {
				return f.Error
			}
		case proto.TypeResult:
			if f.ID == req.ID {
				printJSON(f.Result)
				resultSeen = true
				if id := resultSession(f.Result); id != "" {
					sessionID = id
				}
				if !*events {
					if *closeSession && sessionID != "" {
						return closeRemote(codec, sessionID, deadline)
					}
					return nil
				}
				if !subscribed && sessionID != "" {
					sub, _ := proto.Request(2, proto.MethodEventsSubscribe, map[string]any{"session": sessionID, "since": 0})
					sub.Session = sessionID
					if err := codec.Write(sub); err != nil {
						return err
					}
					subscribed = true
				}
				continue
			}
			if f.ID == 2 {
				continue
			}
		case proto.TypeEvent:
			if !*events {
				continue
			}
			eventCount++
			b, _ := json.Marshal(f.Event)
			fmt.Println(string(b))
			if matchUntil(f.Event, *until) {
				if *closeSession && sessionID != "" {
					return closeRemote(codec, sessionID, deadline)
				}
				return nil
			}
			if *maxEvents > 0 && eventCount >= *maxEvents {
				if *closeSession && sessionID != "" {
					return closeRemote(codec, sessionID, deadline)
				}
				return nil
			}
		}
		if !resultSeen && *events && *until == "" && *maxEvents == 0 {
			// keep waiting for the initial result
		}
	}
}

func printJSON(raw json.RawMessage) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(raw))
	}
}

func resultSession(raw json.RawMessage) string {
	var v struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.Session
}

func matchUntil(event any, spec string) bool {
	if spec == "" || event == nil {
		return false
	}
	b, _ := json.Marshal(event)
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	kind, _ := m["kind"].(string)
	wantKind, wantID, _ := strings.Cut(spec, ":")
	if kind != wantKind {
		return false
	}
	if wantID == "" {
		return true
	}
	switch kind {
	case "finding":
		if f, ok := m["finding"].(map[string]any); ok {
			return f["id"] == wantID
		}
	case "marker":
		return m["marker"] == wantID
	}
	return false
}

func closeRemote(codec *proto.Codec, session string, deadline time.Time) error {
	req, err := proto.Request(99, proto.MethodSessionClose, map[string]any{"session": session, "kill": true})
	if err != nil {
		return err
	}
	req.Session = session
	if err := codec.Write(req); err != nil {
		return err
	}
	for {
		f, err := codec.Read()
		if err != nil {
			return err
		}
		if f.ID == 99 {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timed out closing session")
		}
	}
}

func checkFindings(eng *detect.Engine, expected string, noFindings bool) error {
	findings := eng.Recent()
	if noFindings {
		if len(findings) > 0 {
			ids := make([]string, 0, len(findings))
			for _, f := range findings {
				ids = append(ids, f.ID)
			}
			return fmt.Errorf("unexpected findings: %s", strings.Join(ids, ","))
		}
		return nil
	}
	want := splitList(expected)
	if len(want) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		seen[f.ID] = true
	}
	var missing []string
	for _, id := range want {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing expected finding(s): %s", strings.Join(missing, ","))
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseRegExpectations(s string) (map[string]uint64, error) {
	out := make(map[string]uint64)
	for _, part := range splitList(s) {
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid register assertion %q (want name=value)", part)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		val = strings.TrimSpace(val)
		n, err := strconv.ParseUint(val, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid value for %s: %w", name, err)
		}
		out[name] = n
	}
	return out, nil
}

// ReadStdinLine is a small test helper.
func ReadStdinLine(r io.Reader) string {
	data, _ := io.ReadAll(r)
	return strings.TrimSpace(string(data))
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sink := fs.String("sink", "gfs_sink", "registered sink symbol")
	start := fs.String("start", "gfs_pop_rdi_ret", "first gadget/start symbol")
	chainBase := fs.Uint64("chain-base", 0, "chain buffer address")
	chainLen := fs.Int("chain-len", 64, "chain words to read")
	maxSteps := fs.Int("max-steps", 512, "maximum single-step count")
	expectRegs := fs.String("expect-regs", "", "comma-separated register assertions, e.g. rdi=0x4141")
	expectFindings := fs.String("expect-findings", "", "comma-separated detector IDs that must be present")
	expectNoFindings := fs.Bool("expect-no-findings", false, "fail if any finding is produced")
	hijack := fs.Bool("hijack", false, "watch the saved-RIP slot of --hijack-func instead of arming from --start")
	hijackFunc := fs.String("hijack-func", "gfs_vuln", "function whose saved return slot is watched")
	cfg, _, _, follow, report, stdout, stderr := configFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("missing target program")
	}
	ag := agent.New()
	s, err := ag.Start(agent.CreateParams{
		Mode: "spawn", Path: rest[0], Args: rest, Pause: true,
		Config: *cfg, Follow: *follow, Stdout: *stdout, Stderr: *stderr,
	})
	if err != nil {
		return err
	}
	defer s.Close(true)
	sinkInfo, err := s.RegisterSink(*sink)
	if err != nil {
		return fmt.Errorf("register sink: %w", err)
	}
	if *hijack {
		bp, err := s.BreakSymbol(*hijackFunc)
		if err != nil {
			return fmt.Errorf("break %s: %w", *hijackFunc, err)
		}
		if err := s.ContinueAll(); err != nil {
			return err
		}
		st, err := s.WaitStop(10*time.Second, func(st debugger.Stop) bool {
			return st.Breakpoint != nil && st.Breakpoint.Addr == bp.Addr
		})
		if err != nil {
			return fmt.Errorf("wait for %s: %w", *hijackFunc, err)
		}
		if err := s.ClearBreak(bp.Addr); err != nil {
			return err
		}
		slot := st.Regs.RSP
		base := *chainBase
		if base == 0 {
			base = slot
		}
		if _, _, err := s.WatchHijack(agent.HijackParams{
			Slot: slot, Size: 8, Type: "rw", SinkAddr: sinkInfo.Addr,
			ChainBase: base, ChainLen: *chainLen, MaxSteps: *maxSteps,
		}); err != nil {
			return fmt.Errorf("hijack watch: %w", err)
		}
		if err := s.ContinueAll(); err != nil {
			return err
		}
	} else {
		if _, err := s.ArmROP(*start, 0, *chainBase, *chainLen, *maxSteps); err != nil {
			return fmt.Errorf("arm rop: %w", err)
		}
		if err := s.ContinueAll(); err != nil {
			return err
		}
	}
	result := s.WaitROP(15 * time.Second)
	if result == nil {
		return errors.New("no ROP result (target did not reach the start/sink)")
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(b))
	if *expectRegs != "" {
		want, err := parseRegExpectations(*expectRegs)
		if err != nil {
			return err
		}
		if result.Sink == nil {
			return errors.New("register assertions requested but sink was not reached")
		}
		for name, value := range want {
			if got := result.Sink.Register(name); got != value {
				return fmt.Errorf("register %s: got 0x%x, want 0x%x", name, got, value)
			}
		}
	}
	if err := checkFindings(s.Engine(), *expectFindings, *expectNoFindings); err != nil {
		return err
	}
	if *report != "" {
		if err := s.Export(*report); err != nil {
			return err
		}
	}
	if !result.Verified {
		if result.Error != "" {
			return errors.New(result.Error)
		}
		return errors.New("ROP chain not verified")
	}
	return nil
}
