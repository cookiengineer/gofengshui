package debugger

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"gofengshui/source/core"
)

const (
	userDebugreg0 = 848
	dr6Offset     = 896
	dr7Offset     = 904
)

var (
	localEnable = [4]uint64{1 << 0, 1 << 2, 1 << 4, 1 << 6}
	rwShift     = [4]uint{16, 20, 24, 28}
	lenShift    = [4]uint{18, 22, 26, 30}
)

// WatchType controls the hardware breakpoint access type.
type WatchType string

const (
	WatchWrite   WatchType = "write"
	WatchRead    WatchType = "read"
	WatchAccess  WatchType = "rw"
	WatchExecute WatchType = "execute"
)

type hwSlot struct {
	Kind string
	ID   uint64
	Addr uint64
	Size uint64
	Type WatchType
}

// Breakpoint is an executable breakpoint.
type Breakpoint struct {
	ID       uint64 `json:"id"`
	Addr     uint64 `json:"addr"`
	Symbol   string `json:"symbol,omitempty"`
	Hardware bool   `json:"hardware"`
	Slot     int    `json:"slot,omitempty"`
	original []byte
}

// Watchpoint is a hardware data/execute watchpoint.
type Watchpoint struct {
	ID      uint64    `json:"id"`
	Addr    uint64    `json:"addr"`
	Size    uint64    `json:"size"`
	Type    WatchType `json:"type"`
	Slot    int       `json:"slot"`
	AllocID uint64    `json:"alloc_id,omitempty"`
}

// Stop is one ptrace stop delivered to the session event stream.
type Stop struct {
	TID        int            `json:"tid"`
	PID        int            `json:"pid"`
	Reason     string         `json:"reason"`
	Signal     int            `json:"signal,omitempty"`
	Event      int            `json:"event,omitempty"`
	Address    uint64         `json:"address,omitempty"`
	Regs       core.Registers `json:"regs,omitempty"`
	Breakpoint *Breakpoint    `json:"breakpoint,omitempty"`
	Watchpoint *Watchpoint    `json:"watchpoint,omitempty"`
	ExitCode   int            `json:"exit_code,omitempty"`
	Timestamp  time.Time      `json:"ts"`
}

type threadState struct {
	tid          int
	stopped      bool
	options      bool
	pendingSW    *Breakpoint
	stepReinsert bool
	stepping     bool
}

type command struct {
	fn   func() error
	done chan error
}

// Tracer is a ptrace-based controller for one target process. All ptrace
// calls run on one locked OS thread.
type Tracer struct {
	mu sync.Mutex

	cmd            *exec.Cmd
	pid            int
	attached       bool
	follow         bool
	deliverSignals bool

	tids        map[int]*threadState
	breakpoints map[uint64]*Breakpoint
	watchpoints map[uint64]*Watchpoint
	hw          [4]*hwSlot
	nextID      uint64
	threadHooks []func(int)

	stops chan Stop
	errs  chan error
	done  chan struct{}
	ready chan error
	cmds  chan command

	once   sync.Once
	exited bool
}

// LaunchOptions configures a spawned target.
type LaunchOptions struct {
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stdout io.Writer
	Stderr io.Writer
	Follow bool
}

func newTracer(follow bool) *Tracer {
	return &Tracer{
		follow:         follow,
		deliverSignals: true,
		tids:           make(map[int]*threadState),
		breakpoints:    make(map[uint64]*Breakpoint),
		watchpoints:    make(map[uint64]*Watchpoint),
		stops:          make(chan Stop, 256),
		errs:           make(chan error, 16),
		done:           make(chan struct{}),
		ready:          make(chan error, 1),
		cmds:           make(chan command),
	}
}

// Launch starts a child under ptrace on the dedicated tracer thread.
func Launch(opts LaunchOptions) (*Tracer, error) {
	if opts.Path == "" {
		return nil, errors.New("launch path is empty")
	}
	t := newTracer(opts.Follow)
	go t.runLaunch(opts)
	if err := <-t.ready; err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tracer) runLaunch(opts LaunchOptions) {
	runtime.LockOSThread()
	args := opts.Args
	if len(args) == 0 {
		args = []string{opts.Path}
	}
	cmd := exec.Command(opts.Path, args[1:]...)
	cmd.Env = opts.Env
	cmd.Dir = opts.Dir
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.ready <- fmt.Errorf("start target: %w", err)
		return
	}
	t.mu.Lock()
	t.cmd = cmd
	t.pid = cmd.Process.Pid
	t.tids[t.pid] = &threadState{tid: t.pid}
	t.mu.Unlock()
	t.ready <- nil
	t.loop()
}

// Attach seizes an existing process and interrupts it.
func Attach(pid int, follow bool) (*Tracer, error) {
	t := newTracer(follow)
	go t.runAttach(pid)
	if err := <-t.ready; err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tracer) runAttach(pid int) {
	runtime.LockOSThread()
	tids := listTasks(pid)
	if len(tids) == 0 {
		tids = []int{pid}
	}
	var seized []int
	for _, tid := range tids {
		if err := unix.PtraceSeize(tid); err != nil {
			if tid == pid {
				for _, id := range seized {
					_ = unix.PtraceDetach(id)
				}
				t.ready <- fmt.Errorf("ptrace seize %d: %w", pid, err)
				return
			}
			continue
		}
		seized = append(seized, tid)
		_ = unix.PtraceSetOptions(tid, ptraceOptions(t.follow))
		if err := unix.PtraceInterrupt(tid); err != nil && tid == pid {
			for _, id := range seized {
				_ = unix.PtraceDetach(id)
			}
			t.ready <- fmt.Errorf("ptrace interrupt %d: %w", pid, err)
			return
		}
		t.mu.Lock()
		t.tids[tid] = &threadState{tid: tid}
		t.mu.Unlock()
	}
	t.mu.Lock()
	t.pid = pid
	t.attached = true
	t.mu.Unlock()
	t.ready <- nil
	t.loop()
}

func listTasks(pid int) []int {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err == nil {
			out = append(out, tid)
		}
	}
	return out
}

// PID returns the initial process ID.
func (t *Tracer) PID() int { return t.pid }

// Stops returns the ptrace stop stream.
func (t *Tracer) Stops() <-chan Stop { return t.stops }

// Errors returns non-fatal tracer errors.
func (t *Tracer) Errors() <-chan error { return t.errs }

// NextStop waits for the next ptrace stop.
func (t *Tracer) NextStop(timeout time.Duration) (Stop, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	select {
	case s, ok := <-t.stops:
		if !ok {
			return Stop{}, errors.New("tracer stopped")
		}
		return s, nil
	case <-time.After(timeout):
		return Stop{}, errors.New("timed out waiting for ptrace stop")
	case <-t.done:
		return Stop{}, errors.New("tracer closed")
	}
}

func (t *Tracer) do(fn func() error) error {
	c := command{fn: fn, done: make(chan error, 1)}
	select {
	case t.cmds <- c:
		return <-c.done
	case <-t.done:
		return errors.New("tracer closed")
	}
}

func (t *Tracer) loop() {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case c := <-t.cmds:
			c.done <- c.fn()
		case <-ticker.C:
			t.poll()
		}
	}
}

func (t *Tracer) poll() {
	t.mu.Lock()
	tids := make([]int, 0, len(t.tids))
	for id := range t.tids {
		tids = append(tids, id)
	}
	t.mu.Unlock()
	for _, tid := range tids {
		for {
			var ws unix.WaitStatus
			wpid, err := unix.Wait4(tid, &ws, unix.WNOHANG|unix.WALL, nil)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if errors.Is(err, unix.ECHILD) {
					break
				}
				select {
				case t.errs <- err:
				default:
				}
				break
			}
			if wpid <= 0 {
				break
			}
			if ws.Exited() {
				t.handleExit(wpid, ws.ExitStatus())
				continue
			}
			if ws.Signaled() {
				t.handleExit(wpid, -int(ws.Signal()))
				continue
			}
			if ws.Stopped() {
				t.handleStop(wpid, ws)
			}
		}
	}
}

func (t *Tracer) handleExit(tid, code int) {
	t.mu.Lock()
	delete(t.tids, tid)
	if tid == t.pid {
		t.exited = true
	}
	t.mu.Unlock()
	select {
	case t.stops <- Stop{TID: tid, PID: t.pid, Reason: "exit", ExitCode: code, Timestamp: time.Now()}:
	case <-t.done:
	}
}

func (t *Tracer) handleStop(tid int, ws unix.WaitStatus) {
	t.ensureOptions(tid)
	sig := int(ws.StopSignal())
	event := int(ws.TrapCause())
	if os.Getenv("GFS_PTRACE_LOG") != "" {
		fmt.Fprintf(os.Stderr, "gfs: stop tid=%d sig=%d event=%d\n", tid, sig, event)
	}

	if sig == int(unix.SIGTRAP) && event != 0 {
		switch event {
		case int(unix.PTRACE_EVENT_CLONE), int(unix.PTRACE_EVENT_FORK), int(unix.PTRACE_EVENT_VFORK):
			msg, err := unix.PtraceGetEventMsg(tid)
			if os.Getenv("GFS_PTRACE_LOG") != "" {
				fmt.Fprintf(os.Stderr, "gfs: clone event tid=%d new=%d err=%v\n", tid, msg, err)
			}
			if err == nil {
				newTid := int(msg)
				t.mu.Lock()
				t.tids[newTid] = &threadState{tid: newTid, options: true}
				t.mu.Unlock()
				_ = unix.PtraceSetOptions(newTid, ptraceOptions(t.follow))
				t.applyHardware(newTid)
				t.runThreadHooks(newTid)
				// A clone event leaves the new task in a ptrace stop. It must
				// be continued explicitly or the parent blocks forever.
				err := unix.PtraceCont(newTid, 0)
				if os.Getenv("GFS_PTRACE_LOG") != "" {
					fmt.Fprintf(os.Stderr, "gfs: continue new tid=%d err=%v\n", newTid, err)
				}
			}
		case int(unix.PTRACE_EVENT_EXEC):
			t.applyHardware(tid)
			t.mu.Lock()
			if ts := t.tids[tid]; ts != nil {
				ts.stopped = true
			}
			t.mu.Unlock()
			regs, _ := t.registersLocked(tid)
			t.emit(Stop{TID: tid, PID: t.pid, Reason: "exec", Regs: regs, Timestamp: time.Now()})
			return
		case int(unix.PTRACE_EVENT_STOP):
			regs, _ := t.registersLocked(tid)
			t.mu.Lock()
			if ts := t.tids[tid]; ts != nil {
				ts.stopped = true
			}
			t.mu.Unlock()
			t.emit(Stop{TID: tid, PID: t.pid, Reason: "stopped", Regs: regs, Timestamp: time.Now()})
			return
		}
		_ = unix.PtraceCont(tid, 0)
		return
	}

	if sig == int(unix.SIGTRAP) {
		if bp, w := t.classifyTrap(tid); bp != nil || w != nil {
			regs, _ := t.registersLocked(tid)
			st := Stop{
				TID: tid, PID: t.pid, Reason: "breakpoint", Regs: regs,
				Breakpoint: bp, Watchpoint: w, Timestamp: time.Now(),
			}
			if bp != nil {
				st.Address = bp.Addr
			}
			if w != nil {
				st.Address = w.Addr
			}
			t.mu.Lock()
			if ts := t.tids[tid]; ts != nil {
				ts.stopped = true
			}
			t.mu.Unlock()
			t.emit(st)
			return
		}
		regs, _ := t.registersLocked(tid)
		t.mu.Lock()
		reason := "stopped"
		if ts := t.tids[tid]; ts != nil {
			if ts.stepping {
				reason = "single_step"
				ts.stepping = false
			}
			ts.stopped = true
		}
		t.mu.Unlock()
		t.emit(Stop{TID: tid, PID: t.pid, Reason: reason, Regs: regs, Timestamp: time.Now()})
		return
	}

	if sig == int(unix.SIGSTOP) || sig == int(unix.SIGTSTP) ||
		sig == int(unix.SIGTTIN) || sig == int(unix.SIGTTOU) {
		t.mu.Lock()
		if ts := t.tids[tid]; ts != nil {
			ts.stopped = true
		}
		t.mu.Unlock()
		regs, _ := t.registersLocked(tid)
		t.emit(Stop{TID: tid, PID: t.pid, Reason: "stopped", Signal: sig, Regs: regs, Timestamp: time.Now()})
		return
	}

	t.mu.Lock()
	if ts := t.tids[tid]; ts != nil {
		ts.stopped = true
	}
	t.mu.Unlock()
	regs, _ := t.registersLocked(tid)
	t.emit(Stop{TID: tid, PID: t.pid, Reason: "signal", Signal: sig, Regs: regs, Timestamp: time.Now()})
	if t.deliverSignals {
		t.mu.Lock()
		if ts := t.tids[tid]; ts != nil {
			ts.stopped = false
		}
		t.mu.Unlock()
		err := unix.PtraceCont(tid, sig)
		if os.Getenv("GFS_PTRACE_LOG") != "" {
			fmt.Fprintf(os.Stderr, "gfs: deliver signal %d to tid %d: %v\n", sig, tid, err)
		}
	}
}

func (t *Tracer) ensureOptions(tid int) {
	t.mu.Lock()
	ts := t.tids[tid]
	if ts != nil && ts.options {
		t.mu.Unlock()
		return
	}
	if ts != nil {
		ts.options = true
	}
	t.mu.Unlock()
	_ = unix.PtraceSetOptions(tid, ptraceOptions(t.follow))
}

func ptraceOptions(follow bool) int {
	// Clone tracing is always enabled so new threads are instrumented.
	opts := unix.PTRACE_O_EXITKILL | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_TRACECLONE
	if follow {
		opts |= unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK
	}
	return opts
}

func (t *Tracer) emit(s Stop) {
	select {
	case t.stops <- s:
	case <-t.done:
	}
}

func (t *Tracer) classifyTrap(tid int) (*Breakpoint, *Watchpoint) {
	dr6, _ := peekUser(tid, dr6Offset)
	t.mu.Lock()
	defer t.mu.Unlock()

	if ts := t.tids[tid]; ts != nil && ts.stepReinsert && ts.pendingSW != nil {
		bp := ts.pendingSW
		_, _ = unix.PtracePokeText(tid, uintptr(bp.Addr), []byte{0xcc})
		ts.pendingSW = nil
		ts.stepReinsert = false
		_ = unix.PtraceCont(tid, 0)
		return nil, nil
	}

	if dr6 != 0 {
		_ = pokeUser(tid, dr6Offset, 0)
		for i := 0; i < 4; i++ {
			if dr6&(1<<uint(i)) == 0 {
				continue
			}
			hs := t.hw[i]
			if hs == nil {
				continue
			}
			if hs.Kind == "breakpoint" {
				return t.breakpoints[hs.Addr], nil
			}
			return nil, t.watchpoints[hs.ID]
		}
	}

	regs, err := t.registersLocked(tid)
	if err != nil {
		return nil, nil
	}
	if bp := t.breakpoints[regs.RIP-1]; bp != nil && !bp.Hardware {
		_, _ = unix.PtracePokeText(tid, uintptr(bp.Addr), bp.original)
		regs.RIP--
		_ = t.setRegistersLocked(tid, regs)
		if ts := t.tids[tid]; ts != nil {
			ts.pendingSW = bp
		}
		return bp, nil
	}
	if bp := t.breakpoints[regs.RIP]; bp != nil && bp.Hardware {
		return bp, nil
	}
	return nil, nil
}

// AllStopped reports whether every known thread is in a ptrace stop.
func (t *Tracer) AllStopped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.tids) == 0 {
		return false
	}
	for _, ts := range t.tids {
		if ts == nil || !ts.stopped {
			return false
		}
	}
	return true
}

// Continue resumes one thread or all threads if tid is zero.
func (t *Tracer) Continue(tid int) error {
	return t.do(func() error {
		t.mu.Lock()
		if tid != 0 {
			if ts := t.tids[tid]; ts != nil && ts.pendingSW != nil {
				ts.stepReinsert = true
				ts.stepping = false
				t.mu.Unlock()
				return unix.PtraceSingleStep(tid)
			}
		}
		if tid == 0 {
			tids := make([]int, 0, len(t.tids))
			for id := range t.tids {
				ts := t.tids[id]
				if ts != nil {
					ts.stopped = false
				}
				tids = append(tids, id)
			}
			t.mu.Unlock()
			var errs []error
			for _, id := range tids {
				if err := unix.PtraceCont(id, 0); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		}
		if ts := t.tids[tid]; ts != nil {
			ts.stopped = false
		}
		t.mu.Unlock()
		return unix.PtraceCont(tid, 0)
	})
}

// AddThreadHook registers a callback invoked for each newly cloned thread
// while that thread is still stopped at the clone event.
func (t *Tracer) AddThreadHook(fn func(int)) {
	if fn == nil {
		return
	}
	t.mu.Lock()
	t.threadHooks = append(t.threadHooks, fn)
	t.mu.Unlock()
}

func (t *Tracer) runThreadHooks(tid int) {
	t.mu.Lock()
	hooks := append([]func(int){}, t.threadHooks...)
	t.mu.Unlock()
	for _, fn := range hooks {
		fn(tid)
	}
}

// Pause stops all known threads. Seized tracees use PTRACE_INTERRUPT;
// TRACEME-spawned tracees use a process-wide SIGSTOP group stop.
func (t *Tracer) Pause() error {
	return t.do(func() error {
		if t.AllStopped() {
			return nil
		}
		t.mu.Lock()
		attached := t.attached
		pid := t.pid
		tids := make([]int, 0, len(t.tids))
		for id := range t.tids {
			tids = append(tids, id)
		}
		t.mu.Unlock()
		if !attached {
			var errs []error
			for _, id := range tids {
				if err := unix.Tgkill(pid, id, unix.SIGSTOP); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		}
		var errs []error
		for _, id := range tids {
			if err := unix.PtraceInterrupt(id); err != nil && !errors.Is(err, unix.EIO) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
}

// PauseOthers interrupts every known thread except keep.
func (t *Tracer) PauseOthers(keep int) error {
	return t.do(func() error {
		t.mu.Lock()
		attached := t.attached
		pid := t.pid
		tids := make([]int, 0, len(t.tids))
		for id := range t.tids {
			if id != keep {
				tids = append(tids, id)
			}
		}
		t.mu.Unlock()
		if os.Getenv("GFS_PTRACE_LOG") != "" {
			fmt.Fprintf(os.Stderr, "gfs: PauseOthers keep=%d tids=%v attached=%v\n", keep, tids, attached)
		}
		var errs []error
		for _, id := range tids {
			var err error
			if attached {
				err = unix.PtraceInterrupt(id)
				if errors.Is(err, unix.EIO) {
					err = nil
				}
			} else {
				err = unix.Tgkill(pid, id, unix.SIGSTOP)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
}

// WaitStoppedExcept waits until every thread except keep is stopped.
func (t *Tracer) WaitStoppedExcept(keep int, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if t.AllStoppedExcept(keep) {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// AllStoppedExcept reports whether every known thread except keep is stopped.
func (t *Tracer) AllStoppedExcept(keep int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	found := false
	for id, ts := range t.tids {
		if id == keep {
			continue
		}
		found = true
		if ts == nil || !ts.stopped {
			return false
		}
	}
	return found
}

// ContinueOthers resumes every known thread except keep.
func (t *Tracer) ContinueOthers(keep int) error {
	return t.do(func() error {
		t.mu.Lock()
		tids := make([]int, 0, len(t.tids))
		for id := range t.tids {
			if id != keep {
				tids = append(tids, id)
			}
		}
		t.mu.Unlock()
		var errs []error
		for _, id := range tids {
			if err := unix.PtraceCont(id, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
}

// SingleStep single-steps one thread.
func (t *Tracer) SingleStep(tid int) error {
	if tid == 0 {
		tid = t.pid
	}
	return t.do(func() error {
		t.mu.Lock()
		if ts := t.tids[tid]; ts != nil {
			ts.stepping = true
			ts.stopped = false
		}
		t.mu.Unlock()
		return unix.PtraceSingleStep(tid)
	})
}

// WaitStopped waits until every known thread is in a ptrace stop.
func (t *Tracer) WaitStopped(timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		t.mu.Lock()
		all := len(t.tids) > 0
		for _, ts := range t.tids {
			if ts != nil && !ts.stopped {
				all = false
				break
			}
		}
		t.mu.Unlock()
		if all {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// Threads returns known thread IDs.
func (t *Tracer) Threads() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]int, 0, len(t.tids))
	for id := range t.tids {
		out = append(out, id)
	}
	return out
}

func (t *Tracer) registersLocked(tid int) (core.Registers, error) {
	var r unix.PtraceRegs
	if err := unix.PtraceGetRegs(tid, &r); err != nil {
		return core.Registers{}, err
	}
	return core.Registers{
		R15: r.R15, R14: r.R14, R13: r.R13, R12: r.R12,
		RBP: r.Rbp, RBX: r.Rbx, R11: r.R11, R10: r.R10,
		R9: r.R9, R8: r.R8, RAX: r.Rax, RCX: r.Rcx,
		RDX: r.Rdx, RSI: r.Rsi, RDI: r.Rdi, OrigRAX: r.Orig_rax,
		RIP: r.Rip, CS: r.Cs, EFLAGS: r.Eflags, RSP: r.Rsp, SS: r.Ss,
		FSBase: r.Fs_base, GSBase: r.Gs_base, DS: r.Ds, ES: r.Es, FS: r.Fs, GS: r.Gs,
	}, nil
}

func (t *Tracer) setRegistersLocked(tid int, regs core.Registers) error {
	r := unix.PtraceRegs{
		R15: regs.R15, R14: regs.R14, R13: regs.R13, R12: regs.R12,
		Rbp: regs.RBP, Rbx: regs.RBX, R11: regs.R11, R10: regs.R10,
		R9: regs.R9, R8: regs.R8, Rax: regs.RAX, Rcx: regs.RCX,
		Rdx: regs.RDX, Rsi: regs.RSI, Rdi: regs.RDI, Orig_rax: regs.OrigRAX,
		Rip: regs.RIP, Cs: regs.CS, Eflags: regs.EFLAGS, Rsp: regs.RSP, Ss: regs.SS,
		Fs_base: regs.FSBase, Gs_base: regs.GSBase, Ds: regs.DS, Es: regs.ES, Fs: regs.FS, Gs: regs.GS,
	}
	return unix.PtraceSetRegs(tid, &r)
}

// GetRegisters returns registers for a stopped thread.
func (t *Tracer) GetRegisters(tid int) (core.Registers, error) {
	if tid == 0 {
		tid = t.pid
	}
	var regs core.Registers
	err := t.do(func() error {
		var e error
		regs, e = t.registersLocked(tid)
		return e
	})
	return regs, err
}

// SetRegisters writes register state to a stopped thread.
func (t *Tracer) SetRegisters(tid int, regs core.Registers) error {
	if tid == 0 {
		tid = t.pid
	}
	return t.do(func() error { return t.setRegistersLocked(tid, regs) })
}

// ReadMemory reads target memory.
func (t *Tracer) ReadMemory(addr uint64, size int) ([]byte, error) {
	if size < 0 {
		return nil, errors.New("negative read size")
	}
	buf := make([]byte, size)
	err := t.do(func() error {
		n, err := unix.PtracePeekData(t.pid, uintptr(addr), buf)
		if err != nil {
			return err
		}
		if n != size {
			return fmt.Errorf("short read: %d/%d", n, size)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteMemory writes target memory.
func (t *Tracer) WriteMemory(addr uint64, data []byte) error {
	return t.do(func() error {
		n, err := unix.PtracePokeData(t.pid, uintptr(addr), data)
		if err != nil {
			return err
		}
		if n != len(data) {
			return fmt.Errorf("short write: %d/%d", n, len(data))
		}
		return nil
	})
}

// SetBreakpoint installs a hardware or software execution breakpoint.
func (t *Tracer) SetBreakpoint(addr uint64, symbol string, hardware bool) (*Breakpoint, error) {
	var bp *Breakpoint
	err := t.do(func() error {
		t.mu.Lock()
		defer t.mu.Unlock()
		if existing := t.breakpoints[addr]; existing != nil {
			bp = existing
			return nil
		}
		t.nextID++
		b := &Breakpoint{ID: t.nextID, Addr: addr, Symbol: symbol, Hardware: hardware}
		if hardware {
			slot := t.freeSlot()
			if slot < 0 {
				return errors.New("no hardware breakpoint slots available")
			}
			b.Slot = slot
			t.hw[slot] = &hwSlot{Kind: "breakpoint", ID: b.ID, Addr: addr, Type: WatchExecute, Size: 1}
			t.breakpoints[addr] = b
			for tid := range t.tids {
				if err := t.applySlot(tid, slot); err != nil {
					delete(t.breakpoints, addr)
					t.hw[slot] = nil
					return err
				}
			}
			bp = b
			return nil
		}
		buf := make([]byte, 1)
		if _, err := unix.PtracePeekData(t.pid, uintptr(addr), buf); err != nil {
			return err
		}
		b.original = []byte{buf[0]}
		if _, err := unix.PtracePokeText(t.pid, uintptr(addr), []byte{0xcc}); err != nil {
			return err
		}
		t.breakpoints[addr] = b
		bp = b
		return nil
	})
	return bp, err
}

// ClearBreakpoint removes a breakpoint.
func (t *Tracer) ClearBreakpoint(addr uint64) error {
	return t.do(func() error {
		t.mu.Lock()
		defer t.mu.Unlock()
		bp := t.breakpoints[addr]
		if bp == nil {
			return nil
		}
		if bp.Hardware {
			t.hw[bp.Slot] = nil
			for tid := range t.tids {
				_ = t.clearSlot(tid, bp.Slot)
			}
		} else if bp.original != nil {
			_, _ = unix.PtracePokeText(t.pid, uintptr(addr), bp.original)
		}
		delete(t.breakpoints, addr)
		return nil
	})
}

// SetWatchpoint installs a hardware data watchpoint.
func (t *Tracer) SetWatchpoint(addr, size uint64, typ WatchType, allocID uint64) (*Watchpoint, error) {
	if size == 0 {
		size = 1
	}
	if size != 1 && size != 2 && size != 4 && size != 8 {
		return nil, fmt.Errorf("unsupported watchpoint size %d", size)
	}
	if addr%size != 0 {
		return nil, fmt.Errorf("watchpoint address 0x%x is not %d-byte aligned", addr, size)
	}
	var wp *Watchpoint
	err := t.do(func() error {
		t.mu.Lock()
		defer t.mu.Unlock()
		slot := t.freeSlot()
		if slot < 0 {
			return errors.New("no hardware watchpoint slots available")
		}
		t.nextID++
		w := &Watchpoint{ID: t.nextID, Addr: addr, Size: size, Type: typ, Slot: slot, AllocID: allocID}
		t.hw[slot] = &hwSlot{Kind: "watchpoint", ID: w.ID, Addr: addr, Size: size, Type: typ}
		t.watchpoints[w.ID] = w
		for tid := range t.tids {
			if err := t.applySlot(tid, slot); err != nil {
				delete(t.watchpoints, w.ID)
				t.hw[slot] = nil
				for id := range t.tids {
					_ = t.clearSlot(id, slot)
				}
				return err
			}
		}
		wp = w
		return nil
	})
	return wp, err
}

// ClearWatchpoint removes a watchpoint.
func (t *Tracer) ClearWatchpoint(id uint64) error {
	return t.do(func() error {
		t.mu.Lock()
		defer t.mu.Unlock()
		wp := t.watchpoints[id]
		if wp == nil {
			return nil
		}
		t.hw[wp.Slot] = nil
		for tid := range t.tids {
			_ = t.clearSlot(tid, wp.Slot)
		}
		delete(t.watchpoints, id)
		return nil
	})
}

func (t *Tracer) freeSlot() int {
	for i, s := range t.hw {
		if s == nil {
			return i
		}
	}
	return -1
}

func (t *Tracer) applyHardware(tid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for slot := range t.hw {
		if t.hw[slot] != nil {
			_ = t.applySlot(tid, slot)
		}
	}
}

func (t *Tracer) applySlot(tid, slot int) error {
	hs := t.hw[slot]
	if hs == nil {
		return nil
	}
	if err := pokeUser(tid, userDebugreg0+uintptr(slot*8), hs.Addr); err != nil {
		return err
	}
	dr7, err := peekUser(tid, dr7Offset)
	if err != nil {
		return err
	}
	rw := uint64(0)
	switch hs.Type {
	case WatchWrite:
		rw = 1
	case WatchAccess, WatchRead:
		rw = 3
	case WatchExecute:
		rw = 0
	}
	length := uint64(0)
	switch hs.Size {
	case 1:
		length = 0
	case 2:
		length = 1
	case 8:
		length = 2
	case 4:
		length = 3
	}
	dr7 &^= (0x3 << rwShift[slot]) | (0x3 << lenShift[slot])
	dr7 |= rw << rwShift[slot]
	dr7 |= length << lenShift[slot]
	dr7 |= localEnable[slot]
	if err := pokeUser(tid, dr7Offset, dr7); err != nil {
		return err
	}
	return pokeUser(tid, dr6Offset, 0)
}

func (t *Tracer) clearSlot(tid, slot int) error {
	dr7, err := peekUser(tid, dr7Offset)
	if err != nil {
		return err
	}
	dr7 &^= localEnable[slot]
	if err := pokeUser(tid, dr7Offset, dr7); err != nil {
		return err
	}
	return pokeUser(tid, userDebugreg0+uintptr(slot*8), 0)
}

func peekUser(tid int, offset uintptr) (uint64, error) {
	buf := make([]byte, 8)
	if _, err := unix.PtracePeekUser(tid, offset, buf); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}

func pokeUser(tid int, offset uintptr, value uint64) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	_, err := unix.PtracePokeUser(tid, offset, buf)
	return err
}

// Close kills or detaches the target and stops the tracer loop.
func (t *Tracer) Close(kill bool) error {
	var err error
	if kill {
		err = t.Kill()
	} else {
		err = t.Detach()
	}
	t.once.Do(func() { close(t.done) })
	return err
}

// Detach detaches from the target.
func (t *Tracer) Detach() error {
	var errs []error
	_ = t.do(func() error {
		t.mu.Lock()
		tids := make([]int, 0, len(t.tids))
		for id := range t.tids {
			tids = append(tids, id)
		}
		t.mu.Unlock()
		for _, id := range tids {
			if err := unix.PtraceDetach(id); err != nil && !errors.Is(err, unix.ESRCH) {
				errs = append(errs, err)
			}
		}
		return nil
	})
	t.once.Do(func() { close(t.done) })
	return errors.Join(errs...)
}

// Kill terminates the target process.
func (t *Tracer) Kill() error {
	t.mu.Lock()
	cmd := t.cmd
	pid := t.pid
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Kill()
	}
	return unix.Kill(pid, unix.SIGKILL)
}

// WaitExit waits until the root process has exited or the timeout expires.
func (t *Tracer) WaitExit(timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		t.mu.Lock()
		exited := t.exited
		t.mu.Unlock()
		if exited {
			return true
		}
		select {
		case <-t.done:
			return true
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}
