package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"gofengshui/source/core"
)

const (
	EventAlloc       = core.EventAlloc
	EventFree        = core.EventFree
	EventDoubleFree  = core.EventDoubleFree
	EventInvalidFree = core.EventInvalidFree
	EventMmap        = core.EventMmap
	EventMunmap      = core.EventMunmap
	EventBrk         = core.EventBrk
	EventMremap      = core.EventMremap
	EventMemAccess   = core.EventMemAccess
	EventSyscallRet  = core.EventSyscallRet
	EventAllocFail   = core.EventAllocFail
)

type bpfConfig struct {
	CgroupID uint64
	PID      uint32
	Flags    uint32
	Sample   uint32
	AgentPID uint32
}

type bpfEvent struct {
	Timestamp uint64
	Addr      uint64
	Size      uint64
	ReqSize   uint64
	Caller    uint64
	StackID   uint64
	Arg1      uint64
	Arg2      uint64
	Aux1      uint64
	Aux2      uint64
	Type      uint32
	PID       uint32
	TID       uint32
	Flags     uint32
	Comm      [16]byte
	Pad       uint32
}

type bpfAlloc struct {
	Addr      uint64
	ReqSize   uint64
	ChunkSize uint64
	Timestamp uint64
	StackID   uint64
	Caller    uint64
	TID       uint32
	Op        uint32
	State     uint32
	Pad       uint32
}

type bpfTomb struct {
	Addr      uint64
	Size      uint64
	Timestamp uint64
	TID       uint32
	Gen       uint32
}

// Stats is the aggregate BPF-side event/drop accounting.
type Stats struct {
	Events uint64 `json:"events"`
	Drops  uint64 `json:"drops"`
	Allocs uint64 `json:"allocs"`
	Frees  uint64 `json:"frees"`
	Checks uint64 `json:"checks"`
}

// Tracer owns the embedded eBPF object and its attached links.
type Tracer struct {
	mu sync.RWMutex

	coll        *ebpf.Collection
	links       []link.Link
	libcPath    string
	ex          *link.Executable
	attachedKey map[string]bool
	closed      bool

	events     *ebpf.Map
	allocs     *ebpf.Map
	tombstones *ebpf.Map
	stacks     *ebpf.Map
	statsMap   *ebpf.Map
	configMap  *ebpf.Map

	reader *ringbuf.Reader
	out    chan core.Event
	errs   chan error
	done   chan struct{}
	once   sync.Once

	target core.Target
	cfg    core.Config
}

// New loads the embedded eBPF object. Attach is required before events flow.
func debugf(format string, args ...any) {
	if os.Getenv("GFS_BPF_LOG") != "" {
		fmt.Fprintf(os.Stderr, "gfs-bpf: "+format+"\n", args...)
	}
}

func New(cfg core.Config, target core.Target) (*Tracer, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	opts := ebpf.CollectionOptions{}
	if os.Getenv("GFS_BPF_LOG") != "" {
		opts.Programs.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
		opts.Programs.LogSizeStart = 1 << 20
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("create bpf collection: %w", err)
	}

	t := &Tracer{
		coll:        coll,
		events:      coll.Maps["events"],
		allocs:      coll.Maps["allocs"],
		tombstones:  coll.Maps["tombstones"],
		stacks:      coll.Maps["stacks"],
		statsMap:    coll.Maps["stats"],
		configMap:   coll.Maps["config"],
		out:         make(chan core.Event, 4096),
		errs:        make(chan error, 16),
		attachedKey: make(map[string]bool),
		done:        make(chan struct{}),
		target:      target,
		cfg:         cfg,
	}
	if t.events == nil || t.allocs == nil || t.tombstones == nil ||
		t.stacks == nil || t.statsMap == nil || t.configMap == nil ||
		coll.Maps["sample_ctr"] == nil {
		coll.Close()
		return nil, errors.New("bpf object is missing required maps")
	}
	return t, nil
}

// Attach configures maps and attaches allocator uprobes and raw syscalls.
func (t *Tracer) Attach() error {
	if err := t.updateConfig(); err != nil {
		return err
	}

	debugf("target pid=%d init_pid=%d cgroup=%d flags=0x%x libc=%s",
		t.target.PID, t.target.InitPID, t.target.CgroupID, t.cfg.Flags(), t.target.LibcPath)

	if !t.cfg.NoLibc && t.target.LibcPath != "" {
		ex, err := link.OpenExecutable(t.target.LibcPath)
		if err != nil {
			debugf("open allocator: %v", err)
			select {
			case t.errs <- fmt.Errorf("open allocator: %w", err):
			default:
			}
		} else {
			t.mu.Lock()
			t.ex = ex
			t.libcPath = t.target.LibcPath
			t.mu.Unlock()
			// One uprobe link per process covers all of its threads.
			if err := t.attachThread(t.target.PID, t.libcPath); err != nil {
				debugf("attach process %d: %v", t.target.PID, err)
				select {
				case t.errs <- err:
				default:
				}
			}
		}
	}

	if t.cfg.Syscalls {
		if t.cfg.OOM {
			attached := false
			if prog := t.coll.Programs["gfs_oom_kill"]; prog != nil {
				l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
					Name: "oom_kill_process", Program: prog,
				})
				if err == nil {
					t.links = append(t.links, l)
					attached = true
				} else {
					debugf("attach oom tracepoint: %v", err)
				}
			}
			if !attached {
				if prog := t.coll.Programs["gfs_oom_kprobe"]; prog != nil {
					l, err := link.Kprobe("oom_kill_process", prog, nil)
					if err != nil {
						debugf("attach oom kprobe: %v", err)
						select {
						case t.errs <- fmt.Errorf("attach oom kprobe: %w", err):
						default:
						}
					} else {
						t.links = append(t.links, l)
					}
				}
			}
		}
		for _, name := range []string{"sys_enter", "sys_exit"} {
			prog := t.coll.Programs["gfs_"+name]
			if prog == nil {
				return fmt.Errorf("missing program gfs_%s", name)
			}
			l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name: name, Program: prog,
			})
			if err != nil {
				return fmt.Errorf("attach raw tracepoint %s: %w", name, err)
			}
			t.links = append(t.links, l)
		}
	}

	rd, err := ringbuf.NewReader(t.events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	t.reader = rd
	debugf("ringbuf reader started")
	go t.readLoop()
	return nil
}

// AttachThread attaches allocator probes for one target thread. It is used
// for threads created after the session started.
func (t *Tracer) AttachThread(tid int) error {
	return t.attachThread(tid, "")
}

// AttachThreadPath attaches allocator probes for a thread/task that may have
// exec'd into a different libc path.
func (t *Tracer) AttachThreadPath(tid int, path string) error {
	return t.attachThread(tid, path)
}

func (t *Tracer) attachThread(tid int, path string) error {
	if path == "" {
		path = t.libcPath
	}
	if path == "" {
		return nil
	}
	key := fmt.Sprintf("%d:%s", tid, path)
	t.mu.Lock()
	if t.closed || t.attachedKey[key] {
		t.mu.Unlock()
		return nil
	}
	ex := t.ex
	if path != t.libcPath || ex == nil {
		var err error
		ex, err = link.OpenExecutable(path)
		if err != nil {
			t.mu.Unlock()
			return fmt.Errorf("open allocator %s: %w", path, err)
		}
	}

	t.attachedKey[key] = true
	t.mu.Unlock()

	opts := &link.UprobeOptions{PID: tid}
	entries := []struct {
		symbol string
		prog   string
	}{
		{"malloc", "gfs_malloc_enter"},
		{"calloc", "gfs_calloc_enter"},
		{"realloc", "gfs_realloc_enter"},
		{"free", "gfs_free_enter"},
	}
	returns := []struct {
		symbol string
		prog   string
	}{
		{"malloc", "gfs_malloc_return"},
		{"calloc", "gfs_calloc_return"},
		{"realloc", "gfs_realloc_return"},
	}

	var attachErrs []error
	var newLinks []link.Link
	for _, h := range entries {
		prog := t.coll.Programs[h.prog]
		if prog == nil {
			attachErrs = append(attachErrs, fmt.Errorf("missing program %s", h.prog))
			continue
		}
		l, err := ex.Uprobe(h.symbol, prog, opts)
		if err != nil {
			attachErrs = append(attachErrs, fmt.Errorf("uprobe %s tid %d: %w", h.symbol, tid, err))
			continue
		}
		debugf("uprobe %s tid=%d -> %s", h.symbol, tid, path)
		newLinks = append(newLinks, l)
	}
	for _, h := range returns {
		prog := t.coll.Programs[h.prog]
		if prog == nil {
			attachErrs = append(attachErrs, fmt.Errorf("missing program %s", h.prog))
			continue
		}
		l, err := ex.Uretprobe(h.symbol, prog, opts)
		if err != nil {
			attachErrs = append(attachErrs, fmt.Errorf("uretprobe %s tid %d: %w", h.symbol, tid, err))
			continue
		}
		debugf("uretprobe %s tid=%d -> %s", h.symbol, tid, path)
		newLinks = append(newLinks, l)
	}
	t.mu.Lock()
	t.links = append(t.links, newLinks...)
	t.mu.Unlock()
	return errors.Join(attachErrs...)
}

// AttachCxx attaches C++ new/delete probes for one libstdc++ module. The
// inner malloc/free calls are still emitted, labelled as new/delete by the BPF
// cxx_op map. Missing symbols are reported but do not abort the session.
func (t *Tracer) AttachCxx(path string) error {
	if path == "" {
		return nil
	}
	key := "cxx:" + path
	t.mu.Lock()
	if t.closed || t.attachedKey[key] {
		t.mu.Unlock()
		return nil
	}
	t.attachedKey[key] = true
	pid := t.target.PID
	t.mu.Unlock()

	ex, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("open libstdc++ %s: %w", path, err)
	}
	opts := &link.UprobeOptions{PID: pid}
	type attach struct {
		symbol string
		prog   string
		ret    bool
	}
	links := []attach{
		{"_Znwm", "gfs_new_enter", false},
		{"_Znam", "gfs_new_enter", false},
		{"_Znwm", "gfs_new_return", true},
		{"_Znam", "gfs_new_return", true},
		{"_ZdlPv", "gfs_delete_enter", false},
		{"_ZdlPvm", "gfs_delete_enter", false},
		{"_ZdaPv", "gfs_delete_enter", false},
		{"_ZdaPvm", "gfs_delete_enter", false},
		{"_ZdlPv", "gfs_delete_return", true},
		{"_ZdlPvm", "gfs_delete_return", true},
		{"_ZdaPv", "gfs_delete_return", true},
		{"_ZdaPvm", "gfs_delete_return", true},
	}
	var errs []error
	var newLinks []link.Link
	for _, a := range links {
		prog := t.coll.Programs[a.prog]
		if prog == nil {
			errs = append(errs, fmt.Errorf("missing program %s", a.prog))
			continue
		}
		var l link.Link
		var err error
		if a.ret {
			l, err = ex.Uretprobe(a.symbol, prog, opts)
		} else {
			l, err = ex.Uprobe(a.symbol, prog, opts)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("attach %s/%s: %w", path, a.symbol, err))
			continue
		}
		debugf("cxx %s tid=%d -> %s", a.symbol, pid, path)
		newLinks = append(newLinks, l)
	}
	t.mu.Lock()
	t.links = append(t.links, newLinks...)
	t.mu.Unlock()
	return errors.Join(errs...)
}

func taskIDs(pid int) []int {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return []int{pid}
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err == nil {
			out = append(out, tid)
		}
	}
	if len(out) == 0 {
		out = append(out, pid)
	}
	return out
}

func (t *Tracer) updateConfig() error {
	pid := t.cfg.PID
	if pid == 0 {
		pid = t.target.InitPID
	}
	c := bpfConfig{
		CgroupID: t.cfg.CgroupID,
		PID:      pid,
		Flags:    t.cfg.Flags(),
		Sample:   t.cfg.SampleStacks,
		AgentPID: uint32(os.Getpid()),
	}
	key := uint32(0)
	return t.configMap.Update(key, &c, ebpf.UpdateAny)
}

func (t *Tracer) readLoop() {
	defer close(t.out)
	for {
		rec, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			select {
			case t.errs <- err:
			default:
			}
			return
		}
		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			continue
		}
		select {
		case t.out <- ev:
		case <-t.done:
			return
		}
	}
}

func decodeEvent(raw []byte) (core.Event, error) {
	var be bpfEvent
	if len(raw) < 116 {
		return core.Event{}, fmt.Errorf("short bpf event: %d", len(raw))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &be); err != nil {
		return core.Event{}, err
	}
	now := time.Now()
	return core.Event{
		Timestamp: now,
		KTime:     be.Timestamp,
		Type:      core.EventType(be.Type),
		PID:       be.PID,
		TID:       be.TID,
		Addr:      be.Addr,
		Size:      be.Size,
		ReqSize:   be.ReqSize,
		Caller:    be.Caller,
		StackID:   int32(be.StackID),
		Arg1:      be.Arg1,
		Arg2:      be.Arg2,
		Aux1:      be.Aux1,
		Aux2:      be.Aux2,
		Flags:     be.Flags,
		Comm:      cString(be.Comm[:]),
	}, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Events returns the decoded event stream.
func (t *Tracer) Events() <-chan core.Event { return t.out }

// Errors returns non-fatal tracer errors.
func (t *Tracer) Errors() <-chan error { return t.errs }

// Stack returns the user stack associated with a stack ID.
func (t *Tracer) Stack(id int32) ([]uint64, error) {
	if id < 0 {
		return nil, nil
	}
	var out [32]uint64
	k := uint32(id)
	if err := t.stacks.Lookup(k, &out); err != nil {
		return nil, err
	}
	ret := make([]uint64, 0, len(out))
	for _, v := range out {
		if v == 0 {
			continue
		}
		ret = append(ret, v)
	}
	return ret, nil
}

// HeapSnapshot returns the current BPF-side allocation map.
func (t *Tracer) HeapSnapshot() ([]core.Allocation, error) {
	iter := t.allocs.Iterate()
	var key uint64
	var val bpfAlloc
	var out []core.Allocation
	for iter.Next(&key, &val) {
		a := core.Allocation{
			Addr: val.Addr, ReqSize: val.ReqSize, ChunkSize: val.ChunkSize,
			TID: val.TID, StackID: int32(val.StackID), AllocTS: int64(val.Timestamp),
			Allocator: "glibc",
		}
		if val.State == 1 {
			a.State = core.StateLive
		}
		out = append(out, a)
	}
	return out, iter.Err()
}

// BPFStats returns aggregate ringbuf/map counters.
func (t *Tracer) BPFStats() (Stats, error) {
	var values []Stats
	if err := t.statsMap.Lookup(uint32(0), &values); err != nil {
		return Stats{}, err
	}
	var total Stats
	for _, v := range values {
		total.Events += v.Events
		total.Drops += v.Drops
		total.Allocs += v.Allocs
		total.Frees += v.Frees
		total.Checks += v.Checks
	}
	return total, nil
}

// Close detaches all links and releases BPF resources.
func (t *Tracer) Close() error {
	var errs []error
	t.once.Do(func() {
		t.mu.Lock()
		t.closed = true
		links := append([]link.Link(nil), t.links...)
		t.mu.Unlock()
		close(t.done)
		if t.reader != nil {
			errs = append(errs, t.reader.Close())
		}
		for _, l := range links {
			errs = append(errs, l.Close())
		}
		if t.coll != nil {
			t.coll.Close()
		}
	})
	return errors.Join(errs...)
}

// Config returns the active tracer configuration.
func (t *Tracer) Config() core.Config {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cfg
}
