package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
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
	Pad      uint32
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

type bpfStats struct {
	Events uint64
	Drops  uint64
	Allocs uint64
	Frees  uint64
	Checks uint64
}

// Tracer owns the embedded eBPF object and its attached links.
type Tracer struct {
	mu sync.RWMutex

	coll  *ebpf.Collection
	links []link.Link

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
		coll:       coll,
		events:     coll.Maps["events"],
		allocs:     coll.Maps["allocs"],
		tombstones: coll.Maps["tombstones"],
		stacks:     coll.Maps["stacks"],
		statsMap:   coll.Maps["stats"],
		configMap:  coll.Maps["config"],
		out:        make(chan core.Event, 4096),
		errs:       make(chan error, 16),
		done:       make(chan struct{}),
		target:     target,
		cfg:        cfg,
	}
	if t.events == nil || t.allocs == nil || t.tombstones == nil ||
		t.stacks == nil || t.statsMap == nil || t.configMap == nil {
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
		if err := t.attachAllocator(t.target.LibcPath); err != nil {
			debugf("allocator attach: %v", err)
			t.errs <- err
		}
	}

	if t.cfg.Syscalls {
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

func (t *Tracer) attachAllocator(path string) error {
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("open allocator ELF %s: %w", path, err)
	}
	opts := &link.UprobeOptions{PID: t.target.PID}
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
	for _, h := range entries {
		prog := t.coll.Programs[h.prog]
		if prog == nil {
			attachErrs = append(attachErrs, fmt.Errorf("missing program %s", h.prog))
			continue
		}
		l, err := ex.Uprobe(h.symbol, prog, opts)
		if err != nil {
			attachErrs = append(attachErrs, fmt.Errorf("uprobe %s: %w", h.symbol, err))
			continue
		}
		debugf("uprobe %s -> %s", h.symbol, path)
		t.links = append(t.links, l)
	}
	for _, h := range returns {
		prog := t.coll.Programs[h.prog]
		if prog == nil {
			attachErrs = append(attachErrs, fmt.Errorf("missing program %s", h.prog))
			continue
		}
		l, err := ex.Uretprobe(h.symbol, prog, opts)
		if err != nil {
			attachErrs = append(attachErrs, fmt.Errorf("uretprobe %s: %w", h.symbol, err))
			continue
		}
		debugf("uretprobe %s -> %s", h.symbol, path)
		t.links = append(t.links, l)
	}
	return errors.Join(attachErrs...)
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
	if len(raw) < 100 {
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
func (t *Tracer) BPFStats() (bpfStats, error) {
	var values []bpfStats
	if err := t.statsMap.Lookup(uint32(0), &values); err != nil {
		return bpfStats{}, err
	}
	var total bpfStats
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
		close(t.done)
		if t.reader != nil {
			errs = append(errs, t.reader.Close())
		}
		for _, l := range t.links {
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
