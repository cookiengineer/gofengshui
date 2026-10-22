package core

import (
	"fmt"
	"time"
)

// EventType mirrors enum gfs_event_type in bpf/gofengshui.h.
type EventType uint32

const (
	EventAlloc       EventType = 1
	EventFree        EventType = 2
	EventDoubleFree  EventType = 3
	EventInvalidFree EventType = 4
	EventMmap        EventType = 5
	EventMunmap      EventType = 6
	EventBrk         EventType = 7
	EventMremap      EventType = 8
	EventMemAccess   EventType = 9
	EventSyscallRet  EventType = 10
	EventAllocFail   EventType = 11
	EventStat        EventType = 12
	EventCrash       EventType = 100
)

func (t EventType) String() string {
	switch t {
	case EventAlloc:
		return "alloc"
	case EventFree:
		return "free"
	case EventDoubleFree:
		return "double_free"
	case EventInvalidFree:
		return "invalid_free"
	case EventMmap:
		return "mmap"
	case EventMunmap:
		return "munmap"
	case EventBrk:
		return "brk"
	case EventMremap:
		return "mremap"
	case EventMemAccess:
		return "mem_access"
	case EventSyscallRet:
		return "syscall_ret"
	case EventAllocFail:
		return "alloc_fail"
	case EventStat:
		return "stat"
	case EventCrash:
		return "crash"
	default:
		return fmt.Sprintf("event_%d", uint32(t))
	}
}

// AllocOp mirrors enum gfs_alloc_op.
type AllocOp uint32

const (
	OpMalloc  AllocOp = 1
	OpCalloc  AllocOp = 2
	OpRealloc AllocOp = 3
	OpFree    AllocOp = 4
	OpAligned AllocOp = 5
	OpNew     AllocOp = 6
	OpDelete  AllocOp = 7
)

func (o AllocOp) String() string {
	switch o {
	case OpMalloc:
		return "malloc"
	case OpCalloc:
		return "calloc"
	case OpRealloc:
		return "realloc"
	case OpFree:
		return "free"
	case OpAligned:
		return "aligned_alloc"
	case OpNew:
		return "new"
	case OpDelete:
		return "delete"
	default:
		return fmt.Sprintf("op_%d", uint32(o))
	}
}

// Event flags mirror the GFS_AF_* bits in bpf/gofengshui.h.
const (
	EventFlagUnknown    = 1 << 0
	EventFlagTcacheLink = 1 << 1
	EventFlagMetadata   = 1 << 2
	EventFlagNextChunk  = 1 << 3
)

// Event is a decoded ring-buffer record.
type Event struct {
	Timestamp time.Time `json:"ts"`
	KTime     uint64    `json:"ktime"`
	Type      EventType `json:"type"`
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	Addr      uint64    `json:"addr"`
	Size      uint64    `json:"size"`
	ReqSize   uint64    `json:"req_size"`
	Caller    uint64    `json:"caller"`
	StackID   int32     `json:"stack_id"`
	Arg1      uint64    `json:"arg1"`
	Arg2      uint64    `json:"arg2"`
	Aux1      uint64    `json:"aux1"`
	Aux2      uint64    `json:"aux2"`
	Flags     uint32    `json:"flags"`
	Comm      string    `json:"comm"`
}

func (e Event) String() string {
	return fmt.Sprintf("%s pid=%d tid=%d addr=0x%x size=%d req=%d",
		e.Type, e.PID, e.TID, e.Addr, e.Size, e.ReqSize)
}

// State is the allocator state kept by the heap model.
type State uint32

const (
	StateLive  State = 1
	StateFreed State = 0
)

// Allocation is the normalized heap-model view of one allocation.
type Allocation struct {
	ID          uint64 `json:"id"`
	Addr        uint64 `json:"addr"`
	ReqSize     uint64 `json:"req_size"`
	ChunkSize   uint64 `json:"chunk_size"`
	Allocator   string `json:"allocator"`
	State       State  `json:"state"`
	TID         uint32 `json:"tid"`
	StackID     int32  `json:"stack_id"`
	AllocTS     int64  `json:"alloc_ts"`
	FreeTS      int64  `json:"free_ts"`
	Generation  uint64 `json:"generation"`
	MmapBacked  bool   `json:"mmap_backed"`
	LastEventID uint64 `json:"last_event_id"`
}

func (a Allocation) End() uint64 {
	if a.ChunkSize == 0 {
		return a.Addr + a.ReqSize
	}
	return a.Addr + a.ChunkSize
}

// Finding is produced by the detector engine or ptrace validator.
type Finding struct {
	ID         string         `json:"id"`
	Severity   string         `json:"severity"`
	Message    string         `json:"message"`
	Event      *Event         `json:"event,omitempty"`
	Allocation *Allocation    `json:"allocation,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	Timestamp  time.Time      `json:"ts"`
}

// Target describes a process the agent can attach to.
type Target struct {
	PID        int    `json:"pid"`
	InitPID    uint32 `json:"init_pid"`
	CgroupID   uint64 `json:"cgroup_id"`
	ExePath    string `json:"exe_path"`
	LibcPath   string `json:"libc_path"`
	LibcBase   uint64 `json:"libc_base"`
	ExeBase    uint64 `json:"exe_base"`
	Arch       string `json:"arch"`
	Compatible bool   `json:"compatible"`
}

// Config controls eBPF and detector behavior for a session.
type Config struct {
	PID       uint32 `json:"pid"`
	CgroupID  uint64 `json:"cgroup_id"`
	Heap      bool   `json:"heap"`
	Syscalls  bool   `json:"syscalls"`
	UAF       bool   `json:"uaf"`
	Stacks    bool   `json:"stacks"`
	Detectors bool   `json:"detectors"`
	Follow    bool   `json:"follow"`
	// NoLibc disables allocator uprobes. Useful for statically linked or
	// custom-allocator targets.
	NoLibc bool `json:"no_libc"`
	// NoEBPF is a diagnostic fallback that runs only the ptrace engine.
	NoEBPF bool `json:"no_ebpf"`
	// Backfill scans the main heap when attaching to a running process.
	Backfill bool `json:"backfill"`
	// GlibcVersion overrides allocator profile detection (for example "2.31").
	GlibcVersion string `json:"glibc_version,omitempty"`
	// WatchFreed arms hardware write watchpoints on recently freed chunks.
	WatchFreed bool `json:"watch_freed,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		Heap:      true,
		Syscalls:  true,
		UAF:       true,
		Stacks:    true,
		Detectors: true,
		Backfill:  true,
	}
}

func (c Config) Flags() uint32 {
	var f uint32
	if c.Heap {
		f |= 1 << 0
	}
	if c.Syscalls {
		f |= 1 << 1
	}
	if c.UAF {
		f |= 1 << 2
	}
	if c.Stacks {
		f |= 1 << 3
	}
	if c.Detectors {
		f |= 1 << 4
	}
	return f
}

// Registers is the x86_64 user register set exposed by the debugger.
type Registers struct {
	R15     uint64 `json:"r15"`
	R14     uint64 `json:"r14"`
	R13     uint64 `json:"r13"`
	R12     uint64 `json:"r12"`
	RBP     uint64 `json:"rbp"`
	RBX     uint64 `json:"rbx"`
	R11     uint64 `json:"r11"`
	R10     uint64 `json:"r10"`
	R9      uint64 `json:"r9"`
	R8      uint64 `json:"r8"`
	RAX     uint64 `json:"rax"`
	RCX     uint64 `json:"rcx"`
	RDX     uint64 `json:"rdx"`
	RSI     uint64 `json:"rsi"`
	RDI     uint64 `json:"rdi"`
	OrigRAX uint64 `json:"orig_rax"`
	RIP     uint64 `json:"rip"`
	CS      uint64 `json:"cs"`
	EFLAGS  uint64 `json:"eflags"`
	RSP     uint64 `json:"rsp"`
	SS      uint64 `json:"ss"`
	FSBase  uint64 `json:"fs_base"`
	GSBase  uint64 `json:"gs_base"`
	DS      uint64 `json:"ds"`
	ES      uint64 `json:"es"`
	FS      uint64 `json:"fs"`
	GS      uint64 `json:"gs"`
}

// Arch is the supported architecture.
const ArchX86_64 = "x86_64"

// SyscallNumber constants for x86_64.
const (
	SysRead     = 0
	SysWrite    = 1
	SysMmap     = 9
	SysMunmap   = 11
	SysBrk      = 12
	SysPread64  = 17
	SysPwrite64 = 18
	SysMremap   = 25
	SysSendfile = 40
	SysSendto   = 44
	SysRecvfrom = 45
	SysExecve   = 59
	SysOpenat   = 257
	SysSplice   = 275
)
