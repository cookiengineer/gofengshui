# Go Heap FengShui — Implementation Plan

## Goal

Provide a standalone, `CGO_ENABLED=0` binary and Go library for heap feng shui
and exploit validation on glibc CTF workloads. The agent combines eBPF
observation with ptrace control:

- eBPF: transparent allocator/syscall tracing, heap timeline, UAF/overflow
  candidate detection.
- ptrace: exact pause/resume, breakpoints, step, hardware watchpoints, register
  and memory access.
- ROP validation: registered sink symbols, hijack watchpoints, single-step
  chain tracing, gadget classification, CI assertions.

The first target is dynamically linked glibc C/C++ on x86_64. Modern Linux
kernels with BTF, uprobes, ringbuf and `CAP_BPF`/`CAP_PERFMON`/
`CAP_SYS_PTRACE` are assumed.

## Repository Layout

```
Makefile
bpf/                     eBPF C sources and headers
build/                   all build artefacts (BPF objects, binary, reports)
docs/                    plan, tasks, protocol, deployment
source/                  all Go and test-harness source code
  cmd/gofengshui/        command-line entry point
  agent/                 session manager and request handling
  cli/                   command dispatch
  core/                  shared domain types
  debugger/              ptrace engine (break/watch/step/regs/mem)
  detect/                detector rules
  disasm/                x86 gadget classification
  ebpf/                  loader, attach logic, ringbuf decoding
  export/                JSONL, report and ROP export
  heap/                  heap model, interval checks, glibc adapter
  proto/                 versioned JSONL protocol
  symbols/               ELF/maps resolution
  testdata/              C harnesses and PoCs
  tools/bpfgen/          BPF object -> Go byte-slice generator
  transport/             stdio and unix-socket transports
deploy/                  privileged development scripts
```

No `internal/` directory is used; every package is importable as a library.

## Architecture

```
Host CLI / CI
  | JSONL over stdio or unix socket
  v
agent
  |-- session manager, protocol, assertions
  |-- heap model + detectors + ROP validator
  |-- eBPF tracer: uprobes + raw syscalls -> ringbuf
  |-- ptrace tracer: stop/step/watch/regs/mem
  v
target process
```

### eBPF hooks

| Layer | Hook | Data |
|---|---|---|
| allocator | uprobe/uretprobe `malloc`, `calloc`, `realloc`, `free` | requested size, pointer, header size |
| allocator | `aligned_alloc`, `posix_memalign`, C++ new/delete | when symbols exist |
| syscalls | raw `sys_enter` / `sys_exit` | mmap, munmap, brk, mremap, read, write |
| kernel | OOM tracepoints (later) | allocation failure context |
| stacks | `bpf_get_stackid(BPF_F_USER_STACK)` | allocation call site |

BPF maps:

- `config`: cgroup/PID filter and detector toggles.
- `pending`: per-TID entry/return pairing.
- `pending_sys`: per-TID syscall entry/return pairing.
- `allocs`: live allocation records.
- `tombstones`: freed ranges for fast checks.
- `stacks`: user stack IDs.
- `stats`: ringbuf drops and counters.
- `events`: ringbuf.

Kernel-side allocation size measurement:

- Read the glibc chunk header at `ptr-8` with `bpf_probe_read_user`.
- Mask low flag bits.
- Record both requested and actual chunk size.
- Fall back to requested size if the header is implausible.

### ptrace rules

- One tracer goroutine locked to one OS thread owns `wait4` and all ptrace
  calls.
- Spawn: `PTRACE_TRACEME`, `PTRACE_O_TRACECLONE/FORK/VFORK/EXEC/EXIT`,
  `PTRACE_O_EXITKILL`.
- Attach: `PTRACE_SEIZE` + `PTRACE_INTERRUPT`.
- Hardware execution breakpoints/watchpoints use DR0–DR3 via
  `PTRACE_POKEUSER` offset 848 (`struct user.u_debugreg[0]`, x86_64).
- Never place a software `int3` on an address with an active uprobe.
- Software breakpoints save the original byte, restore it for stepping, and
  reinsert afterwards.
- Watchpoints trigger on read, write, read/write or execute; sizes 1/2/4/8.
- v1 traces one selected thread precisely and suspends other threads
  best-effort. Full per-thread debug-register inheritance is M3.

### Heap model

```text
Allocation {
  id, addr, req_size, chunk_size, allocator, state,
  tid, stack_id, ts_alloc, ts_free, generation, mmap_backed
}
```

- BPF performs exact-address checks.
- Go owns the interval tree and definitive range checks.
- Freed ranges are tombstones. Exact-start checks happen in BPF; range checks
  happen in Go on syscall events.
- D1 double/invalid free.
- D2 UAF read/write from syscall buffers.
- D3 heap overflow from access range versus allocation end.
- D4 OOM/allocation failure (malloc NULL, mmap/mremap errno).
- D5 sink/hijack hit (ptrace).
- D6 crash classification (fatal signal, RIP symbolization and
  controlled-RIP candidate flag).
- Heap analysis: size-class histogram, largest live/freed chunks, address
  gaps and address reuse.
- D7 allocator metadata anomalies (later).

### Sink and ROP validation

Host registers a sink by symbol, module+offset, or raw address. The harness
exports `gfs_sink`.

Preferred chain capture:

1. Register `hijack.watch` on the saved-RIP slot or function-pointer slot.
2. Hardware watchpoint fires when the vulnerable `ret`/indirect call reads it.
3. Capture hijack point and single-step until the sink breakpoint.
4. Record every control transfer, stack pointer and register state.
5. Emit `rop.json` containing the executed chain, disassembled gadgets and
   validation result.

Fallback: `rop.arm {start, chain_base, sink, max_steps}`.

Validation:

- Sink hit at registered address.
- Argument registers match assertions.
- Chain entries are in executable mappings or known data regions.
- Gadgets are classified by disassembly.
- A legitimate sink call without a hijack path is not accepted.

Without a hijack slot or a chain base/start, only the sink hit and stack window
can be proven.

## Protocol

Versioned newline-delimited JSON. Same schema on stdio and unix sockets. See
`docs/PROTOCOL.md`.

Core methods:

```
session.create / session.close / session.status
events.subscribe / events.cursor
heap.query / heap.snapshot / mem.read / mem.write / regs.get / stack.get
break.set / break.clear / watch.set / watch.clear
pause / resume / step / mark
sink.register / hijack.watch / rop.arm
wait / assert / export
```

CLI commands: `run`, `attach`, `validate`, `agent`, `stdio`, `ctl`, `version`.

## Build

```sh
make generate    # clang compile bpf/ -> build/bpf/gofengshui.bpf.o
                 # generate source/ebpf/object_generated.go
make build       # CGO_ENABLED=0 -> build/gofengshui
make test        # Go unit tests
make clean
```

The final binary embeds the BPF object as a Go byte slice. The object is
compiled at build time and lives in `build/`; only generated Go source lives
in `source/`.

## Deployment

- Requires root or `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`
  (+ `CAP_SYS_ADMIN` in practice).
- Default container seccomp profiles block `bpf(2)`; use `seccomp=unconfined`.
- `/sys/kernel/btf/vmlinux` must be visible if kernel BTF is used.
- Rootless podman cannot run eBPF when `unprivileged_bpf_disabled=2`.
- Privileged scripts live in `deploy/` and are executed manually by the host
  operator during development.

## Milestones

### M0 — Scaffold and privileged harness

- Directory layout, Makefile, BPF build, loader, test harness, deploy scripts.
- Acceptance: static agent runs in privileged container; malloc/free JSONL
  events; double free detected.

### M1 — eBPF tracing and remote protocol

- glibc adapter, heap model, syscall tracing, symbol resolver.
- Detectors D1–D4, D6.
- JSONL stdio + unix socket, session commands.
- Acceptance: UAF/overflow detected; heap history queryable over both
  transports.

### M2 — ptrace control and ROP proof

- Spawn/attach, pause/resume, regs/mem, breakpoints, watchpoints, step.
- Sink registration, hijack watch, ROP trace, gadget classification,
  assertions, export.
- Acceptance: stack-overflow PoC reaches sink with expected registers; full
  executed chain exported and disassembled.

### M3 — Hardening

- Full multi-thread debug-register inheritance and stop-the-world.
- fork/exec follow, dlopen rescan.
- allocator metadata inspection.
- Additional detectors and performance tuning.
- musl/Go investigation.

## Risks and Limits

- Glibc internals vary by version; header parsing is validated and falls back.
- eBPF cannot observe every arbitrary load/store. Precise coverage requires
  syscalls, selected libc functions, and hardware watchpoints.
- Hardware watchpoints: four slots per thread.
- IFUNC-resolved libc functions complicate `memcpy` hooks; opt-in only.
- User stack depth needs frame pointers; test harnesses use
  `-fno-omit-frame-pointer`.
- Multi-thread precision is limited in v1.
- ASLR and scheduling limit determinism; use relative offsets and recorded
  baselines.
- The agent is root-equivalent and belongs in a sandboxed CTF/CI environment.

## Current Implementation Status

See `docs/TASKS.md` for the per-task implemented/tested/verified matrix.

Implemented and locally tested:

- repository/build pipeline and embedded BPF object generation
- glibc allocator uprobes and raw syscall tracing source
- heap model, tombstones, D1/D2/D3 findings
- JSONL protocol, stdio and unix transports
- ptrace launch/attach, pause/resume, registers, memory, single-step,
  hardware break/watchpoint installation
- sink registration, hijack watch, ROP single-step tracing source,
  gadget classification and report export
- multi-thread clone hooks, per-thread allocator probes, and stop-the-world
- CLI `run`, `attach`, `validate`, `agent`, `stdio`, `ctl`
- `--no-ebpf` diagnostic mode for ptrace-only validation

Privileged end-to-end verification (2026-10-22):

- eBPF object loaded and allocator uprobes attached
- allocator/syscall event delivery confirmed
- D1 double-free, D2 UAF and D3 heap overflow observed on live targets
- ROP flow reached `gfs_sink` with `RDI=0x4141` and `verified: true`

Deferred:

- C++ new/delete-specific uprobes (libc malloc/free already covers most)
- full multi-thread debug-register inheritance
- dlopen rescan, tcache/main_arena introspection, musl/Go backends
