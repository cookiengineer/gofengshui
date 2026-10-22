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
docs/                    plan, tasks, protocol, deployment, development workflow
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
| syscalls | raw `sys_enter` / `sys_exit` | mmap, munmap, brk, mremap, read, write, openat, execve, sendfile, splice |
| kernel | `oom_kill_process` raw tracepoint or kprobe (`--oom`) | kernel OOM kill events (D4) |
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
- D2 UAF read/write from syscall buffers, including `openat`, `execve`,
  `sendfile` and `splice` offset/path pointers, plus optional auto-watchpoints
  on recently freed chunks for direct (non-syscall) writes.
- D3 heap overflow from access range versus allocation end.
- D4 OOM/allocation failure (malloc NULL, mmap/mremap errno).
- D5 sink/hijack hit (ptrace).
- D6 crash classification: fatal signal, RIP symbolization,
  controlled-RIP candidate flag, `PTRACE_GETSIGINFO` fault address/access
  classification and an executable stack-window summary.
- Heap analysis: size-class histogram, largest live/freed chunks, address
  gaps and address reuse.
- Allocator profiles: detect glibc 2.26–2.44 behavior from the target libc
  (`tcache`, safe-linking, tcache key, bin limits) with an explicit override.
  Glibc 2.42 uses the `num_slots[76]` tcache layout; glibc 2.44 raises the
  fill count to 16 and removes fastbins.
- Direct allocator introspection: locate stripped-libc `tcache` TLS slots via
  `R_X86_64_TPOFF64` relocations and thread `fs_base`, validate both tcache
  layouts, walk safe-linked bins, and scan main/thread arenas. Live tcache
  state is preferred over the event model when available.
- Allocation prediction: profile-driven glibc request2size, per-thread tcache
  LIFO (7 frees through 2.43, 16 from 2.44), plus fastbin LIFO where fastbins
  exist and smallbin FIFO ordering keyed by arena. Arena regions are refreshed
  from maps as threads create heaps; live tcache bins override the model when
  available.
- Realloc-aware timeline: moving reallocs free the old chunk; in-place reallocs
  preserve the allocation ID.
- Baseline/diff snapshots and advisory spray recipes (`heap.baseline`,
  `heap.diff`, `heap.recipe`) with JSON export.
- Attach-time main-heap and thread-arena backfill, dlopen resolver/allocator
  refresh, stdio protocol validation, software breakpoints, allocation-ID
  watch, and CLI CI expectations all verified in the privileged suite.
- D7 tcache free-list link anomalies: the BPF allocator return probe records a
  popped chunk's encoded `next` word; Go decodes safe-linking and flags links
  that leave the tracked free list or mapped memory, self-loops, links to live
  allocations, and cross-size-class links.
- D8 chunk metadata corruption: BPF records the chunk and next-chunk size words
  at free() entry; Go validates alignment, bounds and PREV_INUSE.
- D9 size-field mismatch: the free-time header size is compared with the size
  recorded at allocation, catching valid-looking size overwrites.

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
- The trace must leave the start address (start and sink may not be equal) and
  execute at least one control-transfer gadget before the sink.
- Executable chain entries must decode as valid gadgets; when a chain base is
  supplied, the chain must contain the start and sink addresses. Data words
  are allowed.
- Gadgets are classified by disassembly.
- A legitimate sink call without a hijack path is not accepted.
- A signal, exit, or max-step stop before the sink is not verified and does not
  produce a sink hit.

Without a hijack slot or a chain base/start, only the sink hit and stack window
can be proven.

## Protocol

Versioned newline-delimited JSON. Same schema on stdio and unix sockets. See
`docs/PROTOCOL.md`.

Core methods:

```
session.create / session.close / session.status
events.subscribe / events.cursor
heap.query / heap.snapshot / heap.predict / heap.introspect /
heap.baseline / heap.diff / heap.recipe /
mem.read / mem.write / regs.get / stack.get
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
- D7 can report a medium-severity link for tcache neighbors that were freed
  before an attach session started; spawn mode has a complete free history.
- Direct introspection depends on the target libc exposing
  `R_X86_64_TPOFF64` relocations and on supported tcache arena layouts.
  Glibc 2.43 is treated as the 2.42 layout fallback because its release was
  not separately characterized; the live snapshot overrides the version
  fallback where possible. Large tcache bins (a tunable beyond the default
  0x410 ceiling) are observation-only.
- ASLR and scheduling limit determinism; use relative offsets and recorded
  baselines.
- The agent is root-equivalent and belongs in a sandboxed CTF/CI environment.

## Current Implementation Status

See `docs/TASKS.md` for the per-task implemented/tested/verified matrix.

Implemented and locally tested:

- repository/build pipeline and embedded BPF object generation
- glibc allocator uprobes and raw syscall tracing source
- heap model, tombstones, D1/D2/D3 findings
- glibc allocator profiles (including the 2.42 tcache layout and 2.44
  no-fastbin/16-slot behavior), safe-linking-aware prediction and D7 tcache
  link anomaly detection
- live tcache/arena introspection via stripped-libc TLS relocation discovery
  (`heap.introspect`), with observed-bin prediction
- realloc-aware heap timeline, baseline diffs and spray recipe generation
- live hardware watchpoints on heap-model allocation IDs
- opt-in automatic write watchpoints on recently freed chunks (`--watch-freed`)
- D8 chunk/next-chunk metadata validation at free() entry
- D9 allocated-vs-free chunk size consistency checks
- per-arena fastbin/smallbin modeling with per-thread tcache
- kernel OOM tracepoint/kprobe integration
- direct UAF writes caught by freed-chunk auto-watchpoints
- ringbuf/drop accounting, stack sampling controls and model benchmarks
- versioned release artifacts (`make dist`) with checksums
- dlopen rescan with per-thread allocator probe reattachment (`maps.refresh`)
- C++ new/delete labelling for libstdc++ allocations
- attach-time thread-arena backfill with heap_info validation
- D6 fault-address classification and stack-window summary via ptrace
- D2 checks for openat/execve paths and sendfile/splice offset pointers
- JSONL protocol, stdio and unix transports
- ptrace launch/attach, pause/resume, registers, memory, single-step,
  hardware break/watchpoint installation
- sink registration, hijack watch, ROP single-step tracing source,
  gadget classification and report export
- multi-thread clone hooks, process-wide allocator probes, stop-the-world,
  and fork/exec follow with allocator reattachment
- CLI `run`, `attach`, `validate`, `agent`, `stdio`, `ctl`
- `--no-ebpf` diagnostic mode for ptrace-only validation

Privileged end-to-end verification (2026-10-22):

- eBPF object loaded and allocator uprobes attached
- allocator/syscall event delivery confirmed
- D1 double-free, D2 UAF and D3 heap overflow observed on live targets
- D7 tcache link anomaly observed on glibc 2.39; allocator detection and an
  explicit 2.31 override verified end-to-end
- D8 metadata corruption and D9 size overwrites detected at free() entry
- kernel OOM kills captured through the `oom_kill_process` tracepoint/kprobe
- D6 fault address/classification, crash stack hits, and D2 checks across
  openat/execve/sendfile/splice verified end-to-end
- direct-UAF writes caught by freed-chunk auto-watchpoints
- realloc churn, baseline diff and spray recipe verified end-to-end
- thread-arena attach backfill verified end-to-end
- C++ new/delete labelling and dlopen allocator reattachment verified
- per-arena prediction, zero ringbuf drops and sampled stacks verified
- ROP flow reached `gfs_sink` with `RDI=0x4141` and `verified: true`

Deferred:

- memcg OOM tracepoints
- race/TOCTOU correlation research
- musl and Go runtime backends, arm64 support
