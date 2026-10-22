# Task Tracking

Status legend: `yes`, `partial`, `no`. Updated incrementally during work.

## M0 — Scaffold and privileged harness

| # | Task | Implemented? | Tested? | Verified? |
|---|---|---|---|---|
| M0.1 | Repository layout (`source/`, `bpf/`, `build/`, `docs/`, `deploy/`) | yes | yes | yes |
| M0.2 | `Makefile` targets (`generate`, `build`, `test`, `test-c`, `clean`, `fmt`, `vet`) | yes | yes | yes |
| M0.3 | BPF C module and shared event/map headers | yes | yes | no |
| M0.4 | BPF object -> embedded Go byte-slice generator | yes | yes | yes |
| M0.5 | eBPF loader and ringbuf decoder | yes | yes | no |
| M0.6 | C test harness with `gfs_sink` and PoCs | yes | yes | yes |
| M0.7 | Deploy scripts for privileged container | yes | yes | yes |
| M0.8 | Static `CGO_ENABLED=0` binary build | yes | yes | yes |
| M0.9 | malloc/free JSONL event stream | yes | yes | yes |
| M0.10 | Double-free detection | yes | yes | yes |

## M1 — eBPF tracing and remote protocol

| # | Task | Implemented? | Tested? | Verified? |
|---|---|---|---|---|
| M1.1 | glibc allocator uprobes (malloc/calloc/realloc/free) | yes | yes | yes |
| M1.2 | Chunk-header size measurement from BPF | yes | yes | yes |
| M1.3 | C++ new/delete uprobes | no | no | no |
| M1.4 | Raw syscall tracing (mmap/munmap/brk/mremap/read/write) | yes | yes | yes |
| M1.5 | ELF symbol and `/proc/<pid>/maps` resolver | yes | yes | yes |
| M1.6 | Container filtering (cgroup ID, PID-namespace-safe) | yes | yes | yes |
| M1.7 | Heap model and interval checks | yes | yes | yes |
| M1.8 | D1 double/invalid free | yes | yes | yes |
| M1.9 | D2 UAF syscall-buffer detection | yes | yes | yes |
| M1.10 | D3 heap-overflow range detection | yes | yes | yes |
| M1.11 | D4 OOM/allocation-failure detection | yes | partial | no |
| M1.12 | D6 crash classification | yes | yes | no |
| M1.13 | JSONL protocol framing and versioning | yes | yes | yes |
| M1.14 | stdio transport | yes | yes | partial |
| M1.15 | Unix-socket transport | yes | yes | yes |
| M1.16 | Session manager and commands | yes | yes | yes |
| M1.17 | Event subscription and cursor | yes | partial | partial |
| M1.18 | Heap query/snapshot export | yes | yes | yes |

## M2 — ptrace control and ROP proof

| # | Task | Implemented? | Tested? | Verified? |
|---|---|---|---|---|
| M2.1 | Locked-thread ptrace event loop | yes | yes | yes |
| M2.2 | Spawn-under-tracer | yes | yes | yes |
| M2.3 | Attach to running process | yes | yes | yes |
| M2.4 | Pause / resume | yes | yes | yes |
| M2.5 | Register and memory access | yes | yes | yes |
| M2.6 | Software breakpoints | yes | no | no |
| M2.7 | Hardware execution breakpoints | yes | yes | yes |
| M2.8 | Hardware read/write watchpoints | yes | yes | yes |
| M2.9 | Single-step with control-transfer decode | yes | yes | yes |
| M2.10 | Watch an allocation by heap ID | yes | no | no |
| M2.11 | Sink registration | yes | yes | yes |
| M2.12 | Hijack watch -> single-step -> sink | yes | yes | partial |
| M2.13 | ROP chain capture and gadget classification | yes | yes | yes |
| M2.14 | Argument assertions and `rop.json` | yes | partial | yes |
| M2.15 | CLI `run` / `attach` / `agent` / `ctl` / `validate` | yes | yes | partial |

## M3 — Hardening

| # | Task | Implemented? | Tested? | Verified? |
|---|---|---|---|---|
| M3.1 | Multi-thread tracing, clone hooks, per-thread debug registers | yes | yes | yes |
| M3.2 | Stop-the-world for all traced threads | yes | yes | yes |
| M3.3 | fork/exec follow | yes | yes | yes |
| M3.4 | dlopen rescan / re-attach | no | no | no |
| M3.5 | tcache / main_arena introspection | no | no | no |
| M3.6 | Additional syscall coverage | partial | no | no |
| M3.7 | OOM tracepoint integration | no | no | no |
| M3.8 | Performance/overhead benchmarks | no | no | no |
| M3.9 | musl backend | no | no | no |
| M3.10 | Go runtime backend | no | no | no |
| M3.11 | Docs and CI assertion DSL | yes | partial | no |
| M3.12 | Heap-feng-shui analysis (size classes, gaps, reuse) | yes | yes | yes |
| M3.13 | Per-thread allocator uprobes for new threads | yes | yes | yes |

## Privileged Integration Result (2026-10-22)

`deploy/run-integration.sh` completed with status 0:

- D1 double-free finding observed
- D2 UAF finding observed
- D3 heap-overflow finding observed
- ROP flow reached `gfs_sink` with `RDI=0x4141`
- `rop.json` reports `verified: true`
- reports and event streams written under `build/reports/`

## Latest Privileged Run (2026-10-22)

All checks passed with status 0:

- D1/D2/D3/D4/D6 findings
- clean malloc/free loop with zero false positives
- heap analysis export
- multi-thread allocations from 5 threads
- fork/exec allocations from 2 processes
- `rop.arm` and `hijack.watch` both verified with `RDI=0x4141`
- unix-socket session + live D2 event + close

## Verification Notes

- `yes` under Tested means covered by an automated or executed local check.
- `yes` under Verified means the behavior was observed end-to-end in the
  relevant environment.
- Remaining unverified items are mostly advanced features:
  - M1.3 C++-specific uprobes (deferred)
  - M1.11 D4 live OOM test
  - M1.12/M1.17 crash/cursor edge cases
  - M2.6 software breakpoint trigger, M2.10 allocation watch by ID
  - M2.12 privileged hijack-watch run, M1.14 stdio end-to-end
  - M3 multi-thread/fork/tcache/musl/Go work
- Go unit tests currently pass:
  - heap model D1/D2/D3, mmap tracking, tombstone reuse
  - protocol framing, unix transport, agent hello
  - ELF maps, runtime entry and resolver
  - gadget classification, detector dedup
  - embedded BPF object parsing, event decoding, C/Go struct sizes
  - ptrace launch/attach, registers, memory, pause/resume, single-step
  - hardware execution breakpoint trigger, write watchpoint trigger
  - ROP flow from `gfs_pop_rdi_ret` to `gfs_sink` with `RDI=0x4141`
  - full agent session in `--no-ebpf` diagnostic mode: symbol resolution,
    sink registration, ROP trace, verified results, events/heap/rop/report
    export
- Build/test commands executed successfully:
  - `make generate`, `make build`, `make test-c`, `make test`, `go vet`
  - `podman build -t localhost/gofengshui:dev -f deploy/Containerfile .`
