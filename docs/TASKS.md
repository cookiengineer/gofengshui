# Task Tracking

Status legend: `yes`, `partial`, `no`. Updated incrementally during work.

## M0 — Scaffold and privileged harness

| # | Task | Implemented? | Tested? | Verified? |
|---|---|---|---|---|
| M0.1 | Repository layout (`source/`, `bpf/`, `build/`, `docs/`, `deploy/`) | yes | yes | yes |
| M0.2 | `Makefile` targets (`generate`, `build`, `test`, `test-c`, `clean`, `fmt`, `vet`) | yes | yes | yes |
| M0.3 | BPF C module and shared event/map headers | yes | yes | yes |
| M0.4 | BPF object -> embedded Go byte-slice generator | yes | yes | yes |
| M0.5 | eBPF loader and ringbuf decoder | yes | yes | yes |
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
| M1.11 | D4 OOM/allocation-failure detection | yes | yes | yes |
| M1.12 | D6 crash classification | yes | yes | yes |
| M1.13 | JSONL protocol framing and versioning | yes | yes | yes |
| M1.14 | stdio transport | yes | yes | yes |
| M1.15 | Unix-socket transport | yes | yes | yes |
| M1.16 | Session manager and commands | yes | yes | yes |
| M1.17 | Event subscription and cursor | yes | yes | yes |
| M1.18 | Heap query/snapshot export | yes | yes | yes |

## M2 — ptrace control and ROP proof

| # | Task | Implemented? | Tested? | Verified? |
|---|---|---|---|---|
| M2.1 | Locked-thread ptrace event loop | yes | yes | yes |
| M2.2 | Spawn-under-tracer | yes | yes | yes |
| M2.3 | Attach to running process | yes | yes | yes |
| M2.4 | Pause / resume | yes | yes | yes |
| M2.5 | Register and memory access | yes | yes | yes |
| M2.6 | Software breakpoints | yes | yes | yes |
| M2.7 | Hardware execution breakpoints | yes | yes | yes |
| M2.8 | Hardware read/write watchpoints | yes | yes | yes |
| M2.9 | Single-step with control-transfer decode | yes | yes | yes |
| M2.10 | Watch an allocation by heap ID | yes | yes | partial |
| M2.11 | Sink registration | yes | yes | yes |
| M2.12 | Hijack watch -> single-step -> sink | yes | yes | yes |
| M2.13 | ROP chain capture and gadget classification | yes | yes | yes |
| M2.14 | Argument assertions and `rop.json` | yes | yes | yes |
| M2.15 | CLI `run` / `attach` / `agent` / `ctl` / `validate` / `check` expectations | yes | yes | yes |

## M3 — Hardening

| # | Task | Implemented? | Tested? | Verified? |
|---|---|---|---|---|
| M3.1 | Multi-thread tracing, clone hooks, per-thread debug registers | yes | yes | yes |
| M3.2 | Stop-the-world for all traced threads | yes | yes | yes |
| M3.3 | fork/exec follow | yes | yes | yes |
| M3.4 | dlopen rescan / re-attach (`maps.refresh`, resolver retry) | yes | yes | partial |
| M3.5 | tcache / main_arena introspection | no | no | no |
| M3.6 | Additional syscall coverage | partial | no | no |
| M3.7 | OOM tracepoint integration | no | no | no |
| M3.8 | Performance/overhead benchmarks | no | no | no |
| M3.9 | musl backend | no | no | no |
| M3.10 | Go runtime backend | no | no | no |
| M3.11 | Docs and CI assertion DSL | yes | partial | no |
| M3.12 | Heap-feng-shui analysis (size classes, gaps, reuse) | yes | yes | yes |
| M3.13 | Per-process allocator uprobes covering all threads + fork/exec reattach | yes | yes | yes |
| M3.14 | Tcache/free-list reuse prediction (`heap.predict`) | yes | yes | yes |
| M3.15 | Attach-time main-heap backfill | yes | yes | yes |
| M3.16 | CLI CI expectations (`--expect-findings`, `--expect-no-findings`, `--expect-regs`) | yes | yes | yes |
| M3.17 | glibc allocator profile detection and `--glibc-version` override | yes | yes | partial |
| M3.18 | D7 tcache free-list link / safe-linking anomaly detector | yes | yes | partial |

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
- stdio JSONL session with live D2 event, `wait`, and `assert`
- attach workflow with allocator events from multiple threads
- attach-time main-heap backfill recovered all three fixture allocations
- CLI expectations (`--expect-findings`, `--expect-no-findings`,
  `--expect-regs`) exercised by the suite

## P0 Closure Status

Privileged suite passed with status 0:

- software breakpoint trigger path
- allocation watch by heap ID handler (live watchpoint trigger still to verify)
- event replay cursor
- stdio JSONL session with live D2 event and `assert`
- attach CLI workflow
- attach-time main-heap backfill
- CLI expectation runner for findings and sink registers
- resolver refresh for dlopen'ed modules (allocator reattach still pending)

## Prediction Status

`heap.predict` is implemented with deterministic unit tests for:

- glibc `request2size` mapping
- per-thread tcache LIFO order
- consuming a predicted chunk on reallocation
- tcache overflow into fastbin LIFO
- smallbin FIFO ordering
- per-thread isolation and `tid: 0` merging
- glibc profile detection and safe-linking-aware decoding
- tcache fills with the first seven frees, then fastbin LIFO

It is a userspace model based on observed free/alloc events, not a direct read
of glibc's tcache or arena structures.

## Verification Notes

- `yes` under Tested means covered by an automated or executed local check.
- `yes` under Verified means observed end-to-end in the relevant environment.
- Implemented-but-not-fully-verified items:
  - D7 tcache link detection is unit-tested and wired into the privileged suite; the next privileged rerun is pending.
  - M1.14 stdio end-to-end session driving
  - M1.17 event replay/cursor edge cases
  - M2.6 software-breakpoint trigger path
  - M2.10 watching an allocation by heap model ID
  - M2.14 protocol `assert` command (ROP JSON is verified)
  - M2.15 CLI `attach` workflow
  - M3.11 CI assertion DSL/runner

## Remaining Work

### P0 — Exploit validation completeness

| Item | Status |
|---|---|
| Software-breakpoint trigger/step/reinsert test | done |
| Watch allocation by heap ID end-to-end | handler done; live trigger pending |
| Protocol `assert` command and CI runner | done |
| Stdio JSONL end-to-end session test | done |
| Event replay/cursor tests | done |
| Attach CLI workflow + attach-time heap backfill | done for main heap; thread arenas pending |
| dlopen rescan and reattach for new libraries | resolver refresh done; allocator reattach pending |

### P1 — Allocator depth and heap feng shui

| Item | Status |
|---|---|
| Direct tcache/main_arena/bin introspection | implement |
| Allocator-version profiles (glibc 2.26–2.44) | done |
| tcache poisoning / safe-linking anomaly detector (D7) | done |
| Realloc-style free sequences in predictor | improve |
| C++ new/delete symbol-specific probes | implement |
| Better separation of per-arena vs per-thread bins | improve |
| Baseline comparison and spray recipe export | implement |

### P2 — Zero-day and crash validation

| Item | Status |
|---|---|
| Kernel OOM/memcg tracepoints | implement |
| Fault address via `PTRACE_GETSIGINFO` | implement |
| Additional syscall buffers (`openat`, `execve`, `sendfile`, `splice`) | implement |
| Stack/callstack sanity checks | implement |
| Type-confusion and heap-metadata corruption heuristics | research |
| Race/TOCTOU signal correlation | research |

### P3 — Portability and performance

| Item | Status |
|---|---|
| musl allocator backend | implement |
| Go runtime allocator backend | implement |
| arm64 support | implement |
| Overhead benchmarks and sampling controls | implement |
| Long-running session backpressure/loss accounting | verify |
| Final packaging/docs/release artifacts | implement |
