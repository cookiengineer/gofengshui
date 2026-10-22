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
| M1.3 | C++ new/delete uprobes | yes | yes | yes |
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
| M2.10 | Watch an allocation by heap ID | yes | yes | yes |
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
| M3.4 | dlopen rescan / re-attach (`maps.refresh`, resolver retry) | yes | yes | yes |
| M3.5 | tcache / main_arena introspection | yes | yes | no |
| M3.6 | Additional syscall coverage (`openat`, `execve`, `sendfile`, `splice`) | yes | yes | yes |
| M3.7 | OOM tracepoint/kprobe integration | yes | yes | yes |
| M3.8 | Performance/overhead benchmarks | yes | yes | yes |
| M3.9 | musl backend | no | no | no |
| M3.10 | Go runtime backend | no | no | no |
| M3.11 | Docs and CI assertion DSL | yes | partial | no |
| M3.12 | Heap-feng-shui analysis (size classes, gaps, reuse) | yes | yes | yes |
| M3.13 | Per-process allocator uprobes covering all threads + fork/exec reattach | yes | yes | yes |
| M3.14 | Tcache/free-list reuse prediction (`heap.predict`) | yes | yes | yes |
| M3.15 | Attach-time main-heap and thread-arena backfill | yes | yes | yes |
| M3.16 | CLI CI expectations (`--expect-findings`, `--expect-no-findings`, `--expect-regs`) | yes | yes | yes |
| M3.17 | glibc allocator profile detection and `--glibc-version` override | yes | yes | yes |
| M3.18 | D7 tcache free-list link / safe-linking anomaly detector | yes | yes | yes |
| M3.19 | D6 fault address/access via `PTRACE_GETSIGINFO` and stack hits | yes | yes | yes |
| M3.20 | Realloc-aware heap timeline (moved and in-place) | yes | yes | yes |
| M3.21 | Baseline diff + spray recipe (`heap.baseline`/`diff`/`recipe`) | yes | yes | yes |
| M3.22 | D8 chunk/next-chunk metadata corruption detector | yes | yes | yes |
| M3.23 | Automatic freed-chunk write watchpoints (`--watch-freed`) | yes | yes | yes |
| M3.24 | D9 allocated-vs-free chunk size mismatch detector | yes | yes | yes |
| M3.25 | Per-arena bin modeling (tcache stays per-thread) | yes | yes | yes |
| M3.26 | glibc 2.42+ tcache layout, 2.44 fill count and no-fastbin profile | yes | yes | no |
| M3.27 | `heap.introspect` tcache/arena introspection on stripped libc | yes | yes | no |
| M3.28 | Observed-bin prediction (`heap.predict observe`) | yes | yes | no |

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

- D1/D2/D3/D4/D6/D7 findings
- detected glibc 2.39 profile and explicit 2.31 override verified
- D6 fault address/classification + stack hits and D2 syscall-buffer checks verified
- realloc churn, baseline diff and spray recipe verified over the privileged suite
- thread-arena attach backfill, D8 metadata detection, and direct-UAF auto-watch verified
- BPF event/drop accounting verified with `drops: 0`
- dlopen rescan and allocator probe reattachment verified
- C++ new/delete labelling, D9 size-mismatch detection, stack sampling, and per-arena prediction verified
- kernel OOM capture verified with an isolated sibling victim
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
- allocation watch by heap ID with a live hardware-watchpoint trigger
- event replay cursor
- stdio JSONL session with live D2 event and `assert`
- attach CLI workflow
- attach-time main-heap backfill
- CLI expectation runner for findings and sink registers
- dlopen resolver refresh and allocator probe reattachment

## Prediction Status

`heap.predict` is implemented with deterministic unit tests for:

- glibc `request2size` mapping
- per-thread tcache LIFO order
- consuming a predicted chunk on reallocation
- tcache overflow into fastbin LIFO on pre-2.44 profiles
- tcache overflow into smallbin FIFO on 2.44 (no fastbins)
- smallbin FIFO ordering
- per-thread isolation and `tid: 0` merging
- glibc profile detection and safe-linking-aware decoding
- tcache fills with the profile's fill count (7 through 2.43, 16 from 2.44)
- observed-bin prediction from `heap.introspect`

The default predictor is a userspace model based on observed free/alloc events;
`heap.predict` with `observe: true` (or a recent `heap.introspect` snapshot)
uses live tcache state instead.

## Final Regression (2026-10-22)

`deploy/run-integration.sh` completed with status 0 after the final changes:

- allocator profile detection and 2.31 override
- D7 tcache links (including self-loop/live/cross-size unit coverage)
- D8/D9 chunk metadata and size-mismatch detection
- D2 syscall buffers, D6 fault info/stack hits, direct-UAF auto-watch
- realloc churn, baseline/diff and recipe
- main-heap and thread-arena attach backfill
- C++ new/delete labelling and dlopen probe reattachment
- BPF stats with zero ring-buffer drops and sampled stack capture
- kernel OOM tracepoint/kprobe capture with an isolated victim
- privileged host gates for every item above

Release packaging (`make dist`) is verified locally and is not part of the
privileged container suite.

## Verification Notes

- `yes` under Tested means covered by an automated or executed local check.
- `yes` under Verified means observed end-to-end in the relevant environment.
- Implemented-but-not-fully-verified items:
  - M1.17 event replay/cursor edge cases beyond the current replay test
  - M3.11 CI assertion DSL beyond the implemented CLI expectation runner
  - M3.26–M3.28 are covered by unprivileged live ptrace tests and synthetic
    layout tests; the privileged integration suite does not yet exercise
    `heap.introspect`
- All other implemented items are covered by unit tests and the privileged
  integration suite.

## Remaining Work

### P0 — Exploit validation completeness

| Item | Status |
|---|---|
| Software-breakpoint trigger/step/reinsert test | done |
| Watch allocation by heap ID end-to-end | done |
| Protocol `assert` command and CI runner | done |
| Stdio JSONL end-to-end session test | done |
| Event replay/cursor tests | done |
| Attach CLI workflow + attach-time heap backfill | done for main heap and thread arenas |
| dlopen rescan and reattach for new libraries | done |
| ROP trace soundness: no sink hit on failed traces, start/sink separation, control-flow and chain checks | done (unit-tested) |

### P1 — Allocator depth and heap feng shui

| Item | Status |
|---|---|
| Direct tcache/main_arena/bin introspection | done (`heap.introspect`) |
| Allocator-version profiles (glibc 2.26–2.44) | done (2.42 layout, 2.44 no-fastbin/16-slot) |
| tcache poisoning / safe-linking anomaly detector (D7) | done |
| Realloc-style free sequences in predictor | done |
| C++ new/delete symbol-specific probes | done |
| Better separation of per-arena vs per-thread bins | done |
| Baseline comparison and spray recipe export | done |

### P2 — Zero-day and crash validation

| Item | Status |
|---|---|
| Kernel OOM/memcg tracepoints | OOM done; memcg deferred |
| Fault address via `PTRACE_GETSIGINFO` | done |
| Additional syscall buffers (`openat`, `execve`, `sendfile`, `splice`) | done |
| Stack/callstack sanity checks | done as executable stack-window hits |
| Type-confusion and heap-metadata corruption heuristics | D8/D9 implemented; further heuristics research |
| Race/TOCTOU signal correlation | research |

### P3 — Portability and performance

| Item | Status |
|---|---|
| musl allocator backend | deferred |
| Go runtime allocator backend | deferred |
| arm64 support | deferred |
| Overhead benchmarks and sampling controls | done |
| Long-running session backpressure/loss accounting | done |
| Final packaging/docs/release artifacts | done |
