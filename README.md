# Go Heap Feng Shui eBPF Agent

A standalone `CGO_ENABLED=0` Go agent and library for heap feng shui and
exploit validation on glibc targets. It combines eBPF observation with ptrace
control to develop and validate exploits more efficiently.

Currently targets dynamically linked glibc C/C++ programs on `x86_64`.

## Features

- eBPF allocator and syscall tracing with an embedded BPF object
- Heap timeline, size-class analysis, address gaps, reuse tracking
- Time-series allocation histograms with a bounded offline/live window feed
- Learned or stored baseline anomaly detection (D10) and phase correlation
  (D11), plus sampled chunk-content metrics
- glibc profiles 2.26–2.44, including the 2.42 tcache layout and 2.44
  no-fastbin/16-slot behavior
- Live tcache and arena introspection from stripped libc (`heap.introspect`)
- Free-list prediction (model-derived or observed), baseline diffs, and
  advisory spray recipes
- Detectors:
  - D1 double/invalid free
  - D2 use-after-free from syscall buffers or freed-chunk watchpoints
  - D3 heap overflow
  - D4 allocation failure and kernel OOM
  - D6 crash classification with fault address and stack hits
  - D7 tcache link poisoning/safe-linking anomalies
  - D8 chunk/next-chunk metadata corruption
  - D9 allocated-vs-free chunk size mismatch
  - D10 heap timeline anomaly
  - D11 exploit-phase correlation
- ptrace breakpoints, watchpoints, single-step, registers, and memory access
- Sink/hijack registration and ROP chain validation
- C++ `new`/`delete` labelling, dlopen probe reattachment
- JSONL protocol over stdio and unix sockets, with JSON/report export

## Build

```sh
make generate    # compile bpf/ and embed the object
make build       # static build/gofengshui
make test        # Go unit tests + toolchain tests
make test-c      # build C/C++ test fixtures
make bench       # heap-model benchmarks
make dist        # release tarball + sha256
```

## Testing

Quick unprivileged checks:

```sh
make test
make test-c
make vet
make bench
go -C e2e-tests test ./internal/... -count=1
```

Run the privileged container suite with rootful podman, and with eBPF-module in the host kernel tests:

```sh
sudo -E make e2e
```

Focused anomaly cases:

```sh
sudo -E make e2e-anomaly
sudo -E make e2e-anomaly-matrix
```

Opt-in suites:

```sh
sudo -E make e2e-glibc-matrix   # debian:11-slim and debian:12-slim
sudo -E make e2e-musl           # Alpine; allocator tracing is incomplete
```

The default suite uses only `ubuntu:24.04`.

## Quick Start

```sh
./build/gofengshui --help

sudo ./build/gofengshui run --report build/reports/case -- ./poc

sudo ./build/gofengshui validate \
  --sink gfs_sink --start gfs_pop_rdi_ret \
  --report build/reports/rop -- ./poc
```

Other commands: `attach`, `agent`, `stdio`, `ctl`, `analyze`, `version`.

Offline timeline analysis and anomaly calibration:

```sh
./build/gofengshui analyze --events build/reports/case/events.jsonl \
  --out build/reports/case-analysis \
  --anomaly-warmup 20
```

This writes `timeline.jsonl`, `anomalies.json`, `baseline-model.json` and
`analysis.json`. Use `--anomaly=false` for timeline-only replay, or
`--baseline-in` to score against a stored baseline.

Opt-in live anomaly detection:

```sh
sudo ./build/gofengshui run --anomaly --baseline-out build/baseline.json \
  --report build/reports/case -- ./poc
```

Add `--content-sample` to sample chunk contents and `--baseline-in` to reuse a
previously learned baseline.

## Requirements

- Linux `x86_64`, kernel with `BTF`, `uprobes`, and `ringbuf` support
- `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` (usually `CAP_SYS_ADMIN`)
- `seccomp=unconfined` in containers
- `/sys/kernel/btf/vmlinux` visible for kernel BTF

## Current Status

The memory histogram anomaly detection is implemented and working.

The focused anomaly end-to-end test case and the validation matrix tests
are passing and detecting correctly benign memory allocations and are
correctly detecting exploit anomalies, across window boundaries.

The muslc allocator tracing is still incomplete, see the `docs/` folder
for documentation on what's remaining to implement in that regard.

## Documentation

The documentation is LLM generated, but has been reviewed and is correct.

- [DEVELOPMENT.md](docs/DEVELOPMENT.md) documents harness workflow.
- [TESTING.md](docs/TESTING.md) documents testing matrix, environment variables, log output and (agentic) triage instructions.
- [PLAN.md](docs/TASKS.md) and [TASKS.md](docs/TASKS.md) document remaining Future Work.

## Security

The agent is root-equivalent, it loads eBPF programs and traces processes.
Run it only in disposable CTF/CI sandboxes or otherwise trusted environments.
The unix socket is created with mode `0600`.

