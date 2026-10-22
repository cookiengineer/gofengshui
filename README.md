# Go Heap Feng Shui eBPF Agent

A standalone `CGO_ENABLED=0` Go agent and library for heap feng shui and
exploit validation on glibc targets. It combines eBPF observation with ptrace
control to develop and validate exploits more efficiently.

Currently targets dynamically linked glibc C/C++ programs on `x86_64`.

## Features

- eBPF allocator and syscall tracing with an embedded BPF object
- Heap timeline, size-class analysis, address gaps, reuse tracking
- glibc profiles 2.26–2.44 with safe-linking awareness
- Free-list prediction, baseline diffs, and advisory spray recipes
- Detectors:
  - D1 double/invalid free
  - D2 use-after-free from syscall buffers or freed-chunk watchpoints
  - D3 heap overflow
  - D4 allocation failure and kernel OOM
  - D6 crash classification with fault address and stack hits
  - D7 tcache link poisoning/safe-linking anomalies
  - D8 chunk/next-chunk metadata corruption
  - D9 allocated-vs-free chunk size mismatch
- ptrace breakpoints, watchpoints, single-step, registers, and memory access
- Sink/hijack registration and ROP chain validation
- C++ `new`/`delete` labelling, dlopen probe reattachment
- JSONL protocol over stdio and unix sockets, with JSON/report export

## Build

```sh
make generate    # compile bpf/ and embed the object
make build       # static build/gofengshui
make test        # Go unit tests
make test-c      # build C/C++ test fixtures
make bench       # heap-model benchmarks
make dist        # release tarball + sha256
```

## Quick Start

```sh
./build/gofengshui --help

sudo ./build/gofengshui run --report build/reports/case -- ./poc

sudo ./build/gofengshui validate \
  --sink gfs_sink --start gfs_pop_rdi_ret \
  --report build/reports/rop -- ./poc
```

Other commands: `attach`, `agent`, `stdio`, `ctl`, `version`.

## Requirements

- Linux x86_64, kernel with BTF, uprobes, and ringbuf support
- `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` (usually `CAP_SYS_ADMIN`)
- `seccomp=unconfined` in containers
- `/sys/kernel/btf/vmlinux` visible for kernel BTF

The privileged integration suite is run manually:

```sh
deploy/run-integration.sh
```

## Security

The agent is root-equivalent, it loads eBPF programs and traces processes.
Run it only in disposable CTF/CI sandboxes or otherwise trusted environments.
The unix socket is created with mode `0600`.

