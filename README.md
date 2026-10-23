# Go Heap Feng Shui eBPF Agent

A standalone `CGO_ENABLED=0` Go agent and library for heap feng shui and
exploit validation on glibc targets. It combines eBPF observation with ptrace
control to develop and validate exploits more efficiently.

Currently targets dynamically linked glibc C/C++ programs on `x86_64`.

## Features

- eBPF allocator and syscall tracing with an embedded BPF object
- Heap timeline, size-class analysis, address gaps, reuse tracking
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

## Testing

### Unprivileged tests

Run the source unit tests, fixture builds, vetting, and benchmarks without
root:

```sh
make test
make test-c
make vet
make bench
```

The e2e harness also has unprivileged unit tests:

```sh
go -C e2e-tests test ./internal/...
```

### Privileged e2e tests

The container suite loads real eBPF and uses rootful podman, so it must run as
root:

```sh
sudo -E make e2e
```

This builds the agent and the glibc case image, starts a privileged container,
compiles the victim tests with `go test -c -tags victim`, copies the binary into
the container, executes it, and then validates the exported reports from the
host. Running `make e2e` without `sudo` exits at the root guard and does not
create a new log.

Run the glibc base-image matrix, and allow pulling missing base images:

```sh
sudo -E GFS_E2E_MATRIX=1 GFS_E2E_PULL=1 make e2e
```

Pull the Alpine image for the musl case:

```sh
sudo -E GFS_E2E_PULL=1 make e2e
```

The latest host log is:

```text
build/logs/latest-e2e.log
```

Per-test logs and reports are written under:

```text
build/e2e/<timestamp>-<pid>/<case>/
```

Useful environment variables:

- `GFS_SKIP_BUILD=1` reuses the existing agent binary and case images.
- `GFS_BPF_LOG=1` includes eBPF verifier output.
- `GFS_MEMORY_LIMIT` overrides the container memory limit (default `2g`).
- `GFS_E2E_KEEP=1` keeps the test container for inspection.
- `GFS_E2E_MATRIX=1` enables the glibc base-image matrix.
- `GFS_E2E_PULL=1` allows pulling missing base images.
- `GFS_IMAGE_PREFIX` and `GFS_IMAGE_TAG` override image naming.
- `GFS_REPO_ROOT` overrides repository-root discovery.

### Test case layout

Each container case is self-contained:

```text
e2e-tests/<case>/
  Containerfile
  <case>_test.go   # //go:build !victim; builds images and manages podman
  victim_test.go   # //go:build victim; runs inside the container
```

Compile a victim test binary manually with:

```sh
CGO_ENABLED=0 go -C e2e-tests test -c -tags victim \
  -o build/e2e/<case>.victim.test ./<case>
```

See `docs/DEVELOPMENT.md` for adding cases, failure triage, and the full
privileged workflow.

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

## Security

The agent is root-equivalent, it loads eBPF programs and traces processes.
Run it only in disposable CTF/CI sandboxes or otherwise trusted environments.
The unix socket is created with mode `0600`.

