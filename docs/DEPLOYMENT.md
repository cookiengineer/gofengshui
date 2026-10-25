# Deployment

## Requirements

- Linux x86_64, kernel 5.8+ (6.1+ recommended)
- `/sys/kernel/btf/vmlinux` for kernel BTF
- `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN` in practice
- seccomp profile that permits `bpf(2)` (`seccomp=unconfined`)
- rootful podman or a host-privileged agent container

On this development host:

- `unprivileged_bpf_disabled=2`
- `perf_event_paranoid=2`
- `yama/ptrace_scope=1`
- rootless podman

Therefore rootless podman cannot load the eBPF object. Use the rootful
toolchain commands below.

## Build

```sh
make generate       # clang compiles bpf/ -> build/bpf/gofengshui.bpf.o
                    # generates source/ebpf/object_generated.go
make build          # CGO_ENABLED=0 -> build/gofengshui
make test-c         # builds source/testdata/c PoCs into build/testdata
make test           # Go unit tests
```

The final binary is statically linked and embeds the BPF object.

## Release artifacts

```sh
make dist
```

This builds the static binary with embedded version/commit/date metadata and
writes:

```text
build/dist/gofengshui-<version>-linux-x86_64.tar.gz
build/dist/gofengshui-<version>-linux-x86_64.tar.gz.sha256
```

The archive contains the binary, `docs/`, and the `toolchain/` Go source.
The toolchain source is included for reference; run it from a repository
checkout with a Go toolchain installed. Override the version with
`make dist VERSION=0.2.0`. Inspect the embedded metadata with:

```sh
gofengshui version
gofengshui version --json
```

## Check the host

```sh
make check-env
```

This is read-only and can run as the normal user. It prints the same host and
eBPF diagnostics recorded by the e2e harness. Add JSON output with:

```sh
go -C e2e-tests run ./cmd/hostinfo -json
```

## Build the test image

```sh
make dev-image
```

This runs `make build` and builds `localhost/gofengshui-e2e/glibc:dev` from
`e2e-tests/glibc/Containerfile`, logging to `build/logs/latest-build.log`.
The Go tool itself can be invoked directly with
`go -C toolchain run ./build-image`. The image is built in rootful podman
storage because the privileged runner uses rootful podman; rootless and rootful
podman have separate image stores. `make e2e-image` is an alias for
`make dev-image`. The e2e harness normally builds per-case images itself.

## Run the privileged development container

```sh
make dev-container
```

This executes:

```sh
sudo podman run --rm -it \
  --privileged \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD/build/reports:/reports:Z" \
  localhost/gofengshui-e2e/glibc:dev
```

For an interactive shell, pass a container command after `--`:

```sh
go -C toolchain run ./dev-container -- /bin/bash
```

Use `--dry-run` to print the podman command without executing it.

Or run the e2e suite non-interactively as root:

```sh
sudo -E make e2e
```

The Go e2e harness builds the agent and case images, starts one privileged
container per case, compiles the `//go:build victim` tests with `go test -c`,
copies them into the container, and executes them with `podman exec`. It also
runs host-side report assertions after the victim tests. Builds are reused when
`GFS_SKIP_BUILD=1` is set. The container is memory-limited
(`GFS_MEMORY_LIMIT`, default `2g`) so the OOM tracepoint test has a bounded
cgroup to trigger against.

Logs are written to `build/logs/e2e-*.log` with the
`build/logs/latest-e2e.log` symlink. Per-test logs and reports are written under
`build/e2e/<timestamp>-<pid>/<case>/`. See `docs/DEVELOPMENT.md` for the
unprivileged/privileged handoff, log locations, and failure triage.

Expected results:

- double-free PoC emits a `D1` finding
- UAF PoC emits a `D2` finding
- syscall-buffer PoC emits `D2` through `openat`/`execve`/`sendfile`/`splice`
- direct-UAF PoC emits `D2` through a freed-chunk hardware watchpoint
- crash PoC emits `D6` with fault address, access classification and stack hits
- overflow PoC emits a `D3` finding
- tcache-poisoning PoC emits a `D7` finding
- metadata-corruption PoC emits a `D8` finding before glibc aborts
- OOM PoC triggers a bounded cgroup OOM and emits a `D4` kernel-OOM finding;
  the agent uses the OOM tracepoint when exported, otherwise a kprobe fallback
- size-swap PoC emits a `D9` size-mismatch finding
- realloc churn runs clean and exercises the realloc-aware timeline
- attach backfill recovers chunks from both the main heap and thread arenas
- dlopen plugin is resolved and allocator probes refresh via `maps.refresh`
- C++ allocations are labelled as `new`/`delete` when libstdc++ is present
- `gofengshui validate` reaches `gfs_sink` with `RDI=0x4141` and exports a
  verified ROP trace to `/reports/rop`
- `heap.introspect` reports the live tcache layout, per-thread bins and main
  arena from a stopped target (unprivileged coverage; add to the privileged
  suite when a report assertion is available)
- the Alpine/musl case emits `D1`, `D2`, `D4`, and `D6`, captures allocations
  from multiple threads and fork/exec children, and serves the unix-socket
  protocol; glibc-only tcache/metadata checks are not asserted there

## Host-privileged agent

```sh
make host-agent
```

Runs `gofengshui agent` in a privileged container with `--pid=host`, sharing
`build/run` as `/run/gofengshui`. The underlying Go command is
`go -C toolchain run ./host-agent`. From the host:

```sh
./build/gofengshui ctl \
  --socket build/run/gofengshui.sock \
  --method session.create \
  --params '{"mode":"attach","pid":1234,"pause":true}'
```

Session-bound requests need the returned session ID:

```sh
./build/gofengshui ctl \
  --socket build/run/gofengshui.sock \
  --session s1a2b3c4d \
  --method heap.snapshot
```

## In-container agent and podman exec

One-shot protocol over stdio:

```sh
podman exec -i <container> /usr/local/bin/gofengshui stdio
```

Or spawn a target and serve the protocol on the same stdio stream:

```sh
podman exec -i <container> /usr/local/bin/gofengshui run --jsonl -- ./poc
```

The host must keep stdin open and send newline-delimited JSON requests.

## Ptrace-only diagnostic mode

`--no-ebpf` runs the full session, ptrace, sink and ROP pipeline without
loading eBPF. It is useful on hosts where BPF privileges are unavailable:

```sh
gofengshui validate --no-ebpf   --sink gfs_sink --start gfs_pop_rdi_ret   --report build/reports/rop-local   -- build/testdata/rop_sink
```

This mode does not produce allocator or syscall events, but it exercises the
same breakpoint/watchpoint/ROP code used in the privileged workflow.

## Manual workflows

Trace a target:

```sh
gofengshui run --report /reports/case -- ./poc
```

Pause before continuing:

```sh
gofengshui run --pause -- ./poc
```

Attach to a running process inside the container:

```sh
gofengshui attach --pid 1 --pause
```

Validate a ROP chain:

```sh
gofengshui validate \
  --sink gfs_sink \
  --start gfs_pop_rdi_ret \
  --report /reports/rop \
  -- ./poc
```

## Report ownership

The privileged container runs as root, so e2e artifacts are created with root
ownership. `make e2e` restores ownership of `build/e2e`, `build/logs`,
`build/gofengshui`, `build/bpf`, and `source/ebpf/object_generated.go` to the
invoking `SUDO_UID`/`SUDO_GID` automatically. For reports created by an
interactive `make dev-container` session, run:

```sh
make fix-permissions
```

The underlying command is `go -C toolchain run ./fix-permissions`; it accepts
`--path` to select another tree and `--dry-run` to print the affected paths.

## Security

The agent is root-equivalent: it loads eBPF programs and traces processes.
Run it only in disposable CTF/CI sandboxes. The unix socket is created with
mode 0600 and the agent does not open a network listener by default.

## Known deployment limits

- Rootless podman cannot work with `unprivileged_bpf_disabled=2`.
- The container must expose host BTF for kernel-side CO-RE or tracepoint
  structs.
- Containers in a different PID namespace need PID translation; the agent
  reads `NSpid` from `/proc/<pid>/status`.
- Target libraries are resolved through `/proc/<pid>/root/...`.
- Host `sysctl` changes are not required for the provided toolchain commands.
