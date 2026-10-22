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
scripts below.

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

The archive contains the binary, `docs/`, and `deploy/`. Override the version
with `make dist VERSION=0.2.0`. Inspect the embedded metadata with:

```sh
gofengshui version
gofengshui version --json
```

## Check the host

```sh
deploy/check-env.sh
```

This is read-only and can run as the normal user.

## Build the test image

```sh
deploy/build-image.sh
```

This runs `make build`, `make test-c`, and `sudo podman build`. The image is
built in rootful podman storage because the privileged runner uses rootful
podman; rootless and rootful podman have separate image stores.

## Run the privileged development container

```sh
deploy/dev-container.sh
```

This executes:

```sh
sudo podman run --rm -it \
  --privileged \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD/build/reports:/reports:Z" \
  localhost/gofengshui:dev
```

Or run the integration suite non-interactively:

```sh
deploy/run-integration.sh
```

The host script rebuilds the binary, test PoCs, and rootful container image
before running, unless `GFS_SKIP_BUILD=1` is set. The integration container is
memory-limited (`GFS_MEMORY_LIMIT`, default `2g`) so the OOM tracepoint test has
a bounded cgroup to trigger against. It writes a timestamped log
to `build/logs/integration-*.log` and updates `build/logs/latest.log`. The
container writes its own copy to `build/reports/integration.log`. Both include
the eBPF verifier log when a program fails to load (`GFS_BPF_LOG=1`).

The script also validates the allocator-profile reports on the host and fails
the run if the detected profile or the `--glibc-version 2.31` override is
missing. See `docs/DEVELOPMENT.md` for the unprivileged/privileged handoff,
log locations, and failure triage.

Inside the container, the same suite is:

```sh
/usr/local/bin/gfs-tests
```

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

## Host-privileged agent

```sh
deploy/host-agent.sh
```

Runs `gofengshui agent` in a privileged container with `--pid=host`, sharing
`build/run` as `/run/gofengshui`. From the host:

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

The privileged container runs as root, so `build/reports/` is created with
root ownership. `deploy/run-integration.sh` removes old reports and restores
ownership automatically. For reports created by an interactive
`deploy/dev-container.sh` session, run:

```sh
deploy/fix-permissions.sh
```

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
- Host `sysctl` changes are not required for the provided scripts.
