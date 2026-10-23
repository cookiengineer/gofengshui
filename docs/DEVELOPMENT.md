# Development and Testing Workflow

## Privilege boundary

The normal development loop is unprivileged. Loading eBPF requires `CAP_BPF`
and `CAP_PERFMON`, and this host has `unprivileged_bpf_disabled=2`, so the
privileged e2e suite must be executed as root by the human developer.

The intended handoff is:

1. The agent prepares changes and runs the unprivileged checks.
2. The developer runs `sudo -E make e2e`.
3. The agent reads the latest e2e log under `build/logs/` and the per-test
   artifacts under `build/e2e/`, then continues from the result.

The agent does not need interactive `sudo` access; it needs the log files.

## Fast local loop

Run these before asking for a privileged run:

```sh
make generate    # clang -> BPF object, regenerate embedded Go object
make fmt
make test        # Go unit tests
make vet
make test-c      # build C PoCs in build/testdata
make build       # static build/gofengshui
make bench       # heap-model benchmarks with allocation stats
make dist        # versioned release tarball + sha256
```

The e2e module also has unprivileged unit tests for the harness itself:

```sh
go -C e2e-tests test ./internal/...
```

Stack capture can be sampled on busy targets:

```sh
gofengshui run --sample-stacks 4 -- ./target
```

Useful diagnostic runs that do not require BPF privileges:

```sh
./build/gofengshui run --no-ebpf -- build/testdata/alloc_loop
./build/gofengshui run --no-ebpf --glibc-version 2.31 -- build/testdata/alloc_loop
```

These exercise ptrace, allocator profile detection, and the CLI. They do not
produce allocator or syscall events. The unprivileged Go suite also covers a
live allocation-ID hardware watchpoint (`TestWatchAllocationByIDLive`).

## Privileged e2e loop

The developer runs:

```sh
sudo -E make e2e
```

The suite is a separate Go module in `e2e-tests/`. It must run as root because
rootful podman is required on hosts with `unprivileged_bpf_disabled=2`, and the
Go harness invokes `podman` directly without per-command `sudo`.

`make e2e`:

- checks that the invoking user is root and fails with
  `sudo -E make e2e` otherwise
- runs `go -C e2e-tests test -count=1 -p 1 -timeout=60m -v ./...`
- writes a timestamped log to `build/logs/e2e-*.log`
- updates the `build/logs/latest-e2e.log` symlink
- restores ownership of `build/e2e`, `build/logs`, `build/gofengshui`,
  `build/bpf`, and `source/ebpf/object_generated.go` to the invoking
  `SUDO_UID`/`SUDO_GID`

Each case has its own directory:

```text
e2e-tests/
  glibc/
    Containerfile
    glibc_test.go      # //go:build !victim; podman orchestration
    victim_test.go     # //go:build victim; runs inside the container
  musl/
    Containerfile
    musl_test.go
    victim_test.go
  internal/harness/    # root guard, podman, images, logs, command tracing
  internal/checks/     # JSON/JSONL/report assertions
  internal/agentrun/   # agent, fixture, and protocol helpers
```

The host test builds the case image, compiles the victim test binary with:

```sh
CGO_ENABLED=0 go -C e2e-tests test -c -tags victim \
  -o build/e2e/<run>/<case>/glibc.victim.test ./glibc
```

then copies it into the container as `/opt/gfs/e2e/gofengshui` and runs it with
`podman exec ... -test.v`. The victim test invokes `gofengshui` and the C
fixtures inside the container. The binary name deliberately matches the agent's
`comm` so the agent's existing self-event filter drops the Go test process's own
syscalls. Host-side report assertions run in a separate subtest, so they still
execute when an individual victim scenario fails.

The glibc case runs a base-image matrix (`ubuntu:20.04`, `ubuntu:22.04`,
`debian:12`) against the full glibc victim suite, including concurrency,
protocol, ROP, and OOM, plus the host-side report assertions. Matrix cases skip
early when their base image is not available locally; the default glibc case
fails fast with a pull hint. Set `GFS_E2E_PULL=1` to allow podman to pull
missing base images. The musl case uses Alpine and currently covers allocation
tracing, D1/D2/D4/D6, threads, fork/exec, and the unix-socket protocol.
Glibc-only tcache/metadata checks are intentionally not asserted for musl. The
OOM case runs with `memory.oom.group=0` so only the bounded victim is killed.

## Environment variables

- `GFS_SKIP_BUILD=1` reuses the existing agent binary and case images.
- `GFS_BPF_LOG=1` includes the eBPF verifier log (default in the harness).
- `GFS_MEMORY_LIMIT` sets the container memory limit (default `2g`).
- `GFS_E2E_KEEP=1` keeps the test container after the test for inspection.
- `GFS_E2E_PULL=1` allows podman to pull missing base images.
- `GFS_IMAGE_PREFIX` overrides the image prefix.
- `GFS_IMAGE_TAG` overrides the per-case image tag.
- `GFS_REPO_ROOT` overrides repository-root discovery for the harness.

## Reading results

The latest host log is always:

```sh
build/logs/latest-e2e.log
```

Per-test artifacts live under:

```text
build/e2e/<timestamp>-<pid>/<case>/
  run.json
  logs/
    host.log
    commands.log
    <step>.stdout
    <step>.stderr
    container.json
  reports/
    <scenario>.events.jsonl
    <scenario>.stderr
    <scenario>/
      heap.json
      report.md
      summary.json
      rop.json
```

The container closes with status 0 only when both the victim subtests and the
host report assertions pass. `go test -v` streams the victim output; the full
victim stdout and stderr are also written to the case log directory.

A successful run ends with `ok gofengshui/e2e/glibc`, `ok
gofengshui/e2e/musl`, and the internal harness packages.

## Adding a container case

1. Create `e2e-tests/<name>/`.
2. Add a `Containerfile` that builds the case fixtures with the correct
   toolchain and copies the host-built `build/gofengshui`.
3. Add `doc.go` as a package anchor.
4. Add `<name>_test.go` with `//go:build !victim` for podman orchestration.
5. Add `victim_test.go` with `//go:build victim` for in-container scenarios.
6. Reuse `internal/harness`, `internal/checks`, and `internal/agentrun`.

Keep victim subtests sequential. eBPF, ptrace, and `/tmp` handshake files are
process-global, and the OOM test imposes a container memory limit.

## Failure triage

- `e2e tests must run as root`: run `sudo -E make e2e`.
- Image build failure: inspect `logs/podman-build.stderr` and
  `logs/podman-build.stdout`; confirm BTF is available.
- Missing reports: inspect the victim subtest output and the corresponding
  `reports/` directory.
- Root-owned artifacts: the `make e2e` target restores ownership after the run.
  For interactive containers, run `deploy/fix-permissions.sh`.
- Stale containers: `sudo -E make e2e-clean`.
- Stale image after changing Go or C sources: rerun without
  `GFS_SKIP_BUILD=1`.
- Matrix or musl case skipped: the base image is not local. Set
  `GFS_E2E_PULL=1` or pre-pull the image.
