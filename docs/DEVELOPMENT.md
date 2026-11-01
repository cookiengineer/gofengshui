# Development and Testing Workflow

The canonical test commands, matrices, environment variables, logs and failure
triage live in [`TESTING.md`](TESTING.md). This document focuses on the
development loop and the e2e harness internals.

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

Host and eBPF diagnostics are read-only:

```sh
make check-env
go -C e2e-tests run ./cmd/hostinfo -json
```

The developer toolchain lives in `toolchain/`. `make test` runs its unit tests,
and `make toolchain` builds the commands into `build/toolchain/`.

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

## Anomaly development loop

The anomaly detector can be tuned without root by replaying captured events:

```sh
./build/gofengshui analyze \
  --events build/reports/case/events.jsonl \
  --out build/reports/case-analysis \
  --window-events 128 \
  --anomaly-warmup 20
```

Capture `events.jsonl` from a live `run` or use a scenario file under
`build/e2e/<run>/<case>/reports/`. The command writes `timeline.jsonl`,
`anomalies.json`, `baseline-model.json` and `analysis.json`.
`anomalies.json` contains every scored window, while D10 emission additionally
requires histogram, structural or content evidence. Rate/count/reuse drift
alone is visible in the score but is intentionally not promoted to a finding.

Offline replay has no content samples and no structural findings, so it is best
for histogram, rate, count and reuse tuning. Use the live anomaly matrix for
content and structural cases.

Useful tuning flags:

```text
--window-events, --window-ms, --max-windows
--anomaly-warmup, --anomaly-threshold, --anomaly-high-threshold
--baseline-in, --baseline-out
--anomaly=false        # timeline only
```

For live runs, `--anomaly`, `--content-sample`, `--content-sample-ms`,
`--content-sample-chunks` and `--content-sample-bytes` control the same path.
Content sampling pauses the target briefly and is skipped while a ROP/hijack
trace is active. Fast targets can finish warmup before the first content tick;
the first post-warmup summary then seeds a one-sample content baseline. Content
scoring uses scale floors (0.5 entropy, 0.1 ratios) so that a one-sample
baseline does not turn benign variation into `z=10`.

## Privileged e2e loop

The developer runs:

```sh
sudo -E make e2e
```

The suite is a separate Go module in `e2e-tests/`. It must run as root because
rootful podman is required on hosts with `unprivileged_bpf_disabled=2`, and the
Go harness invokes `podman` directly without per-command `sudo`.

The default suite uses only the `ubuntu:24.04` image (pull it once with
`GFS_E2E_PULL=1` if it is missing). It runs the glibc detectors, the focused
anomaly case and the anomaly validation matrix. `TestGlibcMatrix` and
`TestMusl` are opt-in so the default run does not depend on old distro archives
or incomplete musl tracing.

Focused anomaly commands:

```sh
sudo -E make e2e-anomaly          # TestGlibcAnomaly only
sudo -E make e2e-anomaly-matrix   # benign FPR + exploit latency + overhead
```

Opt-in suites:

```sh
sudo -E make e2e-glibc-matrix     # debian:11-slim / debian:12-slim
sudo -E make e2e-musl             # Alpine
```

`make e2e-glibc-matrix` sets `GFS_E2E_GLIBC_MATRIX=1` and `GFS_E2E_PULL=1`;
it needs apt network access from the build containers. `make e2e-musl` sets
`GFS_E2E_MUSL=1`; it currently fails before the anomaly layer because
`symbols.LibcPath` does not recognize `ld-musl-*`.

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

The opt-in glibc matrix uses the slim `debian:11-slim` (2.31, no safe-linking)
and `debian:12-slim` (2.36, safe-linking) images and runs the full glibc victim
suite, including concurrency, protocol, ROP and OOM, plus the host-side report
assertions. Matrix cases skip early when their base image is not available
locally; set `GFS_E2E_PULL=1` to pull it. The default glibc case uses
`ubuntu:24.04`.

The anomaly validation matrix (`glibc-anomaly-matrix`) uses `ubuntu:24.04` and
writes `anomaly-benign.json`, `anomaly-exploit.json` and
`anomaly-overhead.json`. Its host verifier enforces FPR `0` on scorable benign
runs and requires the `groom` positive control to emit D10.

The opt-in musl case uses Alpine and covers allocation tracing, D1/D2/D4/D6,
threads, fork/exec and the unix-socket protocol. Glibc-only tcache/metadata
checks are intentionally not asserted for musl. It currently fails because musl
libc detection is missing; see `docs/TASKS.md`. The OOM case runs with
`memory.oom.group=0` so only the bounded victim is killed.

## Environment variables

- `GFS_SKIP_BUILD=1` reuses the existing agent binary and case images.
- `GFS_BPF_LOG=1` includes the eBPF verifier log (default in the harness).
- `GFS_MEMORY_LIMIT` sets the container memory limit (default `2g`).
- `GFS_E2E_KEEP=1` keeps the test container after the test for inspection.
- `GFS_E2E_PULL=1` allows podman to pull missing base images.
- `GFS_E2E_GLIBC_MATRIX=1` enables the old-glibc matrix.
- `GFS_E2E_MUSL=1` enables the musl suite.
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
      timeline.jsonl
      anomalies.json
      baseline-model.json
    anomaly-benign.json
    anomaly-exploit.json
    anomaly-overhead.json
```

The anomaly files are written when the corresponding feature is enabled and
has data. The focused `anomaly_groom` case uses
`--anomaly-warmup 4 --anomaly-window-events 64 --content-sample`. The validation
matrix uses `--anomaly-warmup 8 --anomaly-window-events 256
--anomaly-window-ms 250 --content-sample-ms 250`.

The container closes with status 0 only when both the victim subtests and the
host report assertions pass. `go test -v` streams the victim output; the full
victim stdout and stderr are also written to the case log directory. The
default run ends with `ok gofengshui/e2e/glibc` and the internal harness
packages; the opt-in matrix and musl suites add their own package results.

A successful default run ends with `ok gofengshui/e2e/glibc` and the internal
harness packages. The opt-in `e2e-glibc-matrix` and `e2e-musl` targets add
their own package results.

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
  For interactive containers, run `make fix-permissions`.
- Stale containers: `sudo -E make e2e-clean`.
- Stale image after changing Go or C sources: rerun without
  `GFS_SKIP_BUILD=1`.
- Matrix or musl case skipped: both are opt-in. Use `make e2e-glibc-matrix` or
  `make e2e-musl`, or set `GFS_E2E_GLIBC_MATRIX=1` / `GFS_E2E_MUSL=1`.
- Matrix image build fails on apt signatures or timeouts: the build containers
  cannot reach the distro archives. The default suite avoids this by using the
  local `ubuntu:24.04` image.
- Disk pressure: `sudo -E make e2e-clean` removes e2e containers, images, build
  cache, `build/e2e` and `build/reports`.
- `no tests to run`: host tests use `//go:build !victim`, while
  `victim_test.go` is only compiled with `-tags victim`. If the victim subtest
  name appears only in `victim_test.go`, add or run a host-side wrapper; the
  anomaly case uses host `TestGlibcAnomaly` plus victim
  `TestGlibcAnomaly`.
- Anomaly case fails before D10: inspect `reports/anomaly/timeline.jsonl` and
  `anomalies.json` for raw scores and components. Check that the baseline was
  learned before the spray and that the fixture ran long enough for content
  sampling if content scoring is expected.
