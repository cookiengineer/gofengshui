# Testing

This is the canonical testing guide. It covers the unprivileged checks, the
privileged container suite, the anomaly validation matrix, opt-in matrices,
logs, environment variables and disk cleanup.

Related documents:

- `docs/DEVELOPMENT.md` — development loop and e2e harness internals
- `docs/TASKS.md` — open tasks and known gaps
- `docs/PLAN.md` — remaining design work

## Test tiers

| Tier | Command | Root | What it covers |
|---|---|---|---|
| Source unit tests | `make test` | no | BPF generation, toolchain tests, `go -C source test ./...` |
| Fixtures | `make test-c` | no | C/C++ PoCs in `build/testdata` |
| Vet | `make vet` | no | `go vet` for source and toolchain |
| Benchmarks | `make bench` | no | heap model, timeline collector and scoring |
| Harness unit tests | `go -C e2e-tests test ./internal/...` | no | podman/checks/agentrun helpers |
| Default e2e | `sudo -E make e2e` | yes | glibc detectors, anomaly, protocol, concurrency, ROP, OOM |
| Focused anomaly | `sudo -E make e2e-anomaly` | yes | `anomaly_groom` → D10 and exports |
| Anomaly matrix | `sudo -E make e2e-anomaly-matrix` | yes | benign FPR, exploit latency and overhead |
| Old-glibc matrix | `sudo -E make e2e-glibc-matrix` | yes | glibc 2.31 / 2.36 profiles (opt-in) |
| Musl suite | `sudo -E make e2e-musl` | yes | Alpine allocator tracing (opt-in, currently incomplete) |

## Unprivileged checks

Run these before asking for a privileged run:

```sh
make generate
make fmt
make test
make vet
make test-c
make build
make bench
go -C e2e-tests test ./internal/... -count=1
```

`make test` depends on BPF generation and the toolchain tests. If `clang` or the
BPF headers are unavailable, run the Go tests directly:

```sh
go -C source test ./... -count=1
go -C source vet ./...
```

Read-only host and eBPF diagnostics:

```sh
make check-env
go -C e2e-tests run ./cmd/hostinfo -json
```

Compile the container test binaries without running them:

```sh
go -C e2e-tests test -c -tags victim -o /tmp/opencode/glibc.victim.test ./glibc
go -C e2e-tests test -c -o /tmp/opencode/glibc.host.test ./glibc
go -C e2e-tests test -c -o /tmp/opencode/musl.host.test ./musl
```

The unprivileged Go suite also covers a live allocation-ID hardware watchpoint
(`TestWatchAllocationByIDLive`) and the deterministic parts of the timeline,
baseline and scoring logic.

## Privileged e2e suite

The container suite loads real eBPF and uses rootful podman, so it must run as
root:

```sh
sudo -E make e2e
```

The default suite uses the already-local `ubuntu:24.04` image. If it is not
present, run `sudo -E GFS_E2E_PULL=1 make e2e` once to pull it. It runs:

- `TestGlibc` — detectors, profiles, concurrency, protocol, ROP and OOM
- `TestGlibcAnomaly` — focused D10/anomaly exports on `anomaly_groom`
- `TestGlibcAnomalyMatrix` — benign FPR, exploit latency and overhead
- all `e2e-tests/internal/...` unit tests

`TestGlibcMatrix` and `TestMusl` are skipped by default; see the opt-in sections
below. Running `make e2e` without `sudo` exits at the root guard and does not
create a new log.

### What a run does

The harness:

1. builds `build/gofengshui` and a per-case container image
2. compiles the victim tests with `go test -c -tags victim`
3. starts one privileged container per case
4. copies the victim binary into the container and executes it
5. validates the exported reports from the host in a separate subtest

Reports are written even when an individual victim scenario fails, so host-side
assertions still run.

## Anomaly tests

### Focused case

```sh
sudo -E make e2e-anomaly
```

Runs `TestGlibcAnomaly` on `anomaly_groom` with:

```text
--anomaly --anomaly-warmup 4 --anomaly-window-events 64
--content-sample --content-sample-ms 50 --content-sample-chunks 16
```

It requires D10 and validates `timeline.jsonl`, `anomalies.json` and
`baseline-model.json`, including a non-empty content baseline.

### Validation matrix

```sh
sudo -E make e2e-anomaly-matrix
```

Runs on `ubuntu:24.04` with:

```text
--anomaly --anomaly-warmup 8 --anomaly-window-events 256
--anomaly-window-ms 250 --content-sample --content-sample-ms 250
--content-sample-chunks 16
```

It writes three files into the case reports directory:

- `anomaly-benign.json` — windows, scored windows, baseline presence, content
  samples, D10/D11 counts and max score per benign fixture
- `anomaly-exploit.json` — first D10 window, first structural window, latency
  in windows and milliseconds, and max score per exploit mode
- `anomaly-overhead.json` — collector, scoring and content-sampling wall times

The host verifier enforces:

- false-positive rate `0` across scorable benign runs
- at least four scorable benign runs
- the `groom` positive control emits D10
- every exploit mode emits its expected structural finding

Benign fixtures that produce too few windows are recorded as non-scorable
rather than treated as clean.

Recorded on 2026-11-01 (log `build/logs/e2e-20261101-062541-42177.log`):

- benign: 8 scorable runs, 0 D10, FPR `0.0`
- exploit D10: `groom` 7, `poison` 1, `size_swap` 1, `control` 6
- first-finding latency: `groom` 1 window / 7 ms, `poison` 0 / <1 ms,
  `size_swap` 0 / <1 ms, `control` 1 / 6 ms
- `metadata`, `double_free` and `crash` emit D8/D1/D6 but no D10; D10 is a
  timeline anomaly, not a single-event primitive detector
- overhead medians: collector 2901 ms, scoring 2611 ms, content 2581 ms over a
  fixed 1500 ms target phase; the differences are within run-to-run noise

### Offline calibration

Replay a captured event stream without root:

```sh
./build/gofengshui analyze \
  --events build/reports/case/events.jsonl \
  --out build/reports/case-analysis \
  --window-events 128 \
  --anomaly-warmup 20
```

This writes `timeline.jsonl`, `anomalies.json`, `baseline-model.json` and
`analysis.json`. Use `--anomaly=false` for timeline-only replay and
`--baseline-in` to score against a stored baseline. Offline replay does not
include content samples or structural findings, so it is best for histogram,
rate, count and reuse tuning.

## Opt-in matrices

### Old-glibc matrix

```sh
sudo -E make e2e-glibc-matrix
```

This runs `TestGlibcMatrix` against the smaller `debian:11-slim` (glibc 2.31)
and `debian:12-slim` (glibc 2.36) images instead of the large Ubuntu images.
It pulls missing images when `GFS_E2E_PULL=1` (set by the target) and needs apt
network access from the build containers.

The matrix is skipped by default so a normal e2e run does not depend on old
distro archives. If the build containers cannot reach `deb.debian.org`, the
image build fails before any test runs.

### Musl suite

```sh
sudo -E make e2e-musl
```

The musl suite is opt-in because allocator tracing does not yet recognize
Alpine's `ld-musl-x86_64.so.1`. `symbols.LibcPath` only matches `libc.so*` and
`libc-*`, so no allocator uprobes attach and allocator-based tests fail before
reaching anomaly logic. The Alpine image itself is small (`alpine:3.20`), so
this is not a disk-size concern.

## Environment variables

| Variable | Purpose |
|---|---|
| `GFS_SKIP_BUILD=1` | reuse the existing agent binary and case images |
| `GFS_BPF_LOG=1` | include eBPF verifier output (default in the harness) |
| `GFS_MEMORY_LIMIT` | container memory limit (default `2g`) |
| `GFS_E2E_KEEP=1` | keep the test container for inspection |
| `GFS_E2E_PULL=1` | allow pulling missing base images |
| `GFS_E2E_GLIBC_MATRIX=1` | enable the old-glibc matrix |
| `GFS_E2E_MUSL=1` | enable the musl suite |
| `GFS_IMAGE_PREFIX` | override the image prefix |
| `GFS_IMAGE_TAG` | override the per-case image tag |
| `GFS_REPO_ROOT` | override repository-root discovery |

## Logs and reports

The latest host log is always:

```text
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

`anomaly-benign.json`, `anomaly-exploit.json` and `anomaly-overhead.json` are
specific to the anomaly validation matrix. `anomaly_groom` is the dedicated D10
fixture for the focused case.

## Disk usage and cleanup

The e2e suite writes large report directories. To reclaim space:

```sh
sudo -E make e2e-clean
```

This removes:

- e2e containers labeled `gofengshui.e2e=1`
- e2e images under `localhost/gofengshui-e2e/`
- podman build cache
- `build/e2e` and `build/reports`

Base images are kept. Inspect the podman store with:

```sh
sudo podman system df
```

The default suite now uses only `ubuntu:24.04`. The old-glibc matrix uses two
slim Debian images and the musl suite uses one small Alpine image, so the
opt-in suites do not require pulling several large Ubuntu/Debian images.

## Failure triage

- `e2e tests must run as root`: run `sudo -E make e2e`.
- Image build failure: inspect `logs/podman-build.stderr` and
  `logs/podman-build.stdout`; confirm BTF is available and, for opt-in
  matrices, that the build containers can reach their apt archives.
- Missing reports: inspect the victim subtest output and the corresponding
  `reports/` directory.
- Root-owned artifacts: `make e2e` restores ownership after the run. For
  interactive containers, run `make fix-permissions`.
- Stale containers: `sudo -E make e2e-clean`.
- Stale image after changing Go or C sources: rerun without `GFS_SKIP_BUILD=1`.
- A matrix or musl case is skipped: it is opt-in by default. Use the dedicated
  target or set the corresponding environment variable.
- `no tests to run`: host tests use `//go:build !victim`, while
  `victim_test.go` is only compiled with `-tags victim`. Add or run a host-side
  wrapper.
- Anomaly case fails before D10: inspect `reports/anomaly/timeline.jsonl` and
  `anomalies.json` for raw scores and components. Check that the baseline was
  learned before the spray and that the fixture ran long enough for content
  sampling if content scoring is expected.
- Sparse-window scores look low: histogram divergence is skipped below 32 live
  chunks, and content metrics use scale floors. This is intentional; inspect
  the component breakdown before changing thresholds.

See `docs/DEVELOPMENT.md` for the harness internals and `docs/TASKS.md` for
known gaps and recorded measurements.
