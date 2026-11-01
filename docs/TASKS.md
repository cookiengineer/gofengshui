# Task Tracking

Status legend: `todo`, `in_progress`, `partial`, `done`, `blocked`.

The existing D1–D9 detectors, heap model, introspection, prediction, protocol
and export pipeline are treated as the current foundation and are not re-listed
here. This file tracks the anomaly-detection work described in `docs/PLAN.md`.
See `HANDOVER.md` for the next-session checklist and verified evidence.

## Phase 0 — Timeline schema and offline replay

| # | Task | Status |
|---|---|---|
| 0.1 | Define `TimelineConfig`, window, class, thread, site, reuse and rate types | done |
| 0.2 | Implement incremental collector with event-count and time windows | done |
| 0.3 | Track live/freed class histograms and alloc/free/realloc semantics | done |
| 0.4 | Track per-thread and per-stack-site allocation summaries | done |
| 0.5 | Track address reuse including same-class reuse | done |
| 0.6 | Add `ReplayTimeline` from `[]core.Event` | done |
| 0.7 | Add offline parser for exported `events.jsonl` frames | done |
| 0.8 | Add synthetic unit tests for windows, histograms, realloc and reuse | done |

## Phase 1 — Live timeline, protocol and export

| # | Task | Status |
|---|---|---|
| 1.1 | Feed the collector from `detect.Engine` / live session pump | done |
| 1.2 | Add `heap.timeline` protocol method | done |
| 1.3 | Add `heap.timeline` to agent method discovery | done |
| 1.4 | Export `timeline.jsonl` and include timeline data in `heap.json` | done |
| 1.5 | Add live unit/integration tests and a benchmark | done |

## Phase 2 — Baseline learning and D10

| # | Task | Status |
|---|---|---|
| 2.1 | Add robust baseline model (median/MAD, EWMA, quantile bands) | partial |
| 2.2 | Support warmup learning and resetting via `heap.anomaly reset` | done |
| 2.3 | Support stored baseline load/save keyed by executable and profile | done |
| 2.4 | Implement histogram divergence and rate deviation scoring | done |
| 2.5 | Implement CUSUM change-point detection | done |
| 2.6 | Emit D10 findings from closed windows | done |
| 2.7 | Add `heap.anomaly` and baseline `learn` protocol extensions | done |
| 2.8 | Add CLI anomaly and baseline flags | done |
| 2.9 | Add D10 report section and `anomalies.json` / `baseline-model.json` export | done |
| 2.10 | Add EWMA and per-class quantile bands (2.1 currently has median/MAD only) | todo |

## Phase 3 — Sampled content analysis

| # | Task | Status |
|---|---|---|
| 3.1 | Add safe periodic pause/sample/resume path | done |
| 3.2 | Add stratified chunk selection and sampling budget | done |
| 3.3 | Compute entropy, printable, pointer-density and repeated-qword metrics | done |
| 3.4 | Add content baseline metrics and scoring | done |
| 3.5 | Add content sampling tests with synthetic buffers | done |
| 3.6 | Ensure fast targets collect content during warmup, not only after it | done |

## Phase 4 — D11 phase correlation

| # | Task | Status |
|---|---|---|
| 4.1 | Add NORMAL/SUSPECT/PRIMITIVE/CONTROL-FLOW state machine | done |
| 4.2 | Correlate anomalies with structural findings and D5/D6 | done |
| 4.3 | Emit D11 findings with evidence aggregation | done |
| 4.4 | Add phase fields and transition details to scores and findings | done |

## Phase 5 — Validation and tuning

| # | Task | Status |
|---|---|---|
| 5.1 | Add offline calibration workflow (`gofengshui analyze`) | done |
| 5.2 | Run benign fixture matrix and record false-positive rate | done |
| 5.3 | Run exploit fixture matrix and record detection latency | done |
| 5.4 | Measure collector and content-sampling overhead | done |
| 5.5 | Update `docs/PROTOCOL.md`, `README.md` and e2e expectations | done |
| 5.6 | Run the full privileged `sudo -E make e2e` regression | partial |
| 5.7 | Record benign false-positive and exploit detection-latency numbers | done |
| 5.8 | Add anomaly validation matrix harness (`e2e-anomaly-matrix`) | done |
| 5.9 | Skip histogram scoring below a minimum live-chunk count | done |
| 5.10 | Add content-metric scoring scale floors | done |
| 5.11 | Re-run full privileged e2e with base images available | todo |

## Known Gaps

- Phase 2.1 uses median/MAD but not EWMA or quantile bands yet.
- The benign matrix has 8 scorable runs and 0 false positives at
  `warmup=8`, `window-events=256`, `window-ms=250`. `realloc_churn`,
  `arena_backfill`, `dlopen_alloc` and `cxx_alloc` are not scorable at that
  window size because they produce too few events.
- `metadata`, `double_free` and `crash` do not produce D10 by design; D10 is a
  timeline anomaly and those single-event primitives are covered by D8, D1 and
  D6. D11 was not emitted by the current `control` fixture in the latest run.
- The full `sudo -E make e2e` regression still needs a run with the
  `ubuntu:20.04`, `ubuntu:22.04`, `debian:12` and `alpine:3.20` base images
  available (use `GFS_E2E_PULL=1`).

## Verification Notes

- Privileged e2e runs use the existing `e2e-tests` pipeline.
- Unprivileged work is validated with the `source` Go tests.
- Any new root-only test helper should live under `build/` or the e2e harness
  rather than ad-hoc shell commands.

## Progress Log

### 2026-10-31

- Rewrote `docs/PLAN.md` around the timeline/anomaly architecture and removed
  completed milestone history.
- Added `source/heap/timeline.go` with bounded event/time windows, class,
  thread, site, reuse and rate summaries.
- Added `source/analyze` for offline `events.jsonl` replay.
- Wired the timeline into `detect.Engine` and live sessions.
- Added `heap.timeline` protocol support and `timeline.jsonl` export.
- Added `gofengshui analyze` for offline replay.
- Verified with `go -C source test ./...`, `go -C source vet ./...`,
  `make build`, and `BenchmarkTimelineObserve`.
- Added live heap-state tracking across windows, so class `live`/`live_bytes`
  describe heap composition at window close rather than net window activity.
- Added robust baseline learning, Jensen-Shannon histogram divergence, rate,
  count, reuse and structural scoring, and CUSUM change-point tracking.
- Added D10 findings, `heap.anomaly`, `heap.baseline mode=learn`, baseline
  load/save, CLI flags, and anomaly/baseline export.
- Added sampled chunk-content analysis: class-stratified selection, entropy,
  printable/pointer/zero/repeated-qword metrics, content baseline scoring and
  periodic pause/sample/resume integration.
- Added the D11 phase state machine and correlation of suspicious timeline
  phases with control-flow findings.
- Verification includes unprivileged Go tests, `go vet`, `make build`,
  `make test-c`, the e2e harness unit tests, and the privileged anomaly case
  below.
- Added `anomaly_groom` fixture and `TestGlibcAnomaly`, which expects D10 plus
  `timeline.jsonl`, `anomalies.json` and `baseline-model.json`.
- `make e2e-anomaly` runs the privileged anomaly case. The host-side
  `TestGlibcAnomaly` limits the container victim run to the anomaly subtest and
  verifies D10 plus the timeline, anomaly and baseline exports.

### 2026-11-01

- Fixed 3.6 content warmup: timeline windows now signal the content sampler, and
  the anomaly tracker accumulates content summaries received before the baseline
  is built. If warmup closes without content, the first post-warmup summary
  seeds the empty content baseline once.
- Added `ContentBaselineFromSummaries` and reused it from `BuildBaseline`.
- Added `Timeline.Completed()` so the session pump can wake the sampler on
  window close without rescanning the window ring.
- Strengthened `TestGlibcAnomaly` to require a non-zero content baseline.
- Verification: `go -C source test ./...`, `go -C source vet ./...`,
  `make build`, `make test-c`, e2e internal tests, and host/victim compilation.
- `sudo -E make e2e-anomaly` passed, including the new content-baseline
  assertion. The learned baseline had `content.samples.count = 1` (16 chunks,
  entropy 0.615) instead of zero.
- Recorded the existing full e2e results: `TestGlibc` and `TestGlibcAnomaly`
  passed; `TestGlibcMatrix` and `TestMusl` skipped due to missing base images.

### Privileged anomaly run (2026-10-31)

`sudo -E make e2e-anomaly` passed:

- `TestGlibcAnomaly`, `TestGlibcAnomaly/victim` and
  `TestGlibcAnomaly/reports` all passed.
- D10 was emitted from the `anomaly_groom` fixture with a medium-severity
  `primitive` phase score of 13.63 (window 76).
- `timeline.jsonl`, `anomalies.json` and `baseline-model.json` were present and
  validated from the host side.
- Content sampling produced timeline content summaries with 16-32 sampled
  chunks, but the fast fixture completed warmup before the first content tick,
  so content did not contribute to the baseline in this run.

### 2026-11-01 — anomaly validation matrix

- Added `TestGlibcAnomalyMatrix` and the `e2e-anomaly-matrix` target. The
  matrix runs benign FPR, exploit latency and overhead subtests inside the
  privileged Ubuntu 24.04 container and writes `anomaly-benign.json`,
  `anomaly-exploit.json` and `anomaly-overhead.json`.
- Added warmup-prefixed fixtures `anomaly_benign.c`, `anomaly_exploit.c` and
  `anomaly_bench.c`; the existing exploit fixtures were too short to fill a
  timeline warmup.
- Measured pre-tuning FPR at `warmup=4/window=64`: 5/9 benign runs emitted D10.
  At `warmup=8/window=256`: 2/8 (`threads`, `attach_threads`).
- Added `AnomalyConfig.MinHistogramLive = 32`. Benign thread windows had only
  4-8 live chunks, so their class histograms were noise. Histogram scoring is
  now skipped below the minimum. Content metrics also use scale floors (0.5
  entropy, 0.1 ratios) so a one-sample baseline does not turn a small shift
  into `z=10`.
- Final privileged matrix: **FPR 0/8** scorable benign runs. `groom`,
  `poison`, `size_swap` and `control` emitted D10. Latency: `groom` 1 window /
  7 ms, `poison` 0 windows / <1 ms, `size_swap` 0 windows / <1 ms, `control`
  1 window / 6 ms. `metadata`, `double_free` and `crash` emitted their
  structural findings (D8/D1/D6) but no D10.
- Overhead medians over three runs: collector 2901 ms, scoring 2611 ms,
  content 2581 ms (target phase fixed at 1500 ms; differences are within
  run-to-run noise). Benchmarks: `BenchmarkTimelineObserve` 406 ns/op and
  `BenchmarkScoreWindow` 732 ns/op (16 cores, 4 allocs/op each).
- Verification: `go -C source test ./...`, `go -C source vet ./...`,
  `make build`, `make test-c`, e2e internal tests, host/victim compilation and
  `sudo -E make e2e-anomaly-matrix`. The matrix log is
  `build/logs/e2e-20261101-062541-42177.log`.
- Full `sudo -E make e2e` is still pending; it needs the root podman store to
  have the matrix/musl base images (`GFS_E2E_PULL=1`).
