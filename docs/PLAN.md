# Go Heap FengShui — Plan

## Goal

Build a target-process heap anomaly detector on top of the existing eBPF and
ptrace foundation. The detector learns what normal allocation behavior looks
like for a workload, watches allocation histograms and sampled chunk content
over time, and correlates deviations with the structural heap detectors.

This is behavioral exploit detection, not vulnerability discovery. It detects
activity consistent with active heap exploitation:

- grooming and spray patterns
- repeated address reuse and same-size free/alloc cycles
- tcache saturation and poisoning-like behavior
- allocator metadata corruption
- control-flow hijack and crash sequences

The target scope is one traced process (including followed threads and
fork/exec children). Host-wide monitoring is out of scope for this plan.

## Existing Foundation

The repository already provides the event pipeline and structural detectors:

- eBPF allocator and syscall tracing, ringbuf decoding, stack sampling
- `core.Event` and `core.Allocation` domain types
- `heap.Model` with allocation timeline, tombstones, reuse tracking and
  glibc profiles
- structural detectors D1–D9
- point-in-time heap analysis, baseline snapshots, diffs and recipes
- live tcache/arena introspection and free-list prediction
- ptrace pause/resume, breakpoints, watchpoints, registers and memory reads
- session protocol, JSONL export and report generation

The new work is the time-series layer, content sampling, baseline learning,
anomaly scoring and phase correlation.

## Architecture

```text
eBPF / ptrace events
        |
        v
heap.Model (existing) ---> detect.Engine (existing D1-D9)
        |                         |
        +--> Timeline collector --+--> Anomaly scorer --> D10/D11 findings
                 |                                       |
                 +--> content sampler (pause + ReadMemory)
                 |
                 +--> protocol / export / report
```

The existing `Analyze()` snapshot semantics stay unchanged. The timeline is a
separate, bounded time-series layer.

## Timeline Collector

The collector is fed from the live session pump and from offline event replay.
It must be incremental: no full heap scan per event.

Configuration defaults:

- close a window after 1,000 events or 250 ms, whichever comes first
- retain 4,096 completed windows
- update counters in O(1) per event

Each window records:

- exact chunk-size classes up to `0x410`, then log2 buckets
- live/freed counts, bytes and normalized shares per class
- alloc/free/realloc/churn rates per second
- per-thread histograms and call-site (`StackID`) allocation counts
- address reuse counts, including same-address/same-size cycles
- mmap/brk/munmap activity and allocation failures
- tcache occupancy when cached introspection is available
- structural finding counts and BPF drop/sampling confidence

Realloc semantics mirror the heap model: in-place reallocs preserve the live
chunk and adjust its class; moving reallocs free the old chunk and allocate the
new one.

## Sampled Content Analysis

Content sampling is optional and bounded. It never runs on every event.

Defaults:

- at most once per second, or every N windows
- skip while a ROP/hijack trace is active
- pause with the same safe pattern used by allocator introspection
- resume only threads the sampler stopped
- budget: 64 chunks x 256 bytes per checkpoint

Sample selection is stratified by size class and prioritizes anomalous classes,
recently freed chunks and realloc candidates.

Aggregate metrics only, by default:

- byte-value Shannon entropy
- printable-byte ratio
- pointer-like qword density against known mappings
- zero-byte ratio
- most-common-qword / repeated-qword frequency

Raw chunk bytes are not exported unless an explicit debug option is added
later.

## Baseline Model

The baseline supports both per-run warmup and stored benign baselines.

- warmup: learn after the first N windows (default 20)
- optional restart after a phase `mark`
- stored baseline keyed by executable hash + libc profile + optional phase
- advisory only when the executable, libc profile or thread shape differs

Use robust statistics:

- median + MAD per class, rate metric and content metric
- EWMA/EWMV for gradual drift
- per-class quantile bands
- Dirichlet/Laplace smoothing for low-count classes
- explicit confidence reduction for ringbuf drops or sparse stack sampling

## Anomaly Scoring

For each window compare:

- short window vs previous window: sudden grooming/spray
- short window vs long EWMA baseline: sustained change
- current window vs stored baseline: abnormal workload behavior
- phase vs previous phase: marker-aligned comparison

Signals:

- Jensen-Shannon divergence on normalized class histograms
- Wasserstein distance on ordered size buckets
- robust z-scores for alloc/free/churn/reuse rates
- Shannon entropy of the class distribution
- tcache depth oscillation and saturation
- content entropy/pointer-density deviations
- D7/D8/D9 findings as structural evidence

Score composition:

```text
score = histogram_divergence
      + rate_deviation
      + concentration_anomaly
      + reuse_anomaly
      + tcache_pressure
      + content_anomaly
      + structural_signal_bonus
```

Change-point detection (CUSUM or Bayesian online change-point) marks the start
of a suspicious phase.

## Phase Correlation

```text
NORMAL -> SUSPECT -> PRIMITIVE -> CONTROL-FLOW
```

- `SUSPECT`: score above threshold.
- `PRIMITIVE`: anomaly plus repeated reuse, same-class free/alloc cycles,
  tcache saturation, or a D7/D8/D9 finding.
- `CONTROL-FLOW`: D5/D6/ROP or hijack-watch hit.

Findings:

- `D10` heap timeline anomaly: info/medium/high, with window ID, metrics,
  baseline key and contributing signals.
- `D11` exploit-phase correlation: high/critical only when independent signals
  agree.

Timeline findings use window-scoped deduplication keys.

## Protocol, CLI and Export

Protocol additions:

- `heap.timeline`
- `heap.anomaly`
- `heap.baseline` gains `mode: snapshot | learn` and `warmup_windows`

CLI flags:

- `--anomaly`
- `--anomaly-window-ms`
- `--anomaly-window-events`
- `--anomaly-warmup`
- `--baseline-in PATH`
- `--baseline-out PATH`
- `--content-sample`
- `--content-sample-budget`

Offline analysis:

```sh
gofengshui analyze --events events.jsonl --baseline-in benign.json --out analysis/
```

Exports:

- `timeline.jsonl`
- `baseline-model.json`
- `anomalies.json`
- a heap timeline section in `report.md`

## Implementation Phases

### Phase 0 — Timeline schema and offline replay

- window and histogram types
- incremental collector and replay from `[]core.Event`
- offline event-frame parser
- synthetic unit tests

Acceptance: stable histograms and window boundaries from replayed events.

### Phase 1 — Live timeline, protocol and export

- feed the collector from the live session pump
- `heap.timeline` protocol method
- `timeline.jsonl` and `heap.json` integration
- live tests and benchmarks

Acceptance: live windows are queryable and exported without ringbuf drops.

### Phase 2 — Baseline learning and D10

- warmup and stored baseline model
- robust statistics, histogram divergence and rate z-scores
- D10 findings with window-scoped dedup
- CLI flags and report section

Acceptance: benign fixtures stay below threshold; concentration and grooming
fixtures trigger D10.

### Phase 3 — Sampled content analysis

- safe periodic pause/sample/resume path
- stratified chunk selection and aggregate content metrics
- content baseline and scoring integration

Acceptance: synthetic high-entropy and patterned buffers classify correctly;
sampling overhead remains bounded.

### Phase 4 — D11 phase correlation

- phase state machine
- correlation with D5/D6/D7/D8/D9 and ROP results
- severity and evidence aggregation

Acceptance: exploit fixtures trigger D11; benign fixtures do not.

### Phase 5 — Validation and tuning

- offline replay and threshold calibration
- benign versus exploit fixture matrix
- detection latency, false-positive rate and overhead measurements
- docs and CI expectations

## Current Status

As of 2026-10-31:

- Phases 0-4 are implemented.
- Phase 2.1 is partial: the baseline uses median/MAD but not EWMA or per-class
  quantile bands.
- Phase 5 is partial: offline analysis, a privileged anomaly e2e case, docs and
  report assertions are in place; the full regression, benign false-positive
  matrix, exploit detection-latency matrix and overhead measurements are not.
- The privileged `sudo -E make e2e-anomaly` case passes. It emits D10 on the
  `anomaly_groom` fixture and validates the timeline/anomaly/baseline exports.
- Fast targets can finish warmup before the first content-sampling tick, so the
  content baseline can be empty in short runs.

See `docs/TASKS.md` for task-level status and `HANDOVER.md` for the next
session checklist.

## Next Work

1. Run the full privileged regression: `sudo -E make e2e`.
2. Run the complete benign and exploit fixture matrices and record
   false-positive rate and detection latency.
3. Use the measurements to tune D10 thresholds and the content-sampling cadence.
4. Add EWMA and per-class quantile bands.
5. Ensure content is sampled during warmup on fast targets.
6. Measure timeline and content-sampling overhead.

## Validation

Benign fixtures:

- `alloc_loop`, `realloc_churn`, `threads`, `attach_threads`
- `dlopen_alloc`, `cxx_alloc`, `arena_backfill`

Exploit fixtures:

- `poison`, `metadata`, `size_swap`, `uaf_direct`
- `overflow`, `double_free`, `rop_sink`

Content fixtures:

- synthetic buffers with known entropy, pointer density and repeated qwords

Regression checks:

- existing D1–D9 behavior stays unchanged
- BPF drop accounting remains zero on the privileged suite
- no new false positives on the clean fixture

## Risks and Limits

- Workload-dependent allocation patterns make false positives the main risk;
  a learned or stored baseline is required for high confidence.
- Content sampling adds pauses and must not disrupt active ROP traces or
  watchpoints.
- Ringbuf drops and sampled stacks reduce confidence; scores must account for
  them.
- Heap anomalies can also come from benign phases such as startup, cache warmup
  or batch jobs; phase markers and warmup windows mitigate this.
- `D10`/`D11` are probabilistic evidence. They do not prove an unknown
  vulnerability exists.
- The agent remains root-equivalent and belongs in a sandboxed environment.
