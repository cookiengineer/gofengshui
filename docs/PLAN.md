# Go Heap FengShui — Remaining Plan

## Goal

Build a target-process heap anomaly detector on top of the existing eBPF and
ptrace foundation. The detector learns what normal allocation behavior looks
like for a workload, watches allocation histograms and sampled chunk content
over time, and correlates deviations with the structural heap detectors.

This is behavioral exploit detection, not vulnerability discovery. The scope is
one traced process, including followed threads and fork/exec children. Host-wide
monitoring is out of scope.

This document covers the remaining design and tuning work.

## Baseline Robustness

The current baseline uses median/MAD. Remaining work:

- add EWMA/EWMV state for gradual drift and sustained-change scoring
- add per-class quantile bands, especially for classes with sparse or zero MAD
- add Dirichlet/Laplace smoothing for low-count classes
- reduce confidence explicitly when ringbuf drops or sparse stack sampling make
  a window unreliable

## Scoring Extensions

Remaining signals to evaluate or add:

- Wasserstein distance on ordered size buckets
- tcache depth oscillation and saturation
- per-class quantile-band deviations
- re-tune weights, thresholds and content cadence only against measured matrix
  deltas

Keep the existing constraint that D10 requires composition, content or
structural evidence; rate/count/reuse drift alone must not be promoted to a
finding. Histogram divergence stays disabled below 32 live chunks, and content
metrics keep their scale floors.

## Validation and Coverage

- Confirm the default `sudo -E make e2e` suite is green after the opt-in gating
  changes.
- Extend the anomaly matrix so the short benign fixtures
  (`realloc_churn`, `arena_backfill`, `dlopen_alloc`, `cxx_alloc`) can produce
  scorable windows without weakening the FPR gate.
- Add a D11 escalation case that reliably correlates a suspicious phase with
  control flow.
- Use the opt-in old-glibc matrix when container apt network access is
  available.
- Implement musl allocator tracing separately; the musl suite is opt-in until
  `ld-musl-*` detection and allocator handling exist.

## Constraints

- Detection is opt-in. The default session behavior is unchanged.
- Findings and reports only. The detector does not kill or pause the target;
  content sampling briefly pauses it to read memory.
- D10 is a timeline anomaly. Single-event primitives are covered by the
  structural detectors.
- D11 is probabilistic correlation, not proof of exploitation.
- A stored baseline is ignored when its executable/profile key does not match,
  with fallback to warmup.
- The agent is root-equivalent and belongs in a sandboxed environment.

## Testing

See `docs/TESTING.md` for the test tiers, anomaly matrix, opt-in suites,
environment variables, logs, disk cleanup and failure triage. See
`docs/TASKS.md` for the open-task list.
