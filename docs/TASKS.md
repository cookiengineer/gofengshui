# Task Tracking

Status legend: `todo`, `in_progress`, `blocked`.

This file tracks only open anomaly-detection work. Completed work is in the git
history. Implemented behavior is described in `README.md`; test commands and
recorded measurements are in `docs/TESTING.md`.

## Open Work

### Baseline and scoring

| # | Task | Status |
|---|---|---|
| 2.10 | Add EWMA/EWMV and per-class quantile bands to the baseline | todo |
| 2.11 | Add Dirichlet/Laplace smoothing for sparse class distributions | todo |
| 2.12 | Add confidence reduction for ringbuf drops and sparse stack sampling | todo |
| 2.13 | Evaluate Wasserstein distance and tcache-pressure scoring | todo |

### Validation and coverage

| # | Task | Status |
|---|---|---|
| 5.6 | Confirm the default privileged `sudo -E make e2e` run is green after opt-in gating | todo |
| 5.12 | Make the short benign fixtures scorable in the anomaly matrix | todo |
| 5.13 | Add a reliable D11 escalation case | todo |
| 5.14 | Re-tune thresholds and content cadence against matrix deltas | todo |

### Blocked

| # | Task | Status |
|---|---|---|
| 5.15 | Implement musl allocator tracing (`ld-musl-*` detection and allocator model) | blocked |
| 5.16 | Get container apt network access for the opt-in old-glibc matrix | blocked |

## Known Gaps

- The baseline uses median/MAD only. EWMA, per-class quantile bands,
  sparse-class smoothing and drop/stack confidence reduction are not
  implemented.
- The anomaly matrix has 8 scorable benign runs. `realloc_churn`,
  `arena_backfill`, `dlopen_alloc` and `cxx_alloc` produce too few windows at
  the matrix configuration and are reported as non-scorable.
- D10 is a timeline anomaly. Single-event primitives such as metadata
  corruption, double free and crash are covered by D8, D1 and D6 and are not
  expected to emit D10. D11 escalation is not reliably exercised by the current
  matrix.
- The old-glibc matrix is opt-in and uses `debian:11-slim` / `debian:12-slim`.
  Its image builds need apt network access from the build containers.
- The musl suite is opt-in and currently fails before the anomaly layer because
  `symbols.LibcPath` does not recognize `ld-musl-x86_64.so.1`.
- The default privileged e2e suite has not yet had a final green run after the
  opt-in gating changes.

## Verification

Test tiers, commands, logs, report layout, disk cleanup and failure triage are
documented in `docs/TESTING.md`. Unprivileged checks are expected before any
privileged run; privileged runs require rootful podman and `sudo -E`.
