# Development and Testing Workflow

## Privilege boundary

The normal development loop is unprivileged. Loading eBPF requires `CAP_BPF`
and `CAP_PERFMON`, and this host has `unprivileged_bpf_disabled=2`, so the
privileged integration suite is executed by the human developer.

The intended handoff is:

1. The agent prepares changes and runs the unprivileged checks.
2. The developer runs `deploy/run-integration.sh`.
3. The agent reads `build/logs/latest.log` and the reports under
   `build/reports/` and continues from the result.

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

## Privileged integration loop

The developer runs:

```sh
deploy/run-integration.sh
```

The script:

- removes old reports and restores report ownership through `sudo`
- rebuilds the binary, C PoCs, and rootful container image unless
  `GFS_SKIP_BUILD=1` is set
- runs `deploy/in-container-tests.sh` as `/usr/local/bin/gfs-tests` in a
  privileged container with host BTF mounted
- writes the host log to `build/logs/integration-<timestamp>.log` and updates
  the `build/logs/latest.log` symlink
- writes the container log to `build/reports/integration.log`
- runs host-side assertions over the generated reports

Iterating without rebuilding the image:

```sh
GFS_SKIP_BUILD=1 deploy/run-integration.sh
```

Enabling the eBPF verifier log:

```sh
GFS_BPF_LOG=1 deploy/run-integration.sh
```

## What the suite verifies

In addition to D1–D4/D6/D7 and the ROP/sink flows, the suite now verifies the
allocator profile end-to-end:

- `poison` detects the container libc version from its metadata and records
  `source: libc-string`, `tcache: true`, and `safe_linking: true` in
  `heap.json`
- `--glibc-version 2.31` produces `version: 2.31`, `source: override`, and
  `safe_linking: false` in a second report. That check uses the `alloc_once`
  harness, because forcing a pre-safe-linking profile on a newer libc makes
  tcache-link decoding intentionally inconsistent.
- the stdio `session.status` result contains the active `profile` and BPF
  event/drop counters (`drops: 0`)
- `syscall_uaf` reports `D2` with access events for `openat` (257), `execve`
  (59), `sendfile` (40) and `splice` (275)
- `crash` reports `D6` with `fault=0x0 [null]`, `fault_region: null`,
  `fault_access: not-mapped` and a `stack_hits` list
- the stdio session exercises `heap.baseline`, `heap.diff` and `heap.recipe`
  and returns a diff plus a reclaim plan
- `realloc_churn` produces no false positives while exercising moving and
  in-place reallocs
- `arena_backfill` recovers allocations from non-main thread arenas during
  attach
- `metadata` corrupts a chunk size and triggers `D8` at free() entry
- `size_swap` replaces a size with a valid-looking value and triggers `D9`
- `uaf_direct` writes to a freed chunk without a syscall and triggers D2
  through `--watch-freed`
- `dlopen_alloc` loads a plugin, refreshes maps/probes, and allocates again
  after `maps.refresh`
- `cxx_alloc` allocates through libstdc++ and emits `new`/`delete` labelled
  events
- `deploy/run-integration.sh` re-checks these report fields on the host and
  fails the run if they are missing

## Reading results

The latest host log is always:

```sh
build/logs/latest.log
```

A successful run ends with:

```text
=== allocator profile assertions ===
ok: heap.json has detected profile
...
=== crash/syscall assertions ===
ok: D6 crash finding present
ok: openat buffer checked
...
=== finished: ... status=0 ===
```

Relevant report paths:

```text
build/reports/poison/heap.json
build/reports/profile-override/heap.json
build/reports/stdio.jsonl
build/reports/integration.log
```

If the container fails, start with `build/logs/latest.log`; the full eBPF
verifier output is included when `GFS_BPF_LOG=1`.

## Failure triage

- `permission denied` or verifier load failure: confirm the container is
  privileged and `/sys/kernel/btf` is mounted.
- Missing profile assertions: inspect `heap.json` and the
  `allocator=...` line in the run stderr file.
- Root-owned reports after an interactive container session:
  `deploy/fix-permissions.sh`.
- Stale image after changing Go or C sources: rerun without
  `GFS_SKIP_BUILD=1`.
