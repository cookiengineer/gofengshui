# JSONL Protocol

The same versioned, newline-delimited JSON protocol runs over:

- stdio (`gofengshui stdio`, or `gofengshui run --jsonl -- <program>`)
- unix sockets (`gofengshui agent --socket <path>`)

stdout carries protocol frames only. Logs and target I/O go to stderr or
session files.

## Frame

```json
{"v":1,"type":"request","id":7,"method":"heap.query","params":{"addr":"0x555555..."}}
{"v":1,"type":"result","id":7,"result":{...}}
{"v":1,"type":"error","id":7,"error":{"code":"bad_params","message":"..."}}
{"v":1,"type":"event","session":"s1","seq":42,"event":{"kind":"finding","finding":{...}}}
```

Rules:

- `v` is the protocol version (`1`).
- Request IDs are chosen by the client. Responses echo the ID.
- Events may interleave with responses.
- `session` is required for session-bound requests. It may be sent as the
  frame field or inside `params.session`.
- Event sequence numbers are per session and monotonically increasing.

## Session lifecycle

```json
{"v":1,"type":"request","id":1,"method":"session.create","params":{
  "mode":"spawn",
  "path":"/opt/gfs/testdata/uaf",
  "args":["/opt/gfs/testdata/uaf"],
  "pause":false,
  "follow":false,
  "config":{"heap":true,"syscalls":true,"uaf":true,"stacks":true,"detectors":true,
            "no_libc":false,"no_ebpf":false,"glibc_version":"","watch_freed":false}
}}
```

Result:

```json
{"session":"s1a2b3c4d","target":{...},"config":{...},"paused":false}
```

`mode` is `spawn` or `attach`. Attach requires `pid`.

Close a session:

```json
{"method":"session.close","params":{"session":"s1","kill":true}}
```

`session.status` returns the active `profile`, heap `stats` and — when eBPF is
active — a `bpf` object with `events`, `drops`, `allocs`, `frees` and `checks`.
`drops` is the ring-buffer loss counter; a non-zero value means the userspace
consumer could not keep up.

## Events

`events.subscribe` attaches the connection to the live stream:

```json
{"method":"events.subscribe","params":{"session":"s1","since":0}}
```

Replay begins after `since`; live events follow. Event payloads:

```json
{"kind":"event","event":{"ts":"...","type":"alloc","addr":"0x...","size":32,...}}
{"kind":"finding","finding":{"id":"D2","severity":"high","message":"..."}}
{"kind":"stop","stop":{"tid":123,"reason":"breakpoint","regs":{...}}}
{"kind":"sink","sink":{"name":"gfs_sink","regs":{"rdi":16705}}}
{"kind":"rop","rop":{"verified":true,"steps":[...],"chain":[...]}}
{"kind":"marker","marker":"phase-2"}
```

Crash-like signal stops also carry `fault_addr`, `fault_code` (from
`PTRACE_GETSIGINFO`) and a `stack` word window captured before resuming the
target. The corresponding D6 finding reports `fault_region`
(`null`/`unmapped`/`mapped`), `fault_access` (`not-mapped`, `protection`,
`kernel`) and `stack_hits` (executable addresses found in the window, with
module/symbol/offset where resolvable).

## Heap

```json
{"method":"heap.query","params":{"session":"s1","addr":"0x555555..."}}
{"method":"heap.query","params":{"session":"s1","id":12}}
{"method":"heap.query","params":{"session":"s1","live":true,"limit":100}}
{"method":"heap.analyze","params":{"session":"s1"}}
{"method":"heap.predict","params":{"session":"s1","tid":7,"size":24,"limit":16}}
{"method":"heap.baseline","params":{"session":"s1","name":"after-setup","path":"/tmp/base.json"}}
{"method":"heap.diff","params":{"session":"s1","name":"after-setup"}}
{"method":"heap.recipe","params":{"session":"s1","tid":7,"size":24,"count":8}}
{"method":"heap.snapshot","params":{"session":"s1"}}
{"method":"maps.refresh","params":{"session":"s1"}}
```

`heap.query`, `heap.snapshot` and `heap.analyze` include a `profile` object
with the detected glibc version and allocator capabilities, plus an `analysis`
object with size-class histograms, largest live/freed chunks, address gaps and
address-reuse counts. Set `config.glibc_version` (or CLI `--glibc-version`) to
override detection.

`heap.predict` returns likely next allocation addresses for a requested size,
using the detected profile for tcache size/count, safe-linking and bin limits.

`heap.baseline` stores a labeled analysis snapshot and optionally writes it to
`path`; `heap.diff` compares the current heap against that snapshot (size-class,
gap and address-reuse deltas). `heap.recipe` returns an ordered `malloc`/`free`
plan for a requested size and count: predicted free-list reclaims first, then
live same-size candidates, then explicitly unpredicted new chunks. Recipe
addresses are advisory.
`maps.refresh` rescans the target's `/proc/<pid>/maps`, making `dlopen`ed
modules available to later symbol lookups. It also reattaches allocator probes
for all current threads and libc-like modules, returning `allocator_paths` and
`threads` in the result.

It models glibc `request2size`, per-thread tcache LIFO (7 chunks), fastbin
LIFO for chunk sizes up to `0x80`, and smallbin FIFO above that. `tid: 0`
merges free sequences across threads. Candidates include source and
confidence (`tcache-lifo`/high, `fastbin-lifo`/medium,
`smallbin-fifo`/medium, `free-order`/low).

## Memory and registers

```json
{"method":"mem.read","params":{"session":"s1","addr":"0x...","size":64}}
{"method":"mem.write","params":{"session":"s1","addr":"0x...","data":"deadbeef"}}
{"method":"regs.get","params":{"session":"s1","tid":0}}
{"method":"stack.get","params":{"session":"s1","tid":0,"words":16}}
```

## Breakpoints and watchpoints

```json
{"method":"break.set","params":{"session":"s1","symbol":"gfs_sink","hardware":true}}
{"method":"break.set","params":{"session":"s1","addr":"0x..."}}
{"method":"break.clear","params":{"session":"s1","addr":"0x..."}}
{"method":"watch.set","params":{"session":"s1","addr":"0x...","size":8,"type":"rw"}}
{"method":"watch.set","params":{"session":"s1","alloc_id":12,"size":8,"type":"write"}}
{"method":"watch.clear","params":{"session":"s1","id":3}}
```

Watch types: `read`, `write`, `rw`, `execute`. x86 supports four hardware
slots per thread. When watching by `alloc_id` and `size` is omitted, the
agent watches the first 8 bytes of the chunk. Prefer hardware breakpoints on
addresses that already have uprobes.

With `config.watch_freed: true` (CLI `--watch-freed`), the agent installs
write watchpoints on the most recently freed chunks, evicting its own oldest
watchpoint when slots run out. A hit is reported as D2 with
`details.source: hardware-watchpoint`, then the target resumes. Writes from
inside libc/ld are treated as allocator internals and ignored.

## Control

```json
{"method":"pause","params":{"session":"s1"}}
{"method":"resume","params":{"session":"s1","tid":0}}
{"method":"step","params":{"session":"s1","tid":0,"count":1}}
{"method":"mark","params":{"session":"s1","label":"after-spray"}}
```

`step` is asynchronous; observe `stop` events with `reason: "single_step"`.

## Sink and ROP validation

Register a sink symbol:

```json
{"method":"sink.register","params":{
  "session":"s1","symbol":"gfs_sink","name":"gfs_sink"
}}
```

Arm a trace from the first gadget:

```json
{"method":"rop.arm","params":{
  "session":"s1",
  "start_symbol":"gfs_pop_rdi_ret",
  "chain_base":0,
  "chain_len":64,
  "max_steps":512
}}
```

Watch a saved-RIP or function-pointer slot:

```json
{"method":"hijack.watch","params":{
  "session":"s1",
  "slot":"0x7fffffffe000",
  "size":8,
  "type":"rw",
  "sink":"gfs_sink",
  "chain_base":"0x555555...",
  "chain_len":64,
  "max_steps":512
}}
```

When the slot is consumed, the agent single-steps until the sink breakpoint,
records the control flow, disassembles gadgets, optionally reads the chain
buffer, and emits a `rop` event with `verified: true/false`.

## Wait, assertions, export

```json
{"method":"wait","params":{"session":"s1","type":"sink","name":"gfs_sink","timeout_ms":10000}}
{"method":"assert","params":{"session":"s1","assertions":[
  {"type":"finding","id":"D1","min_count":1},
  {"type":"sink","symbol":"gfs_sink","regs":{"rdi":16705}},
  {"type":"rop"}
]}}
{"method":"export","params":{"session":"s1","dir":"/reports/session-1"}}
```

Exports:

- `events.jsonl`
- `heap.json`
- `rop.json` when a trace exists
- `summary.json`
- `report.md`
- `baselines.json` when a baseline was captured
- `recipe.json` when a recipe was built

## `ctl` helper

`gofengshui ctl` sends one request and can optionally subscribe to events:

```sh
gofengshui ctl --socket /run/gofengshui.sock \
  --method session.create \
  --params '{"mode":"spawn","path":"/opt/gfs/testdata/uaf"}' \
  --events --until finding:D2 --close
```

`--until` accepts `finding:D2`, `finding`, `sink`, `rop`, `marker:<label>` or
`stop`. `--max-events N` limits the stream. `--close` sends `session.close`
with `kill:true` before exiting. This is the normal CI/remote driver.

## Error codes

`bad_type`, `bad_params`, `no_session`, `create_failed`, `unknown_method`,
`not_found`, `read_failed`, `write_failed`, `regs_failed`, `symbol`,
`break_failed`, `watch_failed`, `pause_failed`, `resume_failed`,
`step_failed`, `sink_failed`, `rop_failed`, `export_failed`, `marshal`.
