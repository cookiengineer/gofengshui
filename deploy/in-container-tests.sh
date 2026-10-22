#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/local/bin:$PATH"
export GFS_BPF_LOG="${GFS_BPF_LOG:-1}"
PS4='+ [gfs] '
mkdir -p /reports

echo "=== in-container integration $(date -Is) ==="
echo "kernel: $(uname -a)"
echo "gofengshui: $(gofengshui version)"
echo "btf: $(test -e /sys/kernel/btf/vmlinux && echo present || echo missing)"
echo "unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo unknown)"
echo "perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)"
echo "ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unknown)"
echo

echo "== double free =="
timeout 30s gofengshui run --report /reports/double_free --expect-findings D1 \
  --stdout /reports/double_free.stdout \
  --stderr /reports/double_free.stderr \
  -- /opt/gfs/testdata/double_free \
  > /reports/double_free.events.jsonl
grep -q '"id":"D1"' /reports/double_free.events.jsonl
grep -q '\*\*D1\*\*' /reports/double_free/report.md
echo "D1 double-free finding observed"

echo "== uaf =="
timeout 30s gofengshui run --report /reports/uaf --expect-findings D2 \
  --stdout /reports/uaf.stdout \
  --stderr /reports/uaf.stderr \
  -- /opt/gfs/testdata/uaf \
  > /reports/uaf.events.jsonl
grep -q '"id":"D2"' /reports/uaf.events.jsonl
grep -q 'use-after-free' /reports/uaf/report.md
echo "D2 UAF finding observed"

echo "== overflow =="
timeout 30s gofengshui run --report /reports/overflow --expect-findings D3 \
  --stdout /reports/overflow.stdout \
  --stderr /reports/overflow.stderr \
  -- /opt/gfs/testdata/overflow \
  > /reports/overflow.events.jsonl
grep -q '"id":"D3"' /reports/overflow.events.jsonl
grep -q 'heap overflow' /reports/overflow/report.md
echo "D3 overflow finding observed"

echo "== allocation failure / OOM =="
timeout 30s gofengshui run --report /reports/alloc_fail --expect-findings D4 \
  --stdout /reports/alloc_fail.stdout \
  --stderr /reports/alloc_fail.stderr \
  -- /opt/gfs/testdata/alloc_fail \
  > /reports/alloc_fail.events.jsonl
grep -q '"id":"D4"' /reports/alloc_fail.events.jsonl
grep -q 'allocation failed: request=18446744073709551615' /reports/alloc_fail.events.jsonl
grep -q 'mmap/mremap failed: errno=' /reports/alloc_fail/report.md
grep -q '\*\*D4\*\*' /reports/alloc_fail/report.md
echo "D4 allocation-failure finding observed (malloc NULL + mmap ENOMEM)"

echo "== crash classification =="
timeout 30s gofengshui run --report /reports/crash --expect-findings D6 \
  --stdout /reports/crash.stdout \
  --stderr /reports/crash.stderr \
  -- /opt/gfs/testdata/crash \
  > /reports/crash.events.jsonl
grep -q '"id":"D6"' /reports/crash.events.jsonl
grep -q 'signal 11 at RIP' /reports/crash.events.jsonl
grep -q '\*\*D6\*\*' /reports/crash/report.md
echo "D6 crash finding observed (SIGSEGV with symbolized RIP)"

echo "== clean allocation loop (no false positives) =="
timeout 30s gofengshui run --report /reports/clean --expect-no-findings \
  --stdout /reports/clean.stdout \
  --stderr /reports/clean.stderr \
  -- /opt/gfs/testdata/alloc_loop \
  > /reports/clean.events.jsonl
if grep -q '"kind":"finding"' /reports/clean.events.jsonl; then
  echo "unexpected finding on clean allocation loop" >&2
  grep '"kind":"finding"' /reports/clean.events.jsonl >&2 || true
  exit 1
fi
grep -q 'No findings recorded' /reports/clean/report.md
grep -q '"analysis"' /reports/clean/heap.json
grep -q '"size_classes"' /reports/clean/heap.json
echo "no false-positive findings on clean malloc/free loop; heap analysis exported"

echo "== multithread allocation =="
timeout 30s gofengshui run --follow --report /reports/threads --expect-no-findings \
  --stdout /reports/threads.stdout \
  --stderr /reports/threads.stderr \
  -- /opt/gfs/testdata/threads \
  > /reports/threads.events.jsonl
THREAD_TIDS=$(grep -E '"type":1([,}])' /reports/threads.events.jsonl \
  | grep -o '"tid":[0-9]*' | sort -u | wc -l)
if [ "$THREAD_TIDS" -lt 2 ]; then
  echo "expected allocator events from multiple threads, got $THREAD_TIDS" >&2
  exit 1
fi
grep -q '"analysis"' /reports/threads/heap.json
echo "allocator events observed from $THREAD_TIDS threads; analysis exported"

echo "== fork/exec follow =="
timeout 30s gofengshui run --follow --report /reports/fork_exec --expect-no-findings \
  --stdout /reports/fork_exec.stdout \
  --stderr /reports/fork_exec.stderr \
  -- /opt/gfs/testdata/fork_exec \
  > /reports/fork_exec.events.jsonl
FORK_PIDS=$(grep -E '"type":1([,}])' /reports/fork_exec.events.jsonl \
  | grep -o '"pid":[0-9]*' | sort -u | wc -l)
if [ "$FORK_PIDS" -lt 2 ]; then
  echo "expected allocator events from parent and exec child, got $FORK_PIDS process(es)" >&2
  exit 1
fi
grep -q '"analysis"' /reports/fork_exec/heap.json
echo "allocator events observed from $FORK_PIDS processes across fork/exec"

echo "== attach workflow =="
/opt/gfs/testdata/threads &
ATTACH_TARGET=$!
sleep 0.2
timeout 20s gofengshui attach --pid "$ATTACH_TARGET" --expect-no-findings \
  --report /reports/attach \
  --stdout /reports/attach.stdout \
  --stderr /reports/attach.stderr \
  > /reports/attach.events.jsonl
wait "$ATTACH_TARGET" 2>/dev/null || true
ATTACH_TIDS=$(grep -E '"type":1([,}])' /reports/attach.events.jsonl \
  | grep -o '"tid":[0-9]*' | sort -u | wc -l)
if [ "$ATTACH_TIDS" -lt 2 ]; then
  echo "attach captured allocator events from only $ATTACH_TIDS thread(s)" >&2
  exit 1
fi
echo "attach captured allocator events from $ATTACH_TIDS threads"

echo "== attach heap backfill =="
rm -f /tmp/backfill.addrs
/opt/gfs/testdata/backfill &
BACKFILL_TARGET=$!
for _ in $(seq 1 50); do
  [ -s /tmp/backfill.addrs ] && break
  sleep 0.05
done
timeout 20s gofengshui attach --pid "$BACKFILL_TARGET" --backfill --expect-no-findings \
  --report /reports/backfill \
  --stdout /reports/backfill.stdout \
  --stderr /reports/backfill.stderr \
  > /reports/backfill.events.jsonl
wait "$BACKFILL_TARGET" 2>/dev/null || true
while read -r addr; do
  [ -n "$addr" ] || continue
  grep -q "\"addr\": $addr" /reports/backfill/heap.json
done < /tmp/backfill.addrs
grep -q '"backfill"' /reports/backfill/heap.json
echo "attach backfill recovered live heap chunks"

echo "== stdio JSONL =="
printf '%s\n' \
  '{"v":1,"type":"request","id":1,"method":"events.subscribe","params":{"since":0}}' \
  '{"v":1,"type":"request","id":2,"method":"resume","params":{}}' \
  '{"v":1,"type":"request","id":3,"method":"wait","params":{"type":"finding","id":"D2","timeout_ms":10000}}' \
  '{"v":1,"type":"request","id":4,"method":"assert","params":{"assertions":[{"type":"finding","id":"D2","min_count":1}]}}' \
  | timeout 30s gofengshui run --jsonl --pause -- /opt/gfs/testdata/uaf \
  > /reports/stdio.jsonl
grep -q '"id":"D2"' /reports/stdio.jsonl
grep -q '"type":"result","id":3' /reports/stdio.jsonl
grep -q '"type":"result","id":4,"result":{"ok":true' /reports/stdio.jsonl
echo "stdio JSONL session + D2 event + wait/assert results verified"

echo "== rop sink =="
timeout 30s gofengshui validate --report /reports/rop --expect-regs rdi=0x4141 \
  --sink gfs_sink --start gfs_pop_rdi_ret \
  --stdout /reports/rop.target.stdout \
  --stderr /reports/rop.target.stderr \
  -- /opt/gfs/testdata/rop_sink | tee /reports/rop.stdout.json
grep -q '"verified": true' /reports/rop.stdout.json
grep -q '"rdi": 16705' /reports/rop.stdout.json
echo "ROP chain verified with expected RDI"

echo "== hijack watch rop =="
timeout 30s gofengshui validate --report /reports/rop-hijack --expect-regs rdi=0x4141 \
  --hijack --hijack-func gfs_vuln \
  --sink gfs_sink --start gfs_pop_rdi_ret \
  --stdout /reports/rop-hijack.target.stdout \
  --stderr /reports/rop-hijack.target.stderr \
  -- /opt/gfs/testdata/rop_sink | tee /reports/rop-hijack.stdout.json
grep -q '"verified": true' /reports/rop-hijack.stdout.json
grep -q '"rdi": 16705' /reports/rop-hijack.stdout.json
echo "hijack watch ROP chain verified with expected RDI"

echo "== unix socket protocol =="
AGENT_PID=""
cleanup_agent() {
  if [ -n "$AGENT_PID" ]; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    AGENT_PID=""
  fi
}
trap cleanup_agent EXIT
rm -f /tmp/gfs.sock
gofengshui agent --socket /tmp/gfs.sock > /reports/agent.stdout 2> /reports/agent.stderr &
AGENT_PID=$!
for _ in $(seq 1 50); do
  [ -S /tmp/gfs.sock ] && break
  sleep 0.1
done
timeout 20s gofengshui ctl --socket /tmp/gfs.sock --timeout 15s \
  --method session.create \
  --params '{"mode":"spawn","path":"/opt/gfs/testdata/uaf","args":["/opt/gfs/testdata/uaf"]}' \
  --events --until finding:D2 --close > /reports/protocol.jsonl
grep -q '"id":"D2"' /reports/protocol.jsonl
echo "unix socket session + D2 event + close verified"
cleanup_agent
trap - EXIT

echo
echo "all in-container tests passed"
