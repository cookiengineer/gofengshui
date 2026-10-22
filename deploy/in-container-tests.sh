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

echo "== syscall buffer UAF =="
timeout 30s gofengshui run --report /reports/syscall_uaf --expect-findings D2 \
  --stdout /reports/syscall_uaf.stdout \
  --stderr /reports/syscall_uaf.stderr \
  -- /opt/gfs/testdata/syscall_uaf \
  > /reports/syscall_uaf.events.jsonl
grep -q '"id":"D2"' /reports/syscall_uaf.events.jsonl
grep -q 'use-after-free' /reports/syscall_uaf/report.md
grep -q '"arg1":257' /reports/syscall_uaf.events.jsonl
grep -q '"arg1":59' /reports/syscall_uaf.events.jsonl
grep -q '"arg1":40' /reports/syscall_uaf.events.jsonl
grep -q '"arg1":275' /reports/syscall_uaf.events.jsonl
echo "D2 observed through openat/execve/sendfile/splice buffers"

echo "== direct UAF write (auto watch) =="
timeout 30s gofengshui run --watch-freed --report /reports/uaf_direct --expect-findings D2 \
  --stdout /reports/uaf_direct.stdout \
  --stderr /reports/uaf_direct.stderr \
  -- /opt/gfs/testdata/uaf_direct \
  > /reports/uaf_direct.events.jsonl
grep -q '"id":"D2"' /reports/uaf_direct.events.jsonl
grep -q 'hardware-watchpoint' /reports/uaf_direct.events.jsonl
echo "D2 direct write-after-free observed via hardware watchpoint"

echo "== overflow =="
timeout 30s gofengshui run --report /reports/overflow --expect-findings D3 \
  --stdout /reports/overflow.stdout \
  --stderr /reports/overflow.stderr \
  -- /opt/gfs/testdata/overflow \
  > /reports/overflow.events.jsonl
grep -q '"id":"D3"' /reports/overflow.events.jsonl
grep -q 'heap overflow' /reports/overflow/report.md
echo "D3 overflow finding observed"

echo "== tcache poisoning / safe-linking anomaly =="
timeout 30s gofengshui run --report /reports/poison --expect-findings D7 \
  --stdout /reports/poison.stdout \
  --stderr /reports/poison.stderr \
  -- /opt/gfs/testdata/poison \
  > /reports/poison.events.jsonl
grep -q '"id":"D7"' /reports/poison.events.jsonl
grep -q 'tcache' /reports/poison/report.md

GLIBC_VERSION=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
if [ -z "$GLIBC_VERSION" ]; then
  GLIBC_VERSION=$(ldd --version | awk 'NR == 1 {print $NF}')
fi
grep -q "\"version\": \"$GLIBC_VERSION\"" /reports/poison/heap.json
grep -q '"source": "libc-string"' /reports/poison/heap.json
grep -q '"tcache": true' /reports/poison/heap.json
grep -q '"safe_linking": true' /reports/poison/heap.json
echo "D7 tcache link anomaly observed; detected glibc $GLIBC_VERSION profile"

echo "== heap metadata corruption =="
timeout 30s gofengshui run --report /reports/metadata --expect-findings D8 \
  --stdout /reports/metadata.stdout \
  --stderr /reports/metadata.stderr \
  -- /opt/gfs/testdata/metadata \
  > /reports/metadata.events.jsonl
grep -q '"id":"D8"' /reports/metadata.events.jsonl
grep -q 'invalid chunk size' /reports/metadata.events.jsonl
grep -q '\*\*D8\*\*' /reports/metadata/report.md
echo "D8 chunk metadata corruption observed"

echo "== allocation size mismatch =="
timeout 30s gofengshui run --report /reports/size_swap --expect-findings D9 \
  --stdout /reports/size_swap.stdout \
  --stderr /reports/size_swap.stderr \
  -- /opt/gfs/testdata/size_swap \
  > /reports/size_swap.events.jsonl
grep -q '"id":"D9"' /reports/size_swap.events.jsonl
grep -q 'chunk size changed while allocated' /reports/size_swap.events.jsonl
echo "D9 allocation size-field mismatch observed"

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
grep -qF 'fault=0x0 [null]' /reports/crash.events.jsonl
grep -q '"fault_region":"null"' /reports/crash.events.jsonl
grep -q '"fault_access":"not-mapped"' /reports/crash.events.jsonl
grep -q '"stack_hits"' /reports/crash.events.jsonl
grep -q '\*\*D6\*\*' /reports/crash/report.md
echo "D6 crash finding observed (symbolized RIP + fault info + stack hits)"

echo "== clean allocation loop (no false positives) =="
timeout 30s gofengshui run --sample-stacks 4 --report /reports/clean --expect-no-findings \
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

echo "== realloc churn =="
timeout 30s gofengshui run --report /reports/realloc --expect-no-findings \
  --stdout /reports/realloc.stdout \
  --stderr /reports/realloc.stderr \
  -- /opt/gfs/testdata/realloc_churn \
  > /reports/realloc.events.jsonl
grep -q '"analysis"' /reports/realloc/heap.json
grep -q '"size_classes"' /reports/realloc/heap.json
echo "moving/in-place realloc churn produced no false positives"

echo "== C++ new/delete labelling =="
timeout 30s gofengshui run --report /reports/cxx --expect-no-findings \
  --stdout /reports/cxx.stdout \
  --stderr /reports/cxx.stderr \
  -- /opt/gfs/testdata/cxx_alloc \
  > /reports/cxx.events.jsonl
grep -q '"type":1.*"arg2":6' /reports/cxx.events.jsonl
grep -q '"type":2.*"arg1":7' /reports/cxx.events.jsonl
echo "C++ new/delete allocations labelled (NEW/DELETE ops)"

echo "== allocator profile override =="
timeout 30s gofengshui run --glibc-version 2.31 \
  --report /reports/profile-override --expect-no-findings \
  --stdout /reports/profile-override.stdout \
  --stderr /reports/profile-override.stderr \
  -- /opt/gfs/testdata/alloc_once \
  > /reports/profile-override.events.jsonl
grep -q '"version": "2.31"' /reports/profile-override/heap.json
grep -q '"source": "override"' /reports/profile-override/heap.json
grep -q '"tcache": true' /reports/profile-override/heap.json
grep -q '"safe_linking": false' /reports/profile-override/heap.json
echo "glibc 2.31 profile override applied end-to-end"

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

echo "== attach thread-arena backfill =="
rm -f /tmp/arena_backfill.*.addrs
/opt/gfs/testdata/arena_backfill &
ARENA_TARGET=$!
for _ in $(seq 1 50); do
  ARENA_FILES=$(compgen -G '/tmp/arena_backfill.*.addrs' | wc -l)
  [ "$ARENA_FILES" -ge 2 ] && break
  sleep 0.05
done
timeout 20s gofengshui attach --pid "$ARENA_TARGET" --backfill --expect-no-findings \
  --report /reports/arena_backfill \
  --stdout /reports/arena_backfill.stdout \
  --stderr /reports/arena_backfill.stderr \
  > /reports/arena_backfill.events.jsonl
wait "$ARENA_TARGET" 2>/dev/null || true
for f in /tmp/arena_backfill.*.addrs; do
  while read -r addr; do
    [ -n "$addr" ] || continue
    grep -q "\"addr\": $addr" /reports/arena_backfill/heap.json
  done < "$f"
done
grep -qE '"arenas": [1-9][0-9]*' /reports/arena_backfill/heap.json
echo "attach backfill recovered thread-arena chunks"

echo "== stdio JSONL =="
printf '%s\n' \
  '{"v":1,"type":"request","id":1,"method":"events.subscribe","params":{"since":0}}' \
  '{"v":1,"type":"request","id":2,"method":"resume","params":{}}' \
  '{"v":1,"type":"request","id":3,"method":"wait","params":{"type":"finding","id":"D2","timeout_ms":10000}}' \
  '{"v":1,"type":"request","id":4,"method":"assert","params":{"assertions":[{"type":"finding","id":"D2","min_count":1}]}}' \
  '{"v":1,"type":"request","id":5,"method":"session.status","params":{}}' \
  '{"v":1,"type":"request","id":6,"method":"heap.baseline","params":{"name":"check"}}' \
  '{"v":1,"type":"request","id":7,"method":"heap.diff","params":{"name":"check"}}' \
  '{"v":1,"type":"request","id":8,"method":"heap.recipe","params":{"size":64,"count":4}}' \
  | timeout 30s gofengshui run --jsonl --pause -- /opt/gfs/testdata/uaf \
  > /reports/stdio.jsonl
grep -q '"id":"D2"' /reports/stdio.jsonl
grep -q '"type":"result","id":3' /reports/stdio.jsonl
grep -q '"type":"result","id":4,"result":{"ok":true' /reports/stdio.jsonl
grep -q '"type":"result","id":5' /reports/stdio.jsonl
grep -q '"profile":{' /reports/stdio.jsonl
grep -q '"bpf":{' /reports/stdio.jsonl
grep -q '"drops":0' /reports/stdio.jsonl
grep -q '"type":"result","id":6' /reports/stdio.jsonl
grep -q '"type":"result","id":7' /reports/stdio.jsonl
grep -q '"live_delta"' /reports/stdio.jsonl
grep -q '"type":"result","id":8' /reports/stdio.jsonl
grep -q '"reclaim"' /reports/stdio.jsonl
echo "stdio JSONL session + D2 + wait/assert + profile + baseline/diff + recipe verified"

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

echo "== dlopen rescan + allocator reattach =="
DL_AGENT=""
cleanup_dl_agent() {
  if [ -n "$DL_AGENT" ]; then
    kill "$DL_AGENT" 2>/dev/null || true
    wait "$DL_AGENT" 2>/dev/null || true
    DL_AGENT=""
  fi
}
trap cleanup_dl_agent EXIT
rm -f /tmp/gfs-dlopen.sock /tmp/dlopen_alloc.ready \
  /tmp/dlopen_alloc.release /tmp/dlopen_alloc.ptr
gofengshui agent --socket /tmp/gfs-dlopen.sock \
  > /reports/agent-dlopen.stdout 2> /reports/agent-dlopen.stderr &
DL_AGENT=$!
for _ in $(seq 1 50); do
  [ -S /tmp/gfs-dlopen.sock ] && break
  sleep 0.1
done
CREATE=$(timeout 20s gofengshui ctl --socket /tmp/gfs-dlopen.sock --timeout 15s \
  --method session.create \
  --params '{"mode":"spawn","path":"/opt/gfs/testdata/dlopen_alloc","args":["/opt/gfs/testdata/dlopen_alloc"],"pause":true}')
SESSION=$(printf '%s\n' "$CREATE" | sed -n 's/.*"session": "\([^"]*\)".*/\1/p' | head -1)
if [ -z "$SESSION" ]; then
  echo "dlopen test could not create a session" >&2
  printf '%s\n' "$CREATE" >&2
  exit 1
fi
timeout 20s gofengshui ctl --socket /tmp/gfs-dlopen.sock --timeout 15s \
  --session "$SESSION" --method resume > /reports/dlopen-resume.json
for _ in $(seq 1 100); do
  [ -f /tmp/dlopen_alloc.ready ] && break
  sleep 0.05
done
[ -f /tmp/dlopen_alloc.ready ] || {
  echo "dlopen target did not become ready" >&2
  exit 1
}
REFRESH=$(timeout 20s gofengshui ctl --socket /tmp/gfs-dlopen.sock --timeout 15s \
  --session "$SESSION" --method maps.refresh)
printf '%s\n' "$REFRESH" > /reports/dlopen-refresh.json
printf '%s\n' "$REFRESH" | grep -q 'libgfsplugin.so'
printf '%s\n' "$REFRESH" | grep -q '"allocator_paths"'
touch /tmp/dlopen_alloc.release
for _ in $(seq 1 100); do
  [ -f /tmp/dlopen_alloc.ptr ] && break
  sleep 0.05
done
[ -f /tmp/dlopen_alloc.ptr ] || {
  echo "dlopen target did not allocate after refresh" >&2
  exit 1
}
DL_ADDR=$(cat /tmp/dlopen_alloc.ptr)
QUERY=$(timeout 20s gofengshui ctl --socket /tmp/gfs-dlopen.sock --timeout 15s \
  --session "$SESSION" --method heap.query --params "{\"addr\":$DL_ADDR}")
printf '%s\n' "$QUERY" > /reports/dlopen-query.json
printf '%s\n' "$QUERY" | grep -q "\"addr\": $DL_ADDR"
timeout 20s gofengshui ctl --socket /tmp/gfs-dlopen.sock --timeout 15s \
  --session "$SESSION" --method session.close --params '{"kill":true}' > /dev/null
cleanup_dl_agent
trap - EXIT
echo "dlopen module resolved and allocator probes refreshed"

echo
echo "all in-container tests passed"
