#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

LOG_DIR="$PWD/build/logs"
mkdir -p "$LOG_DIR"
# Privileged containers write reports as root. Always clean and restore
# ownership through sudo, otherwise the next run cannot remove them.
fix_reports() {
  sudo chown -R "$(id -u):$(id -g)" build/reports 2>/dev/null || true
}
trap fix_reports EXIT
sudo rm -rf -- "$PWD/build/reports"
mkdir -p build/reports
LOG="$LOG_DIR/integration-$(date +%Y%m%d-%H%M%S).log"
ln -sfn "$LOG" "$LOG_DIR/latest.log"

require_report_grep() {
  local pattern="$1"
  local file="$2"
  local label="$3"
  if grep -q -- "$pattern" "$file"; then
    echo "ok: $label"
  else
    echo "FAIL: $label (pattern '$pattern' missing from $file)" >&2
    return 1
  fi
}

verify_profiles() {
  local failed=0
  local poison=build/reports/poison/heap.json
  local override=build/reports/profile-override/heap.json
  local stdio=build/reports/stdio.jsonl

  echo "=== allocator profile assertions ==="
  if [ ! -s "$poison" ]; then
    echo "FAIL: missing $poison" >&2
    failed=1
  else
    require_report_grep '"profile": {' "$poison" "heap.json has detected profile" || failed=1
    require_report_grep '"source": "libc-string"' "$poison" "profile detected from libc metadata" || failed=1
    require_report_grep '"tcache": true' "$poison" "detected profile enables tcache" || failed=1
    require_report_grep '"safe_linking": true' "$poison" "detected profile enables safe-linking" || failed=1
  fi
  if [ ! -s "$override" ]; then
    echo "FAIL: missing $override" >&2
    failed=1
  else
    require_report_grep '"version": "2.31"' "$override" "override applied glibc 2.31" || failed=1
    require_report_grep '"source": "override"' "$override" "override source recorded" || failed=1
    require_report_grep '"safe_linking": false' "$override" "override disables safe-linking" || failed=1
  fi
  if [ ! -s "$stdio" ]; then
    echo "FAIL: missing $stdio" >&2
    failed=1
  else
    require_report_grep '"profile":{' "$stdio" "session.status exposes profile" || failed=1
    require_report_grep '"bpf":{' "$stdio" "session.status exposes BPF stats" || failed=1
    require_report_grep '"drops":0' "$stdio" "no ringbuf drops recorded" || failed=1
  fi
  return "$failed"
}

verify_findings() {
  local failed=0
  local crash=build/reports/crash.events.jsonl
  local syscall=build/reports/syscall_uaf.events.jsonl
  local realloc=build/reports/realloc.events.jsonl
  local metadata=build/reports/metadata.events.jsonl
  local sizeswap=build/reports/size_swap.events.jsonl
  local cxx=build/reports/cxx.events.jsonl
  local uafdirect=build/reports/uaf_direct.events.jsonl
  local dlopen=build/reports/dlopen-refresh.json
  local arena=build/reports/arena_backfill/heap.json
  local stdio=build/reports/stdio.jsonl

  echo "=== crash/syscall assertions ==="
  if [ ! -s "$crash" ]; then
    echo "FAIL: missing $crash" >&2
    failed=1
  else
    require_report_grep '"id":"D6"' "$crash" "D6 crash finding present" || failed=1
    require_report_grep 'fault=0x0 \[null\]' "$crash" "SIGSEGV fault address captured" || failed=1
    require_report_grep '"fault_region":"null"' "$crash" "fault region classified" || failed=1
    require_report_grep '"stack_hits"' "$crash" "crash stack window analyzed" || failed=1
  fi
  if [ ! -s "$syscall" ]; then
    echo "FAIL: missing $syscall" >&2
    failed=1
  else
    require_report_grep '"id":"D2"' "$syscall" "D2 syscall-buffer finding present" || failed=1
    require_report_grep '"arg1":257' "$syscall" "openat buffer checked" || failed=1
    require_report_grep '"arg1":59' "$syscall" "execve buffer checked" || failed=1
    require_report_grep '"arg1":40' "$syscall" "sendfile offset checked" || failed=1
    require_report_grep '"arg1":275' "$syscall" "splice offset checked" || failed=1
  fi
  if [ ! -s "$realloc" ]; then
    echo "FAIL: missing $realloc" >&2
    failed=1
  elif grep -q '"kind":"finding"' "$realloc"; then
    echo "FAIL: realloc churn produced findings" >&2
    failed=1
  else
    echo "ok: realloc churn produced no findings"
  fi
  if [ ! -s "$metadata" ]; then
    echo "FAIL: missing $metadata" >&2
    failed=1
  else
    require_report_grep '"id":"D8"' "$metadata" "D8 metadata finding present" || failed=1
    require_report_grep 'invalid chunk size' "$metadata" "D8 classified the corrupted size" || failed=1
  fi
  if [ ! -s "$sizeswap" ]; then
    echo "FAIL: missing $sizeswap" >&2
    failed=1
  else
    require_report_grep '"id":"D9"' "$sizeswap" "D9 size mismatch present" || failed=1
    require_report_grep 'chunk size changed while allocated' "$sizeswap" "D9 classified the mismatch" || failed=1
  fi
  if [ ! -s "$cxx" ]; then
    echo "FAIL: missing $cxx" >&2
    failed=1
  else
    require_report_grep '"type":1.*"arg2":6' "$cxx" "C++ new allocation labelled" || failed=1
    require_report_grep '"type":2.*"arg1":7' "$cxx" "C++ delete free labelled" || failed=1
  fi
  if [ ! -s "$uafdirect" ]; then
    echo "FAIL: missing $uafdirect" >&2
    failed=1
  else
    require_report_grep '"id":"D2"' "$uafdirect" "D2 direct UAF finding present" || failed=1
    require_report_grep 'hardware-watchpoint' "$uafdirect" "D2 came from hardware watchpoint" || failed=1
  fi
  if [ ! -s "$dlopen" ]; then
    echo "FAIL: missing $dlopen" >&2
    failed=1
  else
    require_report_grep 'libgfsplugin.so' "$dlopen" "dlopen module appeared after refresh" || failed=1
    require_report_grep '"allocator_paths"' "$dlopen" "allocator probes refreshed" || failed=1
  fi
  if [ ! -s "$arena" ]; then
    echo "FAIL: missing $arena" >&2
    failed=1
  else
    require_report_grep '"arenas": [1-9][0-9]*' "$arena" "thread-arena backfill scanned an arena" || failed=1
  fi
  if [ ! -s "$stdio" ]; then
    echo "FAIL: missing $stdio" >&2
    failed=1
  else
    require_report_grep '"type":"result","id":6' "$stdio" "heap.baseline response present" || failed=1
    require_report_grep '"type":"result","id":7' "$stdio" "heap.diff response present" || failed=1
    require_report_grep '"live_delta"' "$stdio" "baseline diff contains deltas" || failed=1
    require_report_grep '"type":"result","id":8' "$stdio" "heap.recipe response present" || failed=1
    require_report_grep '"reclaim"' "$stdio" "recipe contains reclaim plan" || failed=1
  fi
  return "$failed"
}

{
  echo "=== gofengshui privileged integration ==="
  echo "started: $(date -Is)"
  echo "host: $(uname -a)"
  echo "cwd: $PWD"
  echo "log: $LOG"
  echo
  echo "=== environment preflight ==="
  deploy/check-env.sh || true
  echo
} 2>&1 | tee -a "$LOG"

if [ "${GFS_SKIP_BUILD:-0}" != "1" ]; then
  {
    echo "=== host build ==="
    make build
    make test-c
    echo
    echo "=== rootful image build ==="
    # rootless and rootful podman use different image stores
    sudo podman build -t localhost/gofengshui:dev -f deploy/Containerfile .
    echo
  } 2>&1 | tee -a "$LOG"
fi

{
  echo "=== image ==="
  sudo podman image inspect localhost/gofengshui:dev \
    --format 'id={{.Id}} created={{.Created}}' 2>&1 || true
  echo
  echo "=== container run ==="
} 2>&1 | tee -a "$LOG"

set +e
# Remove any stale integration containers from previous runs.
mapfile -t old_containers < <(sudo podman ps -aq --filter ancestor=localhost/gofengshui:dev)
if [ "${#old_containers[@]}" -gt 0 ]; then
  sudo podman rm -f "${old_containers[@]}" >/dev/null 2>&1 || true
fi
sudo podman run --rm \
  --name gofengshui-integration \
  --privileged \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -e GFS_BPF_LOG="${GFS_BPF_LOG:-1}" \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD/build/reports:/reports:Z" \
  localhost/gofengshui:dev \
  /bin/bash -o pipefail -c '/usr/local/bin/gfs-tests 2>&1 | tee -a /reports/integration.log' 2>&1 | tee -a "$LOG"
status=${PIPESTATUS[0]}
set -e

fix_reports
profile_status=0
verify_profiles 2>&1 | tee -a "$LOG" || profile_status=1
finding_status=0
verify_findings 2>&1 | tee -a "$LOG" || finding_status=1
if [ "$status" -eq 0 ] && { [ "$profile_status" -ne 0 ] || [ "$finding_status" -ne 0 ]; }; then
  status=1
fi
{
  echo
  echo "=== finished: $(date -Is) status=$status ==="
  echo "container log: /reports/integration.log"
  echo "host log: $LOG"
  echo "reports:"
  find build/reports -maxdepth 2 -type f -printf '  %p\n' 2>/dev/null | sort || true
} 2>&1 | tee -a "$LOG"

exit "$status"
