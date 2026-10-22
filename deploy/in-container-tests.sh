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
timeout 30s gofengshui run --report /reports/double_free \
  --stdout /reports/double_free.stdout \
  --stderr /reports/double_free.stderr \
  -- /opt/gfs/testdata/double_free \
  > /reports/double_free.events.jsonl
grep -q '"id":"D1"' /reports/double_free.events.jsonl
echo "D1 double-free finding observed"

echo "== uaf =="
timeout 30s gofengshui run --report /reports/uaf \
  --stdout /reports/uaf.stdout \
  --stderr /reports/uaf.stderr \
  -- /opt/gfs/testdata/uaf \
  > /reports/uaf.events.jsonl
grep -q '"id":"D2"' /reports/uaf.events.jsonl
echo "D2 UAF finding observed"

echo "== overflow =="
timeout 30s gofengshui run --report /reports/overflow \
  --stdout /reports/overflow.stdout \
  --stderr /reports/overflow.stderr \
  -- /opt/gfs/testdata/overflow \
  > /reports/overflow.events.jsonl
grep -q '"id":"D3"' /reports/overflow.events.jsonl
echo "D3 overflow finding observed"

echo "== rop sink =="
timeout 30s gofengshui validate --report /reports/rop \
  --sink gfs_sink --start gfs_pop_rdi_ret \
  --stdout /reports/rop.target.stdout \
  --stderr /reports/rop.target.stderr \
  -- /opt/gfs/testdata/rop_sink | tee /reports/rop.stdout.json
grep -q '"verified": true' /reports/rop.stdout.json
grep -q '"rdi": 16705' /reports/rop.stdout.json
echo "ROP chain verified with expected RDI"

echo "== hijack watch rop =="
timeout 30s gofengshui validate --report /reports/rop-hijack \
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
