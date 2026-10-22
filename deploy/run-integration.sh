#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

LOG_DIR="$PWD/build/logs"
mkdir -p "$LOG_DIR" build/reports
LOG="$LOG_DIR/integration-$(date +%Y%m%d-%H%M%S).log"
ln -sfn "$LOG" "$LOG_DIR/latest.log"

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

{
  echo
  echo "=== finished: $(date -Is) status=$status ==="
  echo "container log: /reports/integration.log"
  echo "host log: $LOG"
  echo "reports:"
  find build/reports -maxdepth 2 -type f -printf '  %p\n' 2>/dev/null | sort || true
} 2>&1 | tee -a "$LOG"

exit "$status"
