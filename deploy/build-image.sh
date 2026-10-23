#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p build/logs
LOG="$PWD/build/logs/build-image-$(date +%Y%m%d-%H%M%S).log"
ln -sfn "$LOG" build/logs/latest-build.log

{
  echo "=== build image $(date -Is) ==="
  make build
  sudo podman build -t localhost/gofengshui-e2e/glibc:dev \
    -f e2e-tests/glibc/Containerfile .
  echo "built localhost/gofengshui-e2e/glibc:dev in rootful podman storage"
  echo "log: $LOG"
} 2>&1 | tee -a "$LOG"
