#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p build/logs
LOG="$PWD/build/logs/build-image-$(date +%Y%m%d-%H%M%S).log"
ln -sfn "$LOG" build/logs/latest-build.log

{
  echo "=== build image $(date -Is) ==="
  make build
  make test-c
  # The privileged runner uses rootful podman, which has a separate image
  # store. Build there explicitly so sudo podman can find the image.
  sudo podman build -t localhost/gofengshui:dev -f deploy/Containerfile .
  echo "built localhost/gofengshui:dev in rootful podman storage"
  echo "log: $LOG"
} 2>&1 | tee -a "$LOG"
