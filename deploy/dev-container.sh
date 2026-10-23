#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p build/reports

# Rootful podman is required on hosts with unprivileged_bpf_disabled=2.
if ! sudo podman image exists localhost/gofengshui-e2e/glibc:dev; then
  echo "image missing from rootful podman storage; run deploy/build-image.sh first" >&2
  exit 1
fi
exec sudo podman run --rm -it \
  --name gofengshui-dev \
  --privileged \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD/build/reports:/reports:Z" \
  localhost/gofengshui-e2e/glibc:dev
