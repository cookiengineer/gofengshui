#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Optional host-privileged agent. It sees host PIDs and can attach to
# processes in other containers. The socket directory is shared with the host.
mkdir -p build/run build/reports
if ! sudo podman image exists localhost/gofengshui:dev; then
  echo "image missing from rootful podman storage; run deploy/build-image.sh first" >&2
  exit 1
fi
exec sudo podman run --rm -it \
  --name gofengshui-host-agent \
  --privileged \
  --pid=host \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD/build/run:/run/gofengshui:Z" \
  -v "$PWD/build/reports:/reports:Z" \
  localhost/gofengshui:dev \
  gofengshui agent --socket /run/gofengshui/gofengshui.sock
