#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Privileged containers run as root, so reports and some build artifacts are
# written with root ownership. Hand them back to the invoking user.
uid="$(id -u)"
gid="$(id -g)"
sudo chown -R "$uid:$gid" build 2>/dev/null || true
echo "restored ownership of build/ to $uid:$gid"
