#!/usr/bin/env bash
set -u

echo "== host =="
uname -a
echo
echo "== eBPF / kernel features =="
printf '%-55s %s\n' /sys/kernel/btf/vmlinux "$(test -e /sys/kernel/btf/vmlinux && echo present || echo missing)"
for f in /proc/sys/kernel/unprivileged_bpf_disabled \
         /proc/sys/kernel/perf_event_paranoid /proc/sys/kernel/yama/ptrace_scope; do
  if [ -e "$f" ]; then
    printf '%-55s %s\n' "$f" "$(cat "$f" 2>/dev/null)"
  else
    printf '%-55s %s\n' "$f" "missing"
  fi
done

echo
echo "== toolchain =="
for c in go clang llvm-strip make gcc podman sudo; do
  printf '%-12s ' "$c"
  command -v "$c" || echo missing
done

echo
echo "== capabilities =="
if command -v capsh >/dev/null 2>&1; then
  capsh --print | sed -n '1,6p'
else
  grep -E 'Cap(Inh|Prm|Eff|Bnd)' /proc/self/status
fi

echo
echo "== podman =="
podman version --format '{{.Client.Version}}' 2>/dev/null || true
podman info --format 'rootless={{.Host.Security.Rootless}}' 2>/dev/null || true

echo
echo "== notes =="
if [ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 0)" != "0" ]; then
  echo "unprivileged_bpf_disabled is set; rootless podman cannot load eBPF."
  echo "Use deploy/dev-container.sh with sudo (rootful privileged podman)."
fi
if [ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)" != "0" ]; then
  echo "yama ptrace_scope is non-zero; same-container root with CAP_SYS_PTRACE"
  echo "or spawn-under-agent mode is required."
fi
