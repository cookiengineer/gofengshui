package harness

import (
	"os"
	"strings"
	"testing"
	"time"

	"gofengshui/e2e/internal/hostinfo"
)

func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("e2e tests must run as root; use: sudo -E make e2e")
	}
}

func (c *Case) Preflight() {
	c.t.Helper()
	if os.Geteuid() != 0 {
		c.t.Fatalf("e2e tests must run as root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		c.t.Fatalf("/sys/kernel/btf/vmlinux is required: %v", err)
	}
	version := c.Exec("podman-version", ExecOptions{Timeout: 30 * time.Second, AllowFailure: true}, "podman", "version")
	c.RequireSuccess("podman version", version)
	info := c.Exec("podman-info", ExecOptions{Timeout: 30 * time.Second, AllowFailure: true}, "podman", "info", "--format", "rootless={{.Host.Security.Rootless}}")
	c.RequireSuccess("podman info", info)
	if strings.Contains(string(info.Stdout), "rootless=true") {
		c.t.Fatalf("rootful podman is required: %s", strings.TrimSpace(string(info.Stdout)))
	}
	for _, item := range hostinfo.ReadSysctls("/") {
		if !item.Present {
			c.Logf("sysctl %s: missing", item.Path)
			continue
		}
		c.Logf("sysctl %s=%s", item.Path, item.Value)
	}
}
