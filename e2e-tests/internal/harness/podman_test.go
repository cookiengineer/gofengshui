package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installFakePodman(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
  version) echo "9.9.9" ;;
  info) echo "rootless=false" ;;
  ps) exit 0 ;;
  run) echo "fake-container-id" ;;
  cp) exit 0 ;;
  rm) exit 0 ;;
  exec) exit 0 ;;
  inspect) echo "[]" ;;
  build) exit 0 ;;
  image)
    if [ "$2" = "exists" ]; then exit 0; fi
    if [ "$2" = "inspect" ]; then echo "id=fake"; fi
    ;;
esac
exit 0
`
	path := filepath.Join(dir, "podman")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake podman: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GFS_E2E_KEEP", "")
}

func TestPodmanContainerLifecycle(t *testing.T) {
	installFakePodman(t)
	run := NewRun(t)
	c := run.NewCaseFor(t, "fake-case")
	container := c.StartContainer(t, ContainerOptions{Image: "fake/image:latest"})
	if container.ID != "fake-container-id" {
		t.Fatalf("container id = %q", container.ID)
	}
	if !strings.HasPrefix(container.Name, "gfs-e2e-fake-case-") {
		t.Fatalf("container name = %q", container.Name)
	}
	container.CopyTo("/tmp/does-not-need-to-exist", "/opt/gfs/e2e/victim.test")
	res := container.Exec("container-echo", ExecOptions{}, "echo", "hello")
	if res.ExitCode != 0 {
		t.Fatalf("exec exit = %d", res.ExitCode)
	}
}

func TestBuildVictimTest(t *testing.T) {
	run := NewRun(t)
	c := run.NewCaseFor(t, "victim-build")
	bin := c.BuildVictimTest("./glibc", "glibc.victim.test")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("victim binary missing: %v", err)
	}
}
