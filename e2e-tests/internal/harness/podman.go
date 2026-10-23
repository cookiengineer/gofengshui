package harness

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type Mount struct {
	Host      string
	Container string
	ReadOnly  bool
}

type ContainerOptions struct {
	Image   string
	Memory  string
	Env     []string
	Mounts  []Mount
	WorkDir string
}

type Container struct {
	Case *Case
	t    *testing.T
	Name string
	ID   string
}

func (c *Case) StartContainer(t *testing.T, opts ContainerOptions) *Container {
	t.Helper()
	c.sweepContainers()
	name := fmt.Sprintf("gfs-e2e-%s-%d", sanitize(c.Name), time.Now().UnixNano())
	memory := opts.Memory
	if memory == "" {
		memory = EnvDefault("GFS_MEMORY_LIMIT", "2g")
	}
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = "/opt/gfs"
	}
	argv := []string{
		"podman", "run", "-d",
		"--name", name,
		"--label", "gofengshui.e2e=1",
		"--label", "gofengshui.case=" + sanitize(c.Name),
		"--label", "gofengshui.run=" + c.Run.ID,
		"--privileged",
		"--memory", memory,
		"--memory-swap", memory,
		"--security-opt", "seccomp=unconfined",
		"--security-opt", "apparmor=unconfined",
		"-v", "/sys/kernel/btf:/sys/kernel/btf:ro",
		"-v", c.Reports + ":/reports:Z",
		"-w", workDir,
	}
	for _, env := range append([]string{"GFS_BPF_LOG=" + EnvDefault("GFS_BPF_LOG", "1")}, opts.Env...) {
		argv = append(argv, "-e", env)
	}
	useOOMGroup := false
	if data, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err == nil && strings.Contains(string(data), "memory") {
		argv = append(argv, "--cgroup-conf", "memory.oom.group=0")
		useOOMGroup = true
	}
	for _, mount := range opts.Mounts {
		spec := mount.Host + ":" + mount.Container
		if mount.ReadOnly {
			spec += ":ro"
		}
		argv = append(argv, "-v", spec)
	}
	argv = append(argv, opts.Image, "/bin/sh", "-c", "while true; do sleep 3600; done")
	res := c.Exec("container-run", ExecOptions{Timeout: 2 * time.Minute, AllowFailure: useOOMGroup}, argv...)
	if useOOMGroup && res.ExitCode != 0 {
		c.Logf("container run with memory.oom.group=0 failed; retrying without it: %s", strings.TrimSpace(string(res.Stderr)))
		retry := make([]string, 0, len(argv))
		for i := 0; i < len(argv); i++ {
			if argv[i] == "--cgroup-conf" {
				i++
				continue
			}
			retry = append(retry, argv[i])
		}
		res = c.Exec("container-run-retry", ExecOptions{Timeout: 2 * time.Minute}, retry...)
	}
	c.RequireSuccess("start container", res)
	container := &Container{
		Case: c,
		t:    t,
		Name: name,
		ID:   strings.TrimSpace(string(res.Stdout)),
	}
	c.Logf("container %s id=%s image=%s memory=%s", name, container.ID, opts.Image, memory)
	t.Cleanup(func() {
		container.Cleanup()
	})
	return container
}

func (c *Case) sweepContainers() {
	res := c.Exec("container-sweep", ExecOptions{Timeout: time.Minute, AllowFailure: true},
		"podman", "ps", "-aq", "--filter", "label=gofengshui.e2e=1")
	if res.ExitCode != 0 {
		return
	}
	ids := strings.Fields(string(res.Stdout))
	if len(ids) == 0 {
		return
	}
	argv := append([]string{"podman", "rm", "-f"}, ids...)
	sweep := c.Exec("container-sweep-rm", ExecOptions{Timeout: 2 * time.Minute, AllowFailure: true}, argv...)
	if sweep.ExitCode != 0 {
		c.Logf("stale container cleanup failed: %s", strings.TrimSpace(string(sweep.Stderr)))
	}
}

func (c *Container) Exec(name string, opts ExecOptions, args ...string) *Result {
	c.t.Helper()
	argv := []string{"podman", "exec", "-w", "/opt/gfs"}
	for _, env := range opts.Env {
		argv = append(argv, "-e", env)
	}
	argv = append(argv, c.Name)
	argv = append(argv, args...)
	opts.Env = nil
	return c.Case.Exec(name, opts, argv...)
}

func (c *Container) CopyTo(hostPath, containerPath string) {
	c.t.Helper()
	dir := path.Dir(containerPath)
	c.Exec("container-mkdir", ExecOptions{Timeout: time.Minute}, "mkdir", "-p", dir)
	res := c.Case.Exec("container-copy", ExecOptions{Timeout: 2 * time.Minute},
		"podman", "cp", hostPath, c.Name+":"+containerPath)
	c.Case.RequireSuccess("podman cp", res)
}

func (c *Container) Inspect() {
	c.t.Helper()
	res := c.Case.Exec("container-inspect", ExecOptions{Timeout: time.Minute, AllowFailure: true},
		"podman", "inspect", c.Name)
	c.Case.WriteJSON("container", map[string]any{
		"name":    c.Name,
		"id":      c.ID,
		"inspect": string(res.Stdout),
		"stderr":  string(res.Stderr),
	})
}

func (c *Container) Cleanup() {
	c.Inspect()
	if EnvBool("GFS_E2E_KEEP") {
		c.Case.Logf("keeping container %s", c.Name)
		return
	}
	res := c.Case.Exec("container-remove", ExecOptions{Timeout: 2 * time.Minute, AllowFailure: true},
		"podman", "rm", "-f", c.Name)
	if res.ExitCode != 0 {
		c.Case.Logf("container remove failed: %s", strings.TrimSpace(string(res.Stderr)))
	}
}

func ReportPath(root, name string) string {
	return filepath.Join(root, sanitize(name))
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
