package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ImageTag(caseName, variant string) string {
	prefix := EnvDefault("GFS_IMAGE_PREFIX", "localhost/gofengshui-e2e")
	if variant == "" {
		variant = "dev"
	}
	if override := os.Getenv("GFS_IMAGE_TAG"); override != "" {
		variant = override
	}
	return fmt.Sprintf("%s/%s:%s", prefix, caseName, variant)
}

func (c *Case) BuildAgent() {
	c.t.Helper()
	if EnvBool("GFS_SKIP_BUILD") {
		binary := filepath.Join(c.Root, "build", "gofengshui")
		if _, err := os.Stat(binary); err != nil {
			c.t.Fatalf("GFS_SKIP_BUILD=1 but %s is missing", binary)
		}
		return
	}
	res := c.Exec("build-agent", ExecOptions{Timeout: 15 * time.Minute}, "make", "build")
	c.RequireSuccess("make build", res)
}

func (c *Case) RequireBaseImage(t *testing.T, image string) {
	t.Helper()
	if EnvBool("GFS_E2E_PULL") {
		return
	}
	if !c.ImageExists(image) {
		t.Skipf("base image %s is not available locally; set GFS_E2E_PULL=1 to pull it", image)
	}
}

func (c *Case) ImageExists(tag string) bool {
	c.t.Helper()
	res := c.Exec("image-exists-"+sanitize(tag), ExecOptions{Timeout: time.Minute, AllowFailure: true}, "podman", "image", "exists", tag)
	return res.ExitCode == 0
}

func (c *Case) BuildImage(tag, containerfile string, buildArgs map[string]string) string {
	c.t.Helper()
	if EnvBool("GFS_SKIP_BUILD") {
		if !c.ImageExists(tag) {
			c.t.Fatalf("GFS_SKIP_BUILD=1 but image %s is missing", tag)
		}
		return tag
	}
	argv := []string{"podman", "build", "-t", tag, "-f", containerfile}
	if !EnvBool("GFS_E2E_PULL") {
		argv = append(argv, "--pull=never")
	}
	for key, value := range buildArgs {
		argv = append(argv, "--build-arg", key+"="+value)
	}
	argv = append(argv, ".")
	res := c.Exec("podman-build", ExecOptions{Dir: c.Root, Timeout: 30 * time.Minute}, argv...)
	c.RequireSuccess("podman build", res)
	inspect := c.Exec("image-inspect-"+sanitize(tag), ExecOptions{Timeout: time.Minute, AllowFailure: true},
		"podman", "image", "inspect", tag, "--format", "id={{.Id}} created={{.Created}}")
	c.Logf("image %s: %s", tag, strings.TrimSpace(string(inspect.Stdout)))
	return tag
}

func (c *Case) BuildVictimTest(pkg, outName string) string {
	c.t.Helper()
	out := filepath.Join(c.Dir, outName)
	res := c.Exec("build-victim-"+sanitize(outName), ExecOptions{
		Dir:     c.Root,
		Env:     []string{"CGO_ENABLED=0"},
		Timeout: 15 * time.Minute,
	}, "go", "-C", "e2e-tests", "test", "-c", "-tags", "victim", "-o", out, pkg)
	c.RequireSuccess("build victim test", res)
	return out
}
