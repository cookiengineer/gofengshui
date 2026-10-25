package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gofengshui/toolchain/internal/execx"
	"gofengshui/toolchain/internal/podman"
	"gofengshui/toolchain/internal/repo"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "host-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	image := flag.String("image", podman.DefaultImage, "container image to run")
	name := flag.String("name", "gofengshui-host-agent", "container name")
	socket := flag.String("socket", "/run/gofengshui/gofengshui.sock", "agent socket path inside the container")
	dryRun := flag.Bool("dry-run", false, "print the podman command without running it")
	flag.Parse()

	root, err := repo.Root()
	if err != nil {
		return err
	}
	runDir := filepath.Join(root, "build", "run")
	reports := filepath.Join(root, "build", "reports")
	runner := execx.New()
	runner.DryRun = *dryRun
	if !*dryRun {
		for _, dir := range []string{runDir, reports} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		existsName, existsArgs := execx.Sudo("podman", podman.ImageExistsArgs(*image)...)
		if !runner.Succeeds(root, existsName, existsArgs...) {
			return fmt.Errorf("image %s is missing from rootful podman storage; run: make dev-image", *image)
		}
	}

	opts := podman.RunOptions{
		Name:        *name,
		Image:       *image,
		Privileged:  true,
		PIDHost:     true,
		Interactive: true,
		Remove:      true,
		SecurityOpts: []string{
			"seccomp=unconfined",
			"apparmor=unconfined",
		},
		Mounts: []podman.Mount{
			{Host: "/sys/kernel/btf", Container: "/sys/kernel/btf", Options: "ro"},
			{Host: runDir, Container: "/run/gofengshui", Options: "Z"},
			{Host: reports, Container: "/reports", Options: "Z"},
		},
		Command: []string{"gofengshui", "agent", "--socket", *socket},
	}
	nameArg, args := execx.Sudo("podman", podman.RunArgs(opts)...)
	return runner.Replace(root, nameArg, args...)
}
