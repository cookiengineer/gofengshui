package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gofengshui/toolchain/internal/execx"
	"gofengshui/toolchain/internal/logging"
	"gofengshui/toolchain/internal/podman"
	"gofengshui/toolchain/internal/repo"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "build-image:", err)
		os.Exit(1)
	}
}

func run() error {
	tag := flag.String("tag", podman.DefaultImage, "image tag to build")
	containerfile := flag.String("containerfile", "e2e-tests/glibc/Containerfile", "Containerfile path, relative to the repository root")
	noBuild := flag.Bool("no-build", false, "skip make build and reuse build/gofengshui")
	dryRun := flag.Bool("dry-run", false, "print commands without running them")
	flag.Parse()

	root, err := repo.Root()
	if err != nil {
		return err
	}
	path := *containerfile
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}

	runner := execx.New()
	runner.DryRun = *dryRun
	stdout := io.Writer(os.Stdout)
	var log *logging.Log
	if !*dryRun {
		log, err = logging.New(filepath.Join(root, "build", "logs"), "build-image")
		if err != nil {
			return err
		}
		defer log.Close()
		stdout = io.MultiWriter(os.Stdout, log.Writer)
		runner.Stdout = stdout
		runner.Stderr = stdout
		fmt.Fprintf(stdout, "=== build image %s ===\n", time.Now().Format(time.RFC3339))
	}
	if !*noBuild {
		if err := runner.Run(root, "make", "build"); err != nil {
			return err
		}
	}
	name, args := execx.Sudo("podman", podman.BuildArgs(*tag, path)...)
	if err := runner.Run(root, name, args...); err != nil {
		return err
	}
	if log != nil {
		fmt.Fprintf(stdout, "built %s in rootful podman storage\n", *tag)
		fmt.Fprintf(stdout, "log: %s\n", log.Path)
	}
	return nil
}
