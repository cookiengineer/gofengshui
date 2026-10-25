package execx

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

type Runner struct {
	DryRun bool
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func New() *Runner {
	return &Runner{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

func Sudo(name string, args ...string) (string, []string) {
	if os.Geteuid() == 0 {
		return name, args
	}
	return "sudo", append([]string{name}, args...)
}

func Format(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quote(name))
	for _, arg := range args {
		parts = append(parts, quote(arg))
	}
	return strings.Join(parts, " ")
}

func (r *Runner) Run(dir, name string, args ...string) error {
	if r.DryRun {
		_, _ = fmt.Fprintln(r.output(), Format(name, append([]string(nil), args...)))
		return nil
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdin = r.Stdin
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", Format(name, args), err)
	}
	return nil
}

func (r *Runner) Succeeds(dir, name string, args ...string) bool {
	if r.DryRun {
		_, _ = fmt.Fprintln(r.output(), Format(name, append([]string(nil), args...)))
		return true
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func (r *Runner) Replace(dir, name string, args ...string) error {
	if r.DryRun {
		_, _ = fmt.Fprintln(r.output(), Format(name, append([]string(nil), args...)))
		return nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	argv := append([]string{path}, args...)
	return syscall.Exec(path, argv, os.Environ())
}

func (r *Runner) output() io.Writer {
	if r.Stdout != nil {
		return r.Stdout
	}
	return os.Stdout
}

func quote(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\n\"'\\$`;&|<>()*?[]{}!") {
		return fmt.Sprintf("%q", value)
	}
	return value
}
