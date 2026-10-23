package agentrun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type Process struct {
	Name       string
	Args       []string
	StdoutPath string
	StderrPath string
	PID        int
	cmd        *exec.Cmd
	done       chan struct{}
	mu         sync.Mutex
	err        error
	stopped    bool
}

func (r *Runner) StartAgent(t testing.TB, name, socket string, opts Options) *Process {
	t.Helper()
	return r.StartProcess(t, name, append([]string{r.Bin, "agent", "--socket", socket}, opts.Args...), opts)
}

func (r *Runner) StartTarget(t testing.TB, name string, target []string, opts Options) *Process {
	t.Helper()
	return r.StartProcess(t, name, target, opts)
}

func (r *Runner) StartProcess(t testing.TB, name string, args []string, opts Options) *Process {
	t.Helper()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	stdoutPath := filepath.Join(r.Reports, sanitize(name)+".stdout")
	stderrPath := filepath.Join(r.Reports, sanitize(name)+".stderr")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatalf("create %s: %v", stdoutPath, err)
	}
	stderr, err := os.Create(stderrPath)
	if err != nil {
		_ = stdout.Close()
		t.Fatalf("create %s: %v", stderrPath, err)
	}
	env := mergeEnv(os.Environ(), append(append([]string{}, r.Env...), opts.Env...))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = workDir()
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if opts.Stdin != "" {
		cmd.Stdin = strings.NewReader(opts.Stdin)
	}
	t.Logf("[agent] start %s", strings.Join(args, " "))
	if err := cmd.Start(); err != nil {
		cancel()
		_ = stdout.Close()
		_ = stderr.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	p := &Process{
		Name:       name,
		Args:       append([]string(nil), args...),
		StdoutPath: stdoutPath,
		StderrPath: stderrPath,
		PID:        cmd.Process.Pid,
		cmd:        cmd,
		done:       make(chan struct{}),
	}
	go func() {
		err := cmd.Wait()
		_ = stdout.Close()
		_ = stderr.Close()
		cancel()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	}()
	t.Cleanup(func() {
		p.Kill()
	})
	return p
}

func (p *Process) Done() <-chan struct{} {
	return p.done
}

func (p *Process) Wait(t testing.TB, timeout time.Duration) error {
	t.Helper()
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.err != nil {
			t.Fatalf("%s exited with error: %v\nstderr:\n%s", p.Name, p.err, tailFile(p.StderrPath, 40))
		}
		return p.err
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", p.Name)
		return nil
	}
}

func (p *Process) Kill() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	cmd := p.cmd
	p.mu.Unlock()
	select {
	case <-p.done:
		return
	default:
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func (p *Process) ExitCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		return 0
	}
	if exitErr, ok := p.err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

func tailFile(path string, lines int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(read %s: %v)", path, err)
	}
	return tail(data, lines)
}
