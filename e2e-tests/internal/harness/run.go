package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gofengshui/e2e/internal/hostinfo"
)

type Run struct {
	t       *testing.T
	Root    string
	Dir     string
	ID      string
	Started time.Time
}

type Case struct {
	*Run
	t       *testing.T
	Name    string
	Dir     string
	Logs    string
	Reports string
	mu      sync.Mutex
}

type ExecOptions struct {
	Dir          string
	Env          []string
	Stdin        string
	Timeout      time.Duration
	AllowFailure bool
	Quiet        bool
}

type Result struct {
	Args     []string
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
	Err      error
}

func (r *Result) String() string {
	return strings.Join(r.Args, " ")
}

func RepoRoot() (string, error) {
	if root := os.Getenv("GFS_REPO_ROOT"); root != "" {
		return filepath.Abs(root)
	}
	_, file, _, ok := runtime.Caller(0)
	if ok {
		root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
		if _, err := os.Stat(filepath.Join(root, "source", "go.mod")); err == nil {
			return root, nil
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "source", "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("repository root not found")
		}
		wd = parent
	}
}

func NewRun(t *testing.T) *Run {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	now := time.Now().UTC()
	id := fmt.Sprintf("%s-%d", now.Format("20060102-150405"), os.Getpid())
	dir := filepath.Join(root, "build", "e2e", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create run directory: %v", err)
	}
	r := &Run{t: t, Root: root, Dir: dir, ID: id, Started: now}
	r.writeRunMetadata()
	return r
}

func (r *Run) writeRunMetadata() {
	meta := map[string]any{
		"id":      r.ID,
		"started": r.Started.Format(time.RFC3339),
		"root":    r.Root,
		"pid":     os.Getpid(),
	}
	if out, err := exec.Command("git", "-C", r.Root, "rev-parse", "HEAD").Output(); err == nil {
		meta["commit"] = strings.TrimSpace(string(out))
	}
	if uname := hostinfo.Uname(); uname != "" {
		meta["uname"] = uname
	}
	if out, err := exec.Command("go", "version").Output(); err == nil {
		meta["go"] = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("podman", "version", "--format", "{{.Client.Version}}").Output(); err == nil {
		meta["podman"] = strings.TrimSpace(string(out))
	}
	for _, item := range hostinfo.ReadSysctls("/") {
		if item.Present {
			meta[filepath.Base(item.Path)] = item.Value
		}
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(filepath.Join(r.Dir, "run.json"), append(data, '\n'), 0o644)
}

func (r *Run) NewCase(name string) *Case {
	return r.NewCaseFor(r.t, name)
}

func (r *Run) NewCaseFor(t *testing.T, name string) *Case {
	t.Helper()
	dir := filepath.Join(r.Dir, sanitize(name))
	logs := filepath.Join(dir, "logs")
	reports := filepath.Join(dir, "reports")
	for _, path := range []string{logs, reports} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create case directory %s: %v", path, err)
		}
	}
	return &Case{
		Run:     r,
		t:       t,
		Name:    name,
		Dir:     dir,
		Logs:    logs,
		Reports: reports,
	}
}

func (c *Case) Logf(format string, args ...any) {
	c.t.Helper()
	msg := fmt.Sprintf(format, args...)
	c.t.Logf("[%s] %s", c.Name, msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := os.OpenFile(filepath.Join(c.Logs, "host.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), msg)
		_ = f.Close()
	}
}

func (c *Case) WriteJSON(name string, v any) {
	c.t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		c.t.Fatalf("marshal %s: %v", name, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(c.Logs, sanitize(name)+".json"), data, 0o644); err != nil {
		c.t.Fatalf("write %s: %v", name, err)
	}
}

func (c *Case) Exec(name string, opts ExecOptions, argv ...string) *Result {
	c.t.Helper()
	if len(argv) == 0 {
		c.t.Fatal("empty command")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	dir := opts.Dir
	if dir == "" {
		dir = c.Root
	}
	env := mergeEnv(os.Environ(), opts.Env)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = env
	if opts.Stdin != "" {
		cmd.Stdin = strings.NewReader(opts.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	c.Logf("$ (cd %s && %s)", dir, strings.Join(argv, " "))
	started := time.Now()
	err := cmd.Run()
	elapsed := time.Since(started)
	res := &Result{
		Args:     append([]string(nil), argv...),
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: 0,
		Duration: elapsed,
		Err:      err,
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			res.ExitCode = -1
			res.Err = fmt.Errorf("timeout after %s", timeout)
		} else {
			res.ExitCode = -1
		}
	}
	c.writeCommandArtifacts(name, res)
	c.Logf("  exit=%d duration=%s stdout=%d bytes stderr=%d bytes", res.ExitCode, elapsed.Round(time.Millisecond), len(res.Stdout), len(res.Stderr))
	if res.Err != nil && !opts.AllowFailure {
		c.t.Fatalf("command failed: %s: %v\n%s", res.String(), res.Err, tail(res.Stderr, 40))
	}
	return res
}

func (c *Case) writeCommandArtifacts(name string, res *Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	base := filepath.Join(c.Logs, sanitize(name))
	_ = os.WriteFile(base+".stdout", res.Stdout, 0o644)
	_ = os.WriteFile(base+".stderr", res.Stderr, 0o644)
	f, err := os.OpenFile(filepath.Join(c.Logs, "commands.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		_, _ = fmt.Fprintf(f, "%s exit=%d duration=%s args=%s\n",
			time.Now().UTC().Format(time.RFC3339), res.ExitCode, res.Duration, strings.Join(res.Args, " "))
		_ = f.Close()
	}
}

func (c *Case) RequireSuccess(name string, res *Result) {
	c.t.Helper()
	if res.ExitCode != 0 {
		c.t.Fatalf("%s failed with exit %d\nstdout:\n%s\nstderr:\n%s",
			name, res.ExitCode, tail(res.Stdout, 40), tail(res.Stderr, 40))
	}
}

func mergeEnv(base, extra []string) []string {
	values := make(map[string]string, len(base)+len(extra))
	order := make([]string, 0, len(base)+len(extra))
	add := func(item string) {
		key, val, ok := strings.Cut(item, "=")
		if !ok {
			return
		}
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = val
	}
	for _, item := range base {
		add(item)
	}
	for _, item := range extra {
		add(item)
	}
	out := make([]string, 0, len(order))
	for _, key := range order {
		out = append(out, key+"="+values[key])
	}
	return out
}

func sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

func tail(data []byte, lines int) string {
	text := strings.TrimRight(string(data), "\n")
	if text == "" {
		return "(empty)"
	}
	parts := strings.Split(text, "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

func EnvBool(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes"
}

func EnvDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
