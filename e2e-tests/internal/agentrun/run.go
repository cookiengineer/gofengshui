package agentrun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gofengshui/e2e/internal/checks"
)

type Runner struct {
	Bin      string
	Reports  string
	Testdata string
	Temp     string
	Env      []string
}

type Options struct {
	Args         []string
	Target       []string
	Env          []string
	Stdin        string
	Timeout      time.Duration
	AllowFailure bool
}

type Result struct {
	Name       string
	Args       []string
	Stdout     []byte
	Stderr     []byte
	ExitCode   int
	Duration   time.Duration
	Err        error
	ReportDir  string
	EventsPath string
	StderrPath string
}

func NewRunner(t testing.TB) *Runner {
	t.Helper()
	bin := os.Getenv("GFS_BIN")
	if bin == "" {
		bin = "/usr/local/bin/gofengshui"
	}
	reports := os.Getenv("GFS_REPORTS")
	if reports == "" {
		reports = "/reports"
	}
	testdata := os.Getenv("GFS_TESTDATA")
	if testdata == "" {
		testdata = "/opt/gfs/testdata"
	}
	temp := os.Getenv("GFS_TMP")
	if temp == "" {
		temp = filepath.Join("/tmp", "gfs-e2e", sanitize(t.Name()))
	}
	if err := os.MkdirAll(reports, 0o755); err != nil {
		t.Fatalf("create reports directory: %v", err)
	}
	if err := os.MkdirAll(temp, 0o755); err != nil {
		t.Fatalf("create temp directory: %v", err)
	}
	return &Runner{Bin: bin, Reports: reports, Testdata: testdata, Temp: temp}
}

func (r *Runner) ReportDir(name string) string {
	return filepath.Join(r.Reports, sanitize(name))
}

func (r *Runner) EventsPath(name string) string {
	return filepath.Join(r.Reports, sanitize(name)+".events.jsonl")
}

func (r *Runner) StderrPath(name string) string {
	return filepath.Join(r.Reports, sanitize(name)+".stderr")
}

func (r *Runner) Run(t testing.TB, name string, opts Options) *Result {
	t.Helper()
	dir := r.ReportDir(name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create report directory: %v", err)
	}
	args := append([]string{"run"}, opts.Args...)
	args = append(args, "--report", dir)
	args = append(args, "--stdout", filepath.Join(dir, "target.stdout"))
	args = append(args, "--stderr", filepath.Join(dir, "target.stderr"))
	if len(opts.Target) > 0 {
		args = append(args, "--")
		args = append(args, opts.Target...)
	}
	res := r.exec(t, name, args, opts)
	res.ReportDir = dir
	res.EventsPath = r.EventsPath(name)
	res.StderrPath = r.StderrPath(name)
	_ = os.WriteFile(res.EventsPath, res.Stdout, 0o644)
	_ = os.WriteFile(res.StderrPath, res.Stderr, 0o644)
	return res
}

func (r *Runner) Validate(t testing.TB, name string, opts Options) *Result {
	t.Helper()
	dir := r.ReportDir(name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create report directory: %v", err)
	}
	args := append([]string{"validate"}, opts.Args...)
	args = append(args, "--report", dir)
	args = append(args, "--stdout", filepath.Join(dir, "target.stdout"))
	args = append(args, "--stderr", filepath.Join(dir, "target.stderr"))
	if len(opts.Target) > 0 {
		args = append(args, "--")
		args = append(args, opts.Target...)
	}
	res := r.exec(t, name, args, opts)
	res.ReportDir = dir
	res.EventsPath = r.EventsPath(name)
	res.StderrPath = r.StderrPath(name)
	_ = os.WriteFile(res.EventsPath, res.Stdout, 0o644)
	_ = os.WriteFile(res.StderrPath, res.Stderr, 0o644)
	return res
}

func (r *Runner) Attach(t testing.TB, name string, opts Options) *Result {
	t.Helper()
	dir := r.ReportDir(name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create report directory: %v", err)
	}
	args := append([]string{"attach"}, opts.Args...)
	args = append(args, "--report", dir)
	args = append(args, "--stdout", filepath.Join(dir, "target.stdout"))
	args = append(args, "--stderr", filepath.Join(dir, "target.stderr"))
	res := r.exec(t, name, args, opts)
	res.ReportDir = dir
	res.EventsPath = r.EventsPath(name)
	res.StderrPath = r.StderrPath(name)
	_ = os.WriteFile(res.EventsPath, res.Stdout, 0o644)
	_ = os.WriteFile(res.StderrPath, res.Stderr, 0o644)
	return res
}

func (r *Runner) Cmd(t testing.TB, name string, args []string, opts Options) *Result {
	t.Helper()
	res := r.exec(t, name, args, opts)
	res.ReportDir = r.ReportDir(name)
	res.EventsPath = r.EventsPath(name)
	res.StderrPath = r.StderrPath(name)
	return res
}

func (r *Runner) Program(t testing.TB, name string, args []string, opts Options) *Result {
	t.Helper()
	res := r.execArgv(t, name, args, opts)
	res.ReportDir = r.ReportDir(name)
	res.EventsPath = filepath.Join(r.Reports, sanitize(name)+".stdout")
	res.StderrPath = filepath.Join(r.Reports, sanitize(name)+".stderr")
	_ = os.WriteFile(res.EventsPath, res.Stdout, 0o644)
	_ = os.WriteFile(res.StderrPath, res.Stderr, 0o644)
	return res
}

func (r *Runner) exec(t testing.TB, name string, args []string, opts Options) *Result {
	t.Helper()
	return r.execArgv(t, name, append([]string{r.Bin}, args...), opts)
}

func (r *Runner) execArgv(t testing.TB, name string, argv []string, opts Options) *Result {
	t.Helper()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	env := mergeEnv(os.Environ(), append(append([]string{}, r.Env...), opts.Env...))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = workDir()
	cmd.Env = env
	if opts.Stdin != "" {
		cmd.Stdin = strings.NewReader(opts.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	t.Logf("[agent] $ %s", strings.Join(argv, " "))
	started := time.Now()
	err := cmd.Run()
	res := &Result{
		Name:     name,
		Args:     argv,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: time.Since(started),
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
	t.Logf("[agent]   exit=%d duration=%s", res.ExitCode, res.Duration.Round(time.Millisecond))
	if res.Err != nil && !opts.AllowFailure {
		t.Fatalf("%s failed: %v\nstdout:\n%s\nstderr:\n%s", name, res.Err, tail(res.Stdout, 40), tail(res.Stderr, 40))
	}
	return res
}

func (r *Result) RequireSuccess(t testing.TB) *Result {
	t.Helper()
	if r.ExitCode != 0 {
		t.Fatalf("%s failed with exit %d\nstdout:\n%s\nstderr:\n%s",
			r.Name, r.ExitCode, tail(r.Stdout, 40), tail(r.Stderr, 40))
	}
	return r
}

func (r *Result) Frames(t testing.TB) []checks.Frame {
	t.Helper()
	frames, err := checks.ParseFrames(r.Stdout)
	if err != nil {
		t.Fatalf("%s: parse frames: %v\n%s", r.Name, err, tail(r.Stdout, 20))
	}
	return frames
}

func (r *Result) Heap(t testing.TB) checks.HeapReport {
	t.Helper()
	return checks.LoadHeap(t, filepath.Join(r.ReportDir, "heap.json"))
}

func (r *Result) Report(t testing.TB) string {
	t.Helper()
	return string(checks.RequireFile(t, filepath.Join(r.ReportDir, "report.md")))
}

func (r *Result) Summary(t testing.TB) checks.SummaryReport {
	t.Helper()
	return checks.LoadSummary(t, filepath.Join(r.ReportDir, "summary.json"))
}

func (r *Runner) StdioRequests(t testing.TB, name string, requests []checks.Request, opts Options) *Result {
	t.Helper()
	var b strings.Builder
	for _, req := range requests {
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	opts.Stdin = b.String()
	return r.Run(t, name, opts)
}

func workDir() string {
	if info, err := os.Stat("/opt/gfs"); err == nil && info.IsDir() {
		return "/opt/gfs"
	}
	return ""
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
