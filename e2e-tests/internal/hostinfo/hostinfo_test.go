package hostinfo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSysctls(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "proc/sys/kernel/unprivileged_bpf_disabled"), "2\n")
	write(t, filepath.Join(root, "proc/sys/kernel/perf_event_paranoid"), "2\n")
	write(t, filepath.Join(root, "proc/sys/kernel/yama/ptrace_scope"), "1\n")
	items := ReadSysctls(root)
	if len(items) != len(sysctlPaths) {
		t.Fatalf("ReadSysctls returned %d items", len(items))
	}
	if !items[0].Present || items[0].Value != "2" {
		t.Fatalf("unexpected sysctl: %+v", items[0])
	}
}

func TestReadSysctlsMissing(t *testing.T) {
	items := ReadSysctls(t.TempDir())
	for _, item := range items {
		if item.Present {
			t.Fatalf("unexpected present sysctl: %+v", item)
		}
	}
}

func TestNotes(t *testing.T) {
	info := Info{
		BTF: true,
		Sysctls: []Sysctl{
			{Path: "/proc/sys/kernel/unprivileged_bpf_disabled", Value: "2", Present: true},
			{Path: "/proc/sys/kernel/yama/ptrace_scope", Value: "1", Present: true},
		},
	}
	notes := strings.Join(Notes(info), "\n")
	if !strings.Contains(notes, "rootless podman cannot load eBPF") {
		t.Fatalf("missing bpf note: %q", notes)
	}
	if !strings.Contains(notes, "yama ptrace_scope is non-zero") {
		t.Fatalf("missing ptrace note: %q", notes)
	}
}

func TestNotesForPermissiveHost(t *testing.T) {
	info := Info{
		BTF: true,
		Sysctls: []Sysctl{
			{Path: "/proc/sys/kernel/unprivileged_bpf_disabled", Value: "0", Present: true},
			{Path: "/proc/sys/kernel/yama/ptrace_scope", Value: "0", Present: true},
		},
	}
	if notes := Notes(info); len(notes) != 0 {
		t.Fatalf("unexpected notes: %v", notes)
	}
}

func TestWriteText(t *testing.T) {
	info := Info{
		Uname:   "Linux test",
		BTFPath: "/sys/kernel/btf/vmlinux",
		BTF:     true,
		Sysctls: []Sysctl{
			{Path: "/proc/sys/kernel/unprivileged_bpf_disabled", Value: "0", Present: true},
		},
		Tools:          []Tool{{Name: "go", Path: "/usr/bin/go", Present: true}},
		Capabilities:   []string{"CapEff: 0000000000000000"},
		PodmanVersion:  "5.0.0",
		PodmanRootless: "rootless=false",
		Notes:          []string{"none"},
	}
	var out bytes.Buffer
	info.WriteText(&out)
	text := out.String()
	for _, want := range []string{"== host ==", "Linux test", "present", "unprivileged_bpf_disabled", "/usr/bin/go", "CapEff", "5.0.0", "rootless=false", "none"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func write(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
