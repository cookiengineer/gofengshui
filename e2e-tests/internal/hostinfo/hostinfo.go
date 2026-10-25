package hostinfo

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var sysctlPaths = []string{
	"/proc/sys/kernel/unprivileged_bpf_disabled",
	"/proc/sys/kernel/perf_event_paranoid",
	"/proc/sys/kernel/yama/ptrace_scope",
}

var toolNames = []string{"go", "clang", "llvm-strip", "make", "gcc", "podman", "sudo"}

type Sysctl struct {
	Path    string `json:"path"`
	Value   string `json:"value,omitempty"`
	Present bool   `json:"present"`
}

type Tool struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Present bool   `json:"present"`
}

type Info struct {
	Uname          string   `json:"uname"`
	BTFPath        string   `json:"btf_path"`
	BTF            bool     `json:"btf"`
	Sysctls        []Sysctl `json:"sysctls"`
	Tools          []Tool   `json:"tools"`
	Capabilities   []string `json:"capabilities"`
	PodmanVersion  string   `json:"podman_version,omitempty"`
	PodmanRootless string   `json:"podman_rootless,omitempty"`
	Notes          []string `json:"notes"`
}

func Collect(root string) Info {
	info := Info{
		Uname:   Uname(),
		BTFPath: "/sys/kernel/btf/vmlinux",
	}
	if _, err := os.Stat(hostPath(root, info.BTFPath)); err == nil {
		info.BTF = true
	}
	info.Sysctls = ReadSysctls(root)
	info.Tools = Tools()
	info.Capabilities = capabilities(hostPath(root, "/proc/self/status"))
	info.PodmanVersion = commandValue("podman", "version", "--format", "{{.Client.Version}}")
	info.PodmanRootless = commandValue("podman", "info", "--format", "rootless={{.Host.Security.Rootless}}")
	info.Notes = Notes(info)
	return info
}

func Uname() string {
	return commandValue("uname", "-a")
}

func ReadSysctls(root string) []Sysctl {
	result := make([]Sysctl, 0, len(sysctlPaths))
	for _, path := range sysctlPaths {
		item := Sysctl{Path: path}
		data, err := os.ReadFile(hostPath(root, path))
		if err == nil {
			item.Present = true
			item.Value = strings.TrimSpace(string(data))
		}
		result = append(result, item)
	}
	return result
}

func Tools() []Tool {
	result := make([]Tool, 0, len(toolNames))
	for _, name := range toolNames {
		item := Tool{Name: name}
		if path, err := exec.LookPath(name); err == nil {
			item.Present = true
			item.Path = path
		}
		result = append(result, item)
	}
	return result
}

func Notes(info Info) []string {
	var notes []string
	if value := sysctlValue(info.Sysctls, "/proc/sys/kernel/unprivileged_bpf_disabled"); value != "" && value != "0" {
		notes = append(notes,
			"unprivileged_bpf_disabled is set; rootless podman cannot load eBPF.",
			"Use make dev-container (rootful privileged podman).")
	}
	if value := sysctlValue(info.Sysctls, "/proc/sys/kernel/yama/ptrace_scope"); value != "" && value != "0" {
		notes = append(notes,
			"yama ptrace_scope is non-zero; same-container root with CAP_SYS_PTRACE",
			"or spawn-under-agent mode is required.")
	}
	if !info.BTF {
		notes = append(notes, info.BTFPath+" is missing; kernel BTF is required.")
	}
	return notes
}

func (info Info) WriteText(w io.Writer) {
	fmt.Fprintln(w, "== host ==")
	fmt.Fprintln(w, emptyFallback(info.Uname, "unavailable"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== eBPF / kernel features ==")
	state := "missing"
	if info.BTF {
		state = "present"
	}
	fmt.Fprintf(w, "%-55s %s\n", info.BTFPath, state)
	for _, item := range info.Sysctls {
		value := "missing"
		if item.Present {
			value = item.Value
		}
		fmt.Fprintf(w, "%-55s %s\n", item.Path, value)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== toolchain ==")
	for _, item := range info.Tools {
		value := "missing"
		if item.Present {
			value = item.Path
		}
		fmt.Fprintf(w, "%-12s %s\n", item.Name, value)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== capabilities ==")
	if len(info.Capabilities) == 0 {
		fmt.Fprintln(w, "unavailable")
	} else {
		for _, line := range info.Capabilities {
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== podman ==")
	fmt.Fprintln(w, emptyFallback(info.PodmanVersion, "unavailable"))
	fmt.Fprintln(w, emptyFallback(info.PodmanRootless, "unavailable"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "== notes ==")
	for _, note := range info.Notes {
		fmt.Fprintln(w, note)
	}
}

func capabilities(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapInh:") ||
			strings.HasPrefix(line, "CapPrm:") ||
			strings.HasPrefix(line, "CapEff:") ||
			strings.HasPrefix(line, "CapBnd:") {
			lines = append(lines, line)
		}
	}
	return lines
}

func sysctlValue(items []Sysctl, path string) string {
	for _, item := range items {
		if item.Path == path && item.Present {
			return item.Value
		}
	}
	return ""
}

func commandValue(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func emptyFallback(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func hostPath(root, path string) string {
	if root == "" || root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}
