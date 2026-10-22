package symbols

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Mapping is one line from /proc/<pid>/maps.
type Mapping struct {
	Start  uint64 `json:"start"`
	End    uint64 `json:"end"`
	Offset uint64 `json:"offset"`
	Perm   string `json:"perm"`
	Path   string `json:"path"`
	Inode  uint64 `json:"inode"`
}

func (m Mapping) Size() uint64 { return m.End - m.Start }
func (m Mapping) Contains(addr uint64) bool {
	return addr >= m.Start && addr < m.End
}

// Symbol is an ELF function/service symbol.
type Symbol struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Size  uint64 `json:"size"`
	Type  uint8  `json:"type"`
	Bind  uint8  `json:"bind"`
}

// Module is an ELF file mapped into a target process.
type Module struct {
	Path    string    `json:"path"`
	FSPath  string    `json:"fs_path,omitempty"`
	Base    uint64    `json:"base"`
	Maps    []Mapping `json:"maps"`
	ELFTyp  elf.Type  `json:"elf_type"`
	Symbols []Symbol  `json:"-"`
	byName  map[string]Symbol
	sorted  []Symbol
}

// Resolver resolves runtime addresses in one process.
type Resolver struct {
	PID     int
	Modules []*Module
	byPath  map[string]*Module
	mu      sync.RWMutex
}

func NewResolver(pid int) (*Resolver, error) {
	maps, err := ReadMaps(pid)
	if err != nil {
		return nil, err
	}
	r := &Resolver{PID: pid, byPath: make(map[string]*Module)}
	seen := make(map[string]*Module)
	for _, m := range maps {
		if m.Path == "" || strings.HasPrefix(m.Path, "[") {
			continue
		}
		key := m.Path
		mod, ok := seen[key]
		if !ok {
			mod = &Module{Path: m.Path, FSPath: targetPath(pid, m.Path), Base: m.Start, ELFTyp: elf.ET_DYN}
			if m.Offset != 0 {
				mod.Base = m.Start - m.Offset
			}
			seen[key] = mod
			r.Modules = append(r.Modules, mod)
			r.byPath[key] = mod
			if f, err := elf.Open(mod.FSPath); err == nil {
				mod.ELFTyp = f.Type
				f.Close()
			}
			if mod.ELFTyp == elf.ET_EXEC {
				mod.Base = 0
			}
			if err := mod.loadSymbols(); err != nil {
				// Keep the module for address->mapping resolution even if the
				// symbol table is stripped.
				mod.Symbols = nil
			}
		}
		mod.Maps = append(mod.Maps, m)
	}
	sort.Slice(r.Modules, func(i, j int) bool {
		return moduleStart(r.Modules[i]) < moduleStart(r.Modules[j])
	})
	return r, nil
}

func moduleStart(m *Module) uint64 {
	if len(m.Maps) == 0 {
		return 0
	}
	start := m.Maps[0].Start
	for _, mm := range m.Maps[1:] {
		if mm.Start < start {
			start = mm.Start
		}
	}
	return start
}

func (m *Module) loadSymbols() error {
	f, err := elf.Open(m.FSPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var syms []elf.Symbol
	if s, err := f.Symbols(); err == nil {
		syms = append(syms, s...)
	}
	if s, err := f.DynamicSymbols(); err == nil {
		syms = append(syms, s...)
	}
	m.byName = make(map[string]Symbol)
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC && elf.ST_TYPE(s.Info) != elf.STT_OBJECT {
			continue
		}
		sym := Symbol{
			Name: s.Name, Value: s.Value, Size: s.Size,
			Type: uint8(elf.ST_TYPE(s.Info)), Bind: uint8(elf.ST_BIND(s.Info)),
		}
		if _, exists := m.byName[s.Name]; !exists {
			m.byName[s.Name] = sym
		}
		m.sorted = append(m.sorted, sym)
	}
	sort.Slice(m.sorted, func(i, j int) bool { return m.sorted[i].Value < m.sorted[j].Value })
	return nil
}

// ModuleFor returns the module containing a runtime address.
func (r *Resolver) ModuleFor(addr uint64) *Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, m := range r.Modules {
		for _, mm := range m.Maps {
			if mm.Contains(addr) {
				return m
			}
		}
	}
	return nil
}

// Name resolves a symbol in the module containing moduleHint or in any module.
func (r *Resolver) Name(moduleHint, name string) (Symbol, *Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if moduleHint != "" {
		if m := r.byPath[moduleHint]; m != nil {
			if s, ok := m.byName[name]; ok {
				return s, m, true
			}
		}
	}
	for _, m := range r.Modules {
		if s, ok := m.byName[name]; ok {
			return s, m, true
		}
	}
	return Symbol{}, nil, false
}

// RuntimeAddr computes the runtime address for a symbol.
func (m *Module) RuntimeAddr(s Symbol) uint64 {
	if m.ELFTyp == elf.ET_EXEC {
		return s.Value
	}
	return m.Base + s.Value
}

// Addr resolves a runtime address to module, symbol and offset.
type AddrInfo struct {
	Module     *Module `json:"-"`
	ModulePath string  `json:"module"`
	Symbol     string  `json:"symbol"`
	Offset     uint64  `json:"offset"`
	Base       uint64  `json:"base"`
}

func (r *Resolver) Addr(addr uint64) AddrInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, m := range r.Modules {
		for _, mm := range m.Maps {
			if !mm.Contains(addr) {
				continue
			}
			info := AddrInfo{Module: m, ModulePath: m.Path, Base: m.Base}
			rel := addr
			if m.ELFTyp != elf.ET_EXEC {
				if addr < m.Base {
					continue
				}
				rel = addr - m.Base
			}
			i := sort.Search(len(m.sorted), func(i int) bool { return m.sorted[i].Value > rel })
			if i > 0 {
				s := m.sorted[i-1]
				info.Symbol = s.Name
				info.Offset = rel - s.Value
			}
			return info
		}
	}
	return AddrInfo{}
}

// ReadMaps parses /proc/<pid>/maps.
func ReadMaps(pid int) ([]Mapping, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Mapping
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		m, ok := parseMapLine(sc.Text())
		if ok {
			out = append(out, m)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseMapLine(line string) (Mapping, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Mapping{}, false
	}
	parts := strings.SplitN(fields[0], "-", 2)
	if len(parts) != 2 {
		return Mapping{}, false
	}
	start, err1 := strconv.ParseUint(parts[0], 16, 64)
	end, err2 := strconv.ParseUint(parts[1], 16, 64)
	off, err3 := strconv.ParseUint(fields[2], 16, 64)
	inode, err4 := strconv.ParseUint(fields[4], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return Mapping{}, false
	}
	path := ""
	if len(fields) > 5 {
		path = strings.Join(fields[5:], " ")
	}
	return Mapping{Start: start, End: end, Offset: off, Perm: fields[1], Path: path, Inode: inode}, true
}

// LibcPath returns a target-accessible path to libc.
func LibcPath(pid int) (string, error) {
	maps, err := ReadMaps(pid)
	if err != nil {
		return "", err
	}
	for _, m := range maps {
		base := filepath.Base(m.Path)
		if strings.HasPrefix(base, "libc.so") || strings.HasPrefix(base, "libc-") {
			return targetPath(pid, m.Path), nil
		}
	}
	return "", fmt.Errorf("libc mapping not found for pid %d", pid)
}

// ExePath returns a target-accessible path to the executable.
func ExePath(pid int) (string, error) {
	p := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	target, err := os.Readlink(p)
	if err != nil {
		return "", err
	}
	target = strings.TrimSuffix(target, " (deleted)")
	if _, err := os.Stat(target); err == nil {
		return target, nil
	}
	return targetPath(pid, target), nil
}

func targetPath(pid int, path string) string {
	candidate := filepath.Join("/proc", strconv.Itoa(pid), "root", path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return path
}

// InitPID translates a PID in the current namespace to the initial PID
// namespace PID used by bpf_get_current_pid_tgid.
func InitPID(pid int) (uint32, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("empty NSpid for pid %d", pid)
		}
		// NSpid lists outer namespaces first. With only one value we are
		// looking at /proc from the same PID namespace and cannot know the
		// initial-namespace PID (e.g. inside a container).
		if len(fields) < 3 {
			return 0, fmt.Errorf("pid %d is only visible in the current PID namespace", pid)
		}
		v, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(v), nil
	}
	return 0, fmt.Errorf("NSpid not found for pid %d", pid)
}

// CgroupID returns the cgroup v2 id used by bpf_get_current_cgroup_id.
func CgroupID(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		rel := strings.TrimPrefix(line, "0::")
		rel = strings.TrimSpace(rel)
		path := "/sys/fs/cgroup"
		if rel != "" && rel != "/" {
			path = filepath.Join(path, rel)
		}
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			return 0, err
		}
		return st.Ino, nil
	}
	return 0, fmt.Errorf("cgroup v2 entry not found for pid %d", pid)
}

// ResolveTarget fills a core.Target-like description without importing core.
type TargetInfo struct {
	PID      int
	InitPID  uint32
	CgroupID uint64
	ExePath  string
	LibcPath string
	LibcBase uint64
	ExeBase  uint64
}

func ResolveTarget(pid int) (TargetInfo, error) {
	var t TargetInfo
	t.PID = pid
	if v, err := InitPID(pid); err == nil {
		t.InitPID = v
	}
	if v, err := CgroupID(pid); err == nil {
		t.CgroupID = v
	}
	if v, err := ExePath(pid); err == nil {
		t.ExePath = v
	}
	if v, err := LibcPath(pid); err == nil {
		t.LibcPath = v
	}
	r, err := NewResolver(pid)
	if err != nil {
		return t, err
	}
	if t.LibcPath != "" {
		for _, m := range r.Modules {
			if strings.Contains(filepath.Base(m.Path), "libc") {
				t.LibcBase = m.Base
			}
		}
	}
	if t.ExePath != "" {
		for _, m := range r.Modules {
			if m.Path == t.ExePath {
				t.ExeBase = m.Base
			}
		}
	}
	return t, nil
}

// EntryPoint returns the ELF entry virtual address and type.
func EntryPoint(path string) (uint64, elf.Type, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	return f.Entry, f.Type, nil
}

// RuntimeEntry resolves the executable entry point in a running process.
func RuntimeEntry(pid int) (uint64, error) {
	exe, err := ExePath(pid)
	if err != nil {
		return 0, err
	}
	entry, typ, err := EntryPoint(exe)
	if err != nil {
		return 0, err
	}
	if typ == elf.ET_EXEC {
		return entry, nil
	}
	r, err := NewResolver(pid)
	if err != nil {
		return 0, err
	}
	for _, m := range r.Modules {
		if sameFile(m.Path, exe) || strings.TrimSuffix(m.Path, " (deleted)") == strings.TrimSuffix(exe, " (deleted)") {
			return m.Base + entry, nil
		}
	}
	return 0, fmt.Errorf("executable mapping not found for %s", exe)
}

func sameFile(a, b string) bool {
	a = strings.TrimSuffix(a, " (deleted)")
	b = strings.TrimSuffix(b, " (deleted)")
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return filepath.Base(a) == filepath.Base(b)
	}
	return os.SameFile(fa, fb)
}
