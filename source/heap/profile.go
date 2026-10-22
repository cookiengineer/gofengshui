package heap

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Profile describes the glibc allocator behavior that matters to the heap
// model. The values are intentionally limited to x86_64 defaults.
type Profile struct {
	Version         string `json:"version"`
	Major           int    `json:"major"`
	Minor           int    `json:"minor"`
	Source          string `json:"source"`
	Tcache          bool   `json:"tcache"`
	TcacheBins      int    `json:"tcache_bins"`
	TcacheMaxChunk  uint64 `json:"tcache_max_chunk"`
	TcacheCount     int    `json:"tcache_count"`
	TcacheKey       bool   `json:"tcache_key"`
	SafeLinking     bool   `json:"safe_linking"`
	FastbinMaxChunk uint64 `json:"fastbin_max_chunk"`
}

var (
	glibcVersionRe = regexp.MustCompile(`GNU C Library[^\x00\n]*?version\s+([0-9]+)\.([0-9]+)`)
	glibcSymbolRe  = regexp.MustCompile(`GLIBC_([0-9]+)\.([0-9]+)`)
	versionRe      = regexp.MustCompile(`([0-9]+)\.([0-9]+)`)
)

// DefaultProfile returns the profile used when no libc can be inspected.
func DefaultProfile() Profile {
	p, _ := ProfileForVersion("2.44")
	p.Source = "default"
	return p
}

// ProfileForVersion builds an x86_64 glibc profile for a version string such
// as "2.31" or "glibc 2.35".
func ProfileForVersion(version string) (Profile, bool) {
	m := versionRe.FindStringSubmatch(version)
	if m == nil {
		return Profile{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major != 2 {
		return Profile{}, false
	}
	p := Profile{
		Version:         fmt.Sprintf("%d.%d", major, minor),
		Major:           major,
		Minor:           minor,
		Source:          "override",
		FastbinMaxChunk: 0x80,
	}
	if minor >= 26 {
		p.Tcache = true
		p.TcacheBins = 64
		p.TcacheMaxChunk = 0x410
		p.TcacheCount = 7
	}
	if minor >= 29 {
		p.TcacheKey = true
	}
	if minor >= 32 {
		p.SafeLinking = true
	}
	return p, true
}

// DetectProfile inspects the target's libc to determine the allocator
// profile. It never fails: an unreadable or unrecognized libc falls back to
// DefaultProfile.
func DetectProfile(pid int, libcPath string) Profile {
	for _, path := range profileCandidates(pid, libcPath) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if p, ok := parseProfileMetadata(string(data)); ok {
			return p
		}
	}
	return DefaultProfile()
}

func profileCandidates(pid int, libcPath string) []string {
	if libcPath == "" {
		return nil
	}
	out := []string{libcPath}
	if pid > 0 && !strings.HasPrefix(libcPath, "/proc/") {
		out = append(out, filepath.Join("/proc", strconv.Itoa(pid), "root", libcPath))
	}
	return out
}

func parseProfileMetadata(data string) (Profile, bool) {
	if m := glibcVersionRe.FindStringSubmatch(data); m != nil {
		p, ok := ProfileForVersion(m[1] + "." + m[2])
		if ok {
			p.Source = "libc-string"
			return p, true
		}
	}
	bestMajor, bestMinor := 0, 0
	for _, m := range glibcSymbolRe.FindAllStringSubmatch(data, -1) {
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		if major > bestMajor || (major == bestMajor && minor > bestMinor) {
			bestMajor, bestMinor = major, minor
		}
	}
	if bestMajor > 0 {
		p, ok := ProfileForVersion(fmt.Sprintf("%d.%d", bestMajor, bestMinor))
		if ok {
			p.Source = "version-defs"
			return p, true
		}
	}
	return Profile{}, false
}

// String returns a short human-readable profile description.
func (p Profile) String() string {
	safe := "raw"
	if p.SafeLinking {
		safe = "safe-linking"
	}
	tcache := "no-tcache"
	if p.Tcache {
		tcache = "tcache"
	}
	return fmt.Sprintf("glibc %s (%s, %s)", p.Version, tcache, safe)
}
