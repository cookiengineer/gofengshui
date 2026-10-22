package heap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileForVersion(t *testing.T) {
	cases := []struct {
		version     string
		tcache      bool
		tcacheKey   bool
		safeLinking bool
		tcacheCount int
		tcacheChunk uint64
		bins        int
		slotSize    int
		layout      string
		fastbins    bool
	}{
		{"2.25", false, false, false, 0, 0, 0, 0, "", true},
		{"2.31", true, true, false, 7, 0x410, 64, 1, TcacheLayoutLegacy, true},
		{"2.35", true, true, true, 7, 0x410, 64, 1, TcacheLayoutLegacy, true},
		{"2.42", true, true, true, 7, 0x410, 76, 2, TcacheLayoutModern, true},
		{"glibc 2.44", true, true, true, 16, 0x410, 76, 2, TcacheLayoutModern, false},
	}
	for _, c := range cases {
		p, ok := ProfileForVersion(c.version)
		if !ok {
			t.Fatalf("ProfileForVersion(%q) failed", c.version)
		}
		if p.Tcache != c.tcache || p.TcacheKey != c.tcacheKey ||
			p.SafeLinking != c.safeLinking || p.TcacheCount != c.tcacheCount ||
			p.TcacheMaxChunk != c.tcacheChunk || p.TcacheBins != c.bins ||
			p.TcacheSlotSize != c.slotSize || p.TcacheLayout != c.layout ||
			p.Fastbins != c.fastbins {
			t.Fatalf("ProfileForVersion(%q) = %#v", c.version, p)
		}
	}
	if _, ok := ProfileForVersion("nonsense"); ok {
		t.Fatal("expected invalid version to fail")
	}
}

func TestParseProfileMetadata(t *testing.T) {
	data := "GNU C Library (GNU libc) stable release version 2.39.\n" +
		"GLIBC_2.44 GLIBC_2.2.5\n"
	p, ok := parseProfileMetadata(data)
	if !ok {
		t.Fatal("expected libc string to be parsed")
	}
	if p.Version != "2.39" || p.Source != "libc-string" || !p.SafeLinking {
		t.Fatalf("unexpected profile: %#v", p)
	}
}

func TestParseProfileMetadataVersionDefs(t *testing.T) {
	p, ok := parseProfileMetadata("GLIBC_2.2.5 GLIBC_2.31 GLIBC_2.34")
	if !ok {
		t.Fatal("expected version definitions to be parsed")
	}
	if p.Version != "2.34" || p.Source != "version-defs" || !p.SafeLinking {
		t.Fatalf("unexpected profile: %#v", p)
	}
}

func TestDetectProfileFromFile(t *testing.T) {
	dir := t.TempDir()
	libc := filepath.Join(dir, "libc.so.6")
	if err := os.WriteFile(libc, []byte("GNU C Library stable release version 2.31.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := DetectProfile(0, libc)
	if p.Version != "2.31" || p.Source != "libc-string" || p.SafeLinking {
		t.Fatalf("unexpected profile: %#v", p)
	}
}
