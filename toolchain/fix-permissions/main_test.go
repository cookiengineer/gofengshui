package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestChownTree(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "a", "b.txt")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if err := chownTree(root, uid, gid); err != nil {
		t.Fatalf("chownTree: %v", err)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat type unavailable")
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf("ownership = %d:%d want %d:%d", stat.Uid, stat.Gid, uid, gid)
	}
}

func TestChownTreeMissingPath(t *testing.T) {
	if err := chownTree(filepath.Join(t.TempDir(), "missing"), os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("chownTree missing path: %v", err)
	}
}

func TestCurrentID(t *testing.T) {
	t.Setenv("GFS_TEST_UID", "1234")
	if got := currentID("GFS_TEST_UID", 1); got != 1234 {
		t.Fatalf("currentID = %d", got)
	}
	t.Setenv("GFS_TEST_UID", "")
	if got := currentID("GFS_TEST_UID", 1); got != 1 {
		t.Fatalf("currentID fallback = %d", got)
	}
	t.Setenv("GFS_TEST_UID", "invalid")
	if got := currentID("GFS_TEST_UID", 2); got != 2 {
		t.Fatalf("currentID invalid = %d", got)
	}
}

func TestDisplayPath(t *testing.T) {
	root := t.TempDir()
	if got := displayPath(root, filepath.Join(root, "build")); got != "build" {
		t.Fatalf("displayPath = %q", got)
	}
	if got := displayPath(root, "/elsewhere"); got != "/elsewhere" {
		t.Fatalf("displayPath outside = %q", got)
	}
}
