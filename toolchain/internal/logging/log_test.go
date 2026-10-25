package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewCreatesLogAndLatestSymlink(t *testing.T) {
	dir := t.TempDir()
	log, err := New(filepath.Join(dir, "logs"), "build-image")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := log.Writer.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	data, err := os.ReadFile(log.Path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("log contents = %q", data)
	}
	link := filepath.Join(dir, "logs", "latest-build-image.log")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != log.Path {
		t.Fatalf("symlink target = %q want %q", target, log.Path)
	}
	if !strings.Contains(filepath.Base(log.Path), "build-image-") {
		t.Fatalf("log name = %q", log.Path)
	}
}
