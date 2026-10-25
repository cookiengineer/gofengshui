package repo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GFS_REPO_ROOT", dir)
	got, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	want, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Root = %q want %q", got, want)
	}
}

func TestRootWalksUp(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "source"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source", "go.mod"), []byte("module test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(nested); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	t.Setenv("GFS_REPO_ROOT", "")
	got, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if got != root {
		t.Fatalf("Root = %q want %q", got, root)
	}
}
