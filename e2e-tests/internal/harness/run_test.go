package harness

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"hello world":      "hello_world",
		"a/b:c":            "a_b_c",
		"already-fine_1.0": "already-fine_1.0",
		"":                 "unnamed",
	}
	for input, want := range cases {
		if got := sanitize(input); got != want {
			t.Fatalf("sanitize(%q) = %q want %q", input, got, want)
		}
	}
}

func TestMergeEnvOverrides(t *testing.T) {
	got := mergeEnv([]string{"A=1", "B=2"}, []string{"B=3", "C=4"})
	want := []string{"A=1", "B=3", "C=4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeEnv = %v want %v", got, want)
	}
}

func TestRepoRoot(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "source", "go.mod")); err != nil {
		t.Fatalf("RepoRoot missing source/go.mod: %v", err)
	}
}

func TestImageTag(t *testing.T) {
	t.Setenv("GFS_IMAGE_PREFIX", "example.invalid/e2e")
	t.Setenv("GFS_IMAGE_TAG", "")
	if got := ImageTag("glibc", "ubuntu-24.04"); got != "example.invalid/e2e/glibc:ubuntu-24.04" {
		t.Fatalf("ImageTag = %q", got)
	}
	t.Setenv("GFS_IMAGE_TAG", "override")
	if got := ImageTag("glibc", "ubuntu-24.04"); got != "example.invalid/e2e/glibc:override" {
		t.Fatalf("ImageTag override = %q", got)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("GFS_TEST_BOOL", "yes")
	if !EnvBool("GFS_TEST_BOOL") {
		t.Fatal("EnvBool should accept yes")
	}
	t.Setenv("GFS_TEST_DEFAULT", "")
	if got := EnvDefault("GFS_TEST_DEFAULT", "fallback"); got != "fallback" {
		t.Fatalf("EnvDefault = %q", got)
	}
}
