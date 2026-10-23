package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func RequireFile(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return data
}

func RequireContains(t testing.TB, haystack, needle, label string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%s: missing %q", label, needle)
	}
}

func RequireNotContains(t testing.TB, haystack, needle, label string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Fatalf("%s: unexpected %q", label, needle)
	}
}

func RequireEqual[T comparable](t testing.TB, got, want T, label string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v want %v", label, got, want)
	}
}

func DecodeJSON(t testing.TB, data []byte, v any, label string) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v\n%s", label, err, string(data))
	}
}

func DecodeResult(t testing.TB, f Frame, v any) {
	t.Helper()
	if len(f.Result) == 0 {
		t.Fatalf("frame %d has no result", f.ID)
	}
	if err := json.Unmarshal(f.Result, v); err != nil {
		t.Fatalf("decode result %d: %v\n%s", f.ID, err, string(f.Result))
	}
}

func Failf(t testing.TB, format string, args ...any) {
	t.Helper()
	t.Fatalf(format, args...)
}

func Summary(ids []string) string {
	if len(ids) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%v", ids)
}
