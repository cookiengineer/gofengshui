package execx

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatQuotesUnsafeArguments(t *testing.T) {
	got := Format("podman", []string{"run", "hello world", "plain", ""})
	if !strings.Contains(got, `"hello world"`) {
		t.Fatalf("Format = %q", got)
	}
	if !strings.Contains(got, `""`) {
		t.Fatalf("Format = %q", got)
	}
	if !strings.Contains(got, "plain") {
		t.Fatalf("Format = %q", got)
	}
}

func TestRunnerDryRun(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{DryRun: true, Stdout: &out}
	if err := runner.Run("/tmp", "podman", "run", "hello world"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "podman run \"hello world\"") {
		t.Fatalf("output = %q", got)
	}
}
