package checks

import (
	"os"
	"strings"
	"testing"
	"time"
)

func Eventually(t testing.TB, timeout, interval time.Duration, fn func() bool, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, label)
		}
		time.Sleep(interval)
	}
}

func WaitForFile(t testing.TB, path string, timeout time.Duration) {
	t.Helper()
	Eventually(t, timeout, 25*time.Millisecond, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, "file "+path)
}

func WaitForSocket(t testing.TB, path string, timeout time.Duration) {
	t.Helper()
	Eventually(t, timeout, 25*time.Millisecond, func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Mode()&os.ModeSocket != 0
	}, "socket "+path)
}

func WaitForText(t testing.TB, path, needle string, timeout time.Duration) {
	t.Helper()
	Eventually(t, timeout, 25*time.Millisecond, func() bool {
		data, err := os.ReadFile(path)
		return err == nil && len(data) > 0 && strings.Contains(string(data), needle)
	}, needle+" in "+path)
}

func WaitForExit(t testing.TB, done <-chan struct{}, timeout time.Duration, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for %s", timeout, label)
	}
}
