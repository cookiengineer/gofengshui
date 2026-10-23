package agentrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartAgentUsesRunnerBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-agent")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake agent: %v", err)
	}
	r := &Runner{Bin: bin, Reports: dir, Temp: dir}
	p := r.StartAgent(t, "agent", filepath.Join(dir, "agent.sock"), Options{Timeout: 5 * time.Second})
	p.Wait(t, 5*time.Second)
	data, err := os.ReadFile(p.StdoutPath)
	if err != nil {
		t.Fatalf("read agent stdout: %v", err)
	}
	if !strings.Contains(string(data), "agent\n--socket\n"+filepath.Join(dir, "agent.sock")) {
		t.Fatalf("unexpected agent args:\n%s", data)
	}
}
