package export

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gofengshui/core"
	"gofengshui/heap"
	"gofengshui/proto"
)

// JSON writes an indented JSON document.
func JSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// JSONL writes one JSON object per line.
func JSONL(path string, frames []*proto.Frame) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, frame := range frames {
		if err := enc.Encode(frame); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ROPReport is kept generic to avoid an import cycle with the agent package.
type ROPReport interface {
	IsVerified() bool
}

// Report writes a human-readable summary.
func Report(path, session string, target core.Target, profile heap.Profile, stats heap.Stats, sink any, rop any, findings []core.Finding) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Go Heap FengShui report\n\n")
	fmt.Fprintf(&b, "- Session: `%s`\n", session)
	fmt.Fprintf(&b, "- Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Target PID: %d\n", target.PID)
	fmt.Fprintf(&b, "- Executable: `%s`\n", target.ExePath)
	fmt.Fprintf(&b, "- libc: `%s`\n", target.LibcPath)
	fmt.Fprintf(&b, "- Allocator: %s (source: %s)\n", profile.String(), profile.Source)
	fmt.Fprintf(&b, "- Allocations: %d (live %d, freed %d)\n", stats.Allocations, stats.Live, stats.Freed)
	fmt.Fprintf(&b, "- Tombstones: %d\n", stats.Tombstones)
	fmt.Fprintf(&b, "- mmap regions: %d\n\n", stats.Mappings)

	fmt.Fprintf(&b, "## Findings\n\n")
	if len(findings) == 0 {
		fmt.Fprintf(&b, "No findings recorded.\n\n")
	} else {
		for _, f := range findings {
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", f.ID, f.Severity, f.Message)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Sink\n\n")
	if sink == nil {
		fmt.Fprintf(&b, "No sink registered or reached.\n\n")
	} else {
		fmt.Fprintf(&b, "```json\n%s\n```\n\n", mustJSON(sink))
	}

	fmt.Fprintf(&b, "## ROP\n\n")
	if rop == nil {
		fmt.Fprintf(&b, "No ROP trace captured.\n")
	} else {
		fmt.Fprintf(&b, "```json\n%s\n```\n", mustJSON(rop))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%q", err.Error())
	}
	return string(b)
}
