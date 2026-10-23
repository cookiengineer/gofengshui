package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gofengshui/core"
	"gofengshui/heap"
)

type HeapReport struct {
	Allocations   []core.Allocation   `json:"allocations"`
	Tombstones    []heap.Tombstone    `json:"tombstones"`
	Mappings      []heap.Mmap         `json:"mappings"`
	Stats         heap.Stats          `json:"stats"`
	Profile       heap.Profile        `json:"profile"`
	Analysis      heap.Analysis       `json:"analysis"`
	Backfill      *heap.BackfillStats `json:"backfill"`
	Introspection *heap.Introspection `json:"introspection"`
	Findings      []core.Finding      `json:"findings"`
	BPF           json.RawMessage     `json:"bpf"`
}

type SummaryReport struct {
	Session  string              `json:"session"`
	Target   core.Target         `json:"target"`
	Config   core.Config         `json:"config"`
	Profile  heap.Profile        `json:"profile"`
	Stats    heap.Stats          `json:"stats"`
	Markers  []any               `json:"markers"`
	Backfill *heap.BackfillStats `json:"backfill"`
	BPF      json.RawMessage     `json:"bpf"`
}

func LoadHeap(t testing.TB, path string) HeapReport {
	t.Helper()
	var report HeapReport
	DecodeJSON(t, RequireFile(t, path), &report, path)
	return report
}

func LoadSummary(t testing.TB, path string) SummaryReport {
	t.Helper()
	var report SummaryReport
	DecodeJSON(t, RequireFile(t, path), &report, path)
	return report
}

func RequireReportFile(t testing.TB, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	RequireFile(t, path)
	return path
}

func RequireTextContains(t testing.TB, path, needle, label string) {
	t.Helper()
	RequireContains(t, string(RequireFile(t, path)), needle, label)
}

func RequireFindingID(t testing.TB, findings []core.Finding, id string) core.Finding {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return f
		}
	}
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	t.Fatalf("finding %s missing; got %s", id, Summary(ids))
	return core.Finding{}
}

func RequireHeapFinding(t testing.TB, report HeapReport, id string) core.Finding {
	t.Helper()
	return RequireFindingID(t, report.Findings, id)
}

func RequireProfileVersion(t testing.TB, report HeapReport, version string) {
	t.Helper()
	if report.Profile.Version != version {
		t.Fatalf("profile version: got %q want %q", report.Profile.Version, version)
	}
}

func RequireProfileSource(t testing.TB, report HeapReport, source string) {
	t.Helper()
	if report.Profile.Source != source {
		t.Fatalf("profile source: got %q want %q", report.Profile.Source, source)
	}
}

func RequireDir(t testing.TB, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", path)
	}
}
