package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NIRODH/devshield/pkg/schema"
)

func TestWriteSARIF_EmptyFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.sarif")

	if err := WriteSARIF(emptyResult(), outPath); err != nil {
		t.Fatalf("WriteSARIF() error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read SARIF output: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Should contain SARIF version
	if v, ok := parsed["version"]; !ok || v != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", v)
	}

	// Should have at least one run (empty run for DevShield)
	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Error("SARIF should have at least one run")
	}
}

func TestWriteSARIF_WithFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.sarif")

	if err := WriteSARIF(sampleResult(), outPath); err != nil {
		t.Fatalf("WriteSARIF() error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read SARIF output: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("No runs in SARIF output")
	}

	// Check that the run has results
	run := runs[0].(map[string]interface{})
	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatal("Run has no results")
	}
	if len(results) != 2 {
		t.Errorf("Results count = %d, want 2", len(results))
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		sev    schema.Severity
		expect string
	}{
		{schema.SeverityCritical, "error"},
		{schema.SeverityHigh, "error"},
		{schema.SeverityMedium, "warning"},
		{schema.SeverityLow, "note"},
		{schema.SeverityInfo, "note"},
		{schema.Severity("unknown"), "none"},
	}
	for _, tc := range tests {
		if got := severityToSARIFLevel(tc.sev); got != tc.expect {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tc.sev, got, tc.expect)
		}
	}
}

func TestWriteSARIF_SuppressedFinding(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "suppressed.sarif")

	result := &schema.ScanResult{
		Version:       "dev",
		ScanTimestamp: "2026-03-23T00:00:00Z",
		ToolsUsed:    []schema.ToolInfo{{Name: "gitleaks", Version: "8.30.1"}},
		Findings: []schema.Finding{
			{
				Tool:       "gitleaks",
				Severity:   schema.SeverityHigh,
				Title:      "Suppressed Secret",
				File:       "test.txt",
				Line:       1,
				RuleID:     "generic-api-key",
				Suppressed: true,
			},
		},
	}

	if err := WriteSARIF(result, outPath); err != nil {
		t.Fatalf("WriteSARIF() error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	// Verify it's valid SARIF JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
}
