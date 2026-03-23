package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NIRODH/devshield/pkg/schema"
)

func sampleResult() *schema.ScanResult {
	return &schema.ScanResult{
		Version:             "dev",
		ScanTimestamp:        "2026-03-23T00:00:00Z",
		ScanDurationSeconds: 1.5,
		ProjectPath:         "/test/project",
		Context: schema.ScanResultContext{
			Languages: []schema.Language{"go"},
			HasGit:    true,
		},
		Summary: schema.SeveritySummary{
			Critical: 1, High: 2, Medium: 1, Low: 0, Info: 1, Total: 5,
		},
		ToolsUsed: []schema.ToolInfo{
			{Name: "gitleaks", Version: "8.30.1", FindingsCount: 5, DurationMs: 100},
		},
		Findings: []schema.Finding{
			{
				ID:          "gitleaks:aws-key:config.yaml:10",
				Tool:        "gitleaks",
				Category:    schema.CategorySecrets,
				Severity:    schema.SeverityCritical,
				Title:       "AWS Access Key Found",
				Description: "Hard-coded AWS access key.",
				File:        "config.yaml",
				Line:        10,
				RuleID:      "aws-access-key-id",
				CWEID:       "CWE-798",
				Fingerprint: "abc123def456",
			},
			{
				ID:       "gitleaks:generic:env:5",
				Tool:     "gitleaks",
				Category: schema.CategorySecrets,
				Severity: schema.SeverityHigh,
				Title:    "Generic Secret Detected",
				File:     ".env",
				Line:     5,
				RuleID:   "generic-api-key",
			},
		},
	}
}

func emptyResult() *schema.ScanResult {
	return &schema.ScanResult{
		Version:             "dev",
		ScanTimestamp:        "2026-03-23T00:00:00Z",
		ScanDurationSeconds: 0.1,
		ProjectPath:         "/test/project",
		Summary:             schema.SeveritySummary{},
		ToolsUsed: []schema.ToolInfo{
			{Name: "gitleaks", Version: "8.30.1", FindingsCount: 0, DurationMs: 50},
		},
		Findings: []schema.Finding{},
	}
}

func TestWriteJSON(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.json")

	if err := WriteJSON(sampleResult(), outPath); err != nil {
		t.Fatalf("WriteJSON() error: %v", err)
	}

	// Read and parse the output
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var parsed schema.ScanResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if parsed.Version != "dev" {
		t.Errorf("Version = %q, want %q", parsed.Version, "dev")
	}
	if len(parsed.Findings) != 2 {
		t.Errorf("Findings count = %d, want 2", len(parsed.Findings))
	}
	if parsed.ProjectPath != "/test/project" {
		t.Errorf("ProjectPath = %q, want %q", parsed.ProjectPath, "/test/project")
	}
}

func TestWriteJSON_EmptyFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "empty.json")

	if err := WriteJSON(emptyResult(), outPath); err != nil {
		t.Fatalf("WriteJSON() error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var parsed schema.ScanResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if len(parsed.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(parsed.Findings))
	}
}
