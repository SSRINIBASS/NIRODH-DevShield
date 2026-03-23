package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NIRODH/devshield/pkg/schema"
)

func TestWriteHTML(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.html")

	if err := WriteHTML(sampleResult(), outPath); err != nil {
		t.Fatalf("WriteHTML() error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read HTML output: %v", err)
	}

	html := string(data)

	// Should be valid HTML
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Missing <!DOCTYPE html>")
	}
	if !strings.Contains(html, "<html") {
		t.Error("Missing <html> tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("Missing closing </html> tag")
	}

	// Should contain report elements
	if !strings.Contains(html, "DevShield Security Report") {
		t.Error("Missing report title")
	}
	if !strings.Contains(html, "/test/project") {
		t.Error("Missing project path in report")
	}
	if !strings.Contains(html, "gitleaks") {
		t.Error("Missing tool name in report")
	}
}

func TestWriteHTML_EmptyFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "empty.html")

	if err := WriteHTML(emptyResult(), outPath); err != nil {
		t.Fatalf("WriteHTML() error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read HTML output: %v", err)
	}

	html := string(data)
	if !strings.Contains(html, "No security findings detected") {
		t.Error("Should show 'no findings' message for empty results")
	}
}

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		sev    schema.Severity
		expect string
	}{
		{schema.SeverityCritical, "#dc2626"},
		{schema.SeverityHigh, "#ea580c"},
		{schema.SeverityMedium, "#d97706"},
		{schema.SeverityLow, "#2563eb"},
		{schema.SeverityInfo, "#6b7280"},
		{schema.Severity("unknown"), "#6b7280"},
	}
	for _, tc := range tests {
		if got := severityColor(tc.sev); got != tc.expect {
			t.Errorf("severityColor(%q) = %q, want %q", tc.sev, got, tc.expect)
		}
	}
}

func TestSeverityBgColor(t *testing.T) {
	tests := []struct {
		sev    schema.Severity
		expect string
	}{
		{schema.SeverityCritical, "#fef2f2"},
		{schema.SeverityHigh, "#fff7ed"},
		{schema.SeverityMedium, "#fffbeb"},
		{schema.SeverityLow, "#eff6ff"},
		{schema.SeverityInfo, "#f9fafb"},
	}
	for _, tc := range tests {
		if got := severityBgColor(tc.sev); got != tc.expect {
			t.Errorf("severityBgColor(%q) = %q, want %q", tc.sev, got, tc.expect)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds float64
		expect  string
	}{
		{0.1, "100ms"},
		{0.001, "1ms"},
		{0.5, "500ms"},
		{1.0, "1.0s"},
		{2.5, "2.5s"},
		{60.0, "60.0s"},
	}
	for _, tc := range tests {
		if got := formatDuration(tc.seconds); got != tc.expect {
			t.Errorf("formatDuration(%f) = %q, want %q", tc.seconds, got, tc.expect)
		}
	}
}
