package suppress

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NIRODH/devshield/pkg/schema"
)

func TestNewEngine_NoIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	e, err := NewEngine(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	if e == nil {
		t.Fatal("NewEngine() returned nil")
	}
	if len(e.suppressions) != 0 {
		t.Errorf("suppressions = %d, want 0", len(e.suppressions))
	}
}

func TestNewEngine_WithIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	content := `# Comment line
finding-id-1 # reason: Test fixture expires: 2099-12-31
finding-id-2 # reason: False positive

`
	ignorePath := filepath.Join(tmpDir, ".devshield-ignore")
	if err := os.WriteFile(ignorePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	e, err := NewEngine(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	if len(e.suppressions) != 2 {
		t.Fatalf("suppressions = %d, want 2", len(e.suppressions))
	}

	// Check first suppression
	if e.suppressions[0].ID != "finding-id-1" {
		t.Errorf("ID = %q, want %q", e.suppressions[0].ID, "finding-id-1")
	}
	if e.suppressions[0].Reason != "Test fixture" {
		t.Errorf("Reason = %q, want %q", e.suppressions[0].Reason, "Test fixture")
	}
	if e.suppressions[0].Expires == nil {
		t.Error("Expires is nil, want non-nil")
	}

	// Check second suppression
	if e.suppressions[1].ID != "finding-id-2" {
		t.Errorf("ID = %q, want %q", e.suppressions[1].ID, "finding-id-2")
	}
	if e.suppressions[1].Reason != "False positive" {
		t.Errorf("Reason = %q, want %q", e.suppressions[1].Reason, "False positive")
	}
}

func TestNewEngine_WithConfigSuppressions(t *testing.T) {
	tmpDir := t.TempDir()

	cs := []ConfigSuppression{
		{ID: "config-sup-1", Reason: "Config reason", Expires: "2099-12-31"},
		{ID: "config-sup-2", Reason: "Another reason"},
	}

	e, err := NewEngine(tmpDir, cs)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	if len(e.suppressions) != 2 {
		t.Fatalf("suppressions = %d, want 2", len(e.suppressions))
	}

	if e.suppressions[0].Expires == nil {
		t.Error("First config suppression Expires is nil, want non-nil")
	}
	if e.suppressions[1].Expires != nil {
		t.Error("Second config suppression Expires should be nil")
	}
}

func TestApply_MatchByFingerprint(t *testing.T) {
	tmpDir := t.TempDir()

	e, _ := NewEngine(tmpDir, []ConfigSuppression{
		{ID: "fp-abc123", Reason: "Test"},
	})

	findings := []schema.Finding{
		{ID: "gitleaks:rule:file:1", Fingerprint: "fp-abc123", Severity: schema.SeverityHigh},
		{ID: "gitleaks:rule:file:2", Fingerprint: "fp-other", Severity: schema.SeverityHigh},
	}

	result := e.Apply(findings)

	if !result[0].Suppressed {
		t.Error("Finding with matching fingerprint should be suppressed")
	}
	if result[1].Suppressed {
		t.Error("Finding with non-matching fingerprint should not be suppressed")
	}
}

func TestApply_MatchByID(t *testing.T) {
	tmpDir := t.TempDir()

	e, _ := NewEngine(tmpDir, []ConfigSuppression{
		{ID: "gitleaks:rule:file:1", Reason: "By ID"},
	})

	findings := []schema.Finding{
		{ID: "gitleaks:rule:file:1", Fingerprint: "something-else", Severity: schema.SeverityHigh},
	}

	result := e.Apply(findings)
	if !result[0].Suppressed {
		t.Error("Finding matching by ID should be suppressed")
	}
}

func TestApply_ExpiredSuppression(t *testing.T) {
	tmpDir := t.TempDir()

	// Expired suppression (past date)
	e, _ := NewEngine(tmpDir, []ConfigSuppression{
		{ID: "expired-id", Reason: "Old", Expires: "2020-01-01"},
	})

	findings := []schema.Finding{
		{ID: "expired-id", Severity: schema.SeverityHigh},
	}

	result := e.Apply(findings)
	if result[0].Suppressed {
		t.Error("Finding with expired suppression should NOT be suppressed")
	}
}

func TestApply_FutureSuppression(t *testing.T) {
	tmpDir := t.TempDir()

	e, _ := NewEngine(tmpDir, []ConfigSuppression{
		{ID: "future-id", Reason: "Still active", Expires: "2099-12-31"},
	})

	findings := []schema.Finding{
		{ID: "future-id", Severity: schema.SeverityHigh},
	}

	result := e.Apply(findings)
	if !result[0].Suppressed {
		t.Error("Finding with future suppression should be suppressed")
	}
}

func TestApply_NoSuppressions(t *testing.T) {
	tmpDir := t.TempDir()

	e, _ := NewEngine(tmpDir, nil)
	findings := []schema.Finding{
		{ID: "some-id", Severity: schema.SeverityHigh},
	}

	result := e.Apply(findings)
	if result[0].Suppressed {
		t.Error("With no suppressions, finding should not be suppressed")
	}
}

func TestParseIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	content := `# This is a comment

finding-abc # reason: Test reason expires: 2099-06-15
finding-def
finding-ghi # reason: Just a reason

`
	path := filepath.Join(tmpDir, "ignore")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	sups, err := parseIgnoreFile(path)
	if err != nil {
		t.Fatalf("parseIgnoreFile() error: %v", err)
	}

	if len(sups) != 3 {
		t.Fatalf("parseIgnoreFile() returned %d suppressions, want 3", len(sups))
	}

	// First entry: has reason + expires
	if sups[0].ID != "finding-abc" {
		t.Errorf("[0].ID = %q, want %q", sups[0].ID, "finding-abc")
	}
	if sups[0].Reason != "Test reason" {
		t.Errorf("[0].Reason = %q, want %q", sups[0].Reason, "Test reason")
	}
	if sups[0].Expires == nil {
		t.Error("[0].Expires is nil, want 2099-06-15")
	}

	// Second: ID only
	if sups[1].ID != "finding-def" {
		t.Errorf("[1].ID = %q, want %q", sups[1].ID, "finding-def")
	}
	if sups[1].Reason != "" {
		t.Errorf("[1].Reason = %q, want empty", sups[1].Reason)
	}

	// Third: reason no expires
	if sups[2].ID != "finding-ghi" {
		t.Errorf("[2].ID = %q, want %q", sups[2].ID, "finding-ghi")
	}
	if sups[2].Reason != "Just a reason" {
		t.Errorf("[2].Reason = %q, want %q", sups[2].Reason, "Just a reason")
	}
	if sups[2].Expires != nil {
		t.Error("[2].Expires should be nil")
	}
}
