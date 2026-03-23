package gitleaks

import (
	"testing"

	"github.com/NIRODH/devshield/pkg/schema"
	gitleaksReport "github.com/zricethezav/gitleaks/v8/report"
)

// =============================================================================
// Scanner interface tests
// =============================================================================

func TestScanner_Name(t *testing.T) {
	s := &Scanner{}
	if got := s.Name(); got != "gitleaks" {
		t.Errorf("Name() = %q, want %q", got, "gitleaks")
	}
}

func TestScanner_Category(t *testing.T) {
	s := &Scanner{}
	if got := s.Category(); got != schema.CategorySecrets {
		t.Errorf("Category() = %q, want %q", got, schema.CategorySecrets)
	}
}

func TestScanner_IsAvailable(t *testing.T) {
	s := &Scanner{}
	if !s.IsAvailable() {
		t.Error("IsAvailable() = false, want true (Go lib is always available)")
	}
}

func TestScanner_Version(t *testing.T) {
	s := &Scanner{}
	v, err := s.Version()
	if err != nil {
		t.Fatalf("Version() error: %v", err)
	}
	if v != "8.30.1" {
		t.Errorf("Version() = %q, want %q", v, "8.30.1")
	}
}

// =============================================================================
// mapSeverity tests
// =============================================================================

func TestMapSeverity_CriticalPatterns(t *testing.T) {
	criticalRules := []string{
		"aws-access-key-id",
		"aws-secret-access-key",
		"github-pat",
		"github-fine-grained-pat",
		"github-oauth",
		"gcp-api-key",
		"gcp-service-account",
		"private-key",
		"stripe-api-key",
	}
	for _, rule := range criticalRules {
		if got := mapSeverity(rule); got != schema.SeverityCritical {
			t.Errorf("mapSeverity(%q) = %q, want %q", rule, got, schema.SeverityCritical)
		}
	}
}

func TestMapSeverity_DefaultHigh(t *testing.T) {
	unknownRules := []string{
		"generic-api-key",
		"some-other-rule",
		"custom-pattern",
	}
	for _, rule := range unknownRules {
		if got := mapSeverity(rule); got != schema.SeverityHigh {
			t.Errorf("mapSeverity(%q) = %q, want %q", rule, got, schema.SeverityHigh)
		}
	}
}

// =============================================================================
// computeFingerprint tests
// =============================================================================

func TestComputeFingerprint_Deterministic(t *testing.T) {
	fp1 := computeFingerprint("rule1", "file.go", "secret123")
	fp2 := computeFingerprint("rule1", "file.go", "secret123")

	if fp1 != fp2 {
		t.Errorf("Fingerprints should be deterministic: %q != %q", fp1, fp2)
	}
	if len(fp1) != 32 {
		t.Errorf("Fingerprint length = %d, want 32 hex chars", len(fp1))
	}
}

func TestComputeFingerprint_UniquePerInput(t *testing.T) {
	fp1 := computeFingerprint("rule1", "file.go", "secret123")
	fp2 := computeFingerprint("rule2", "file.go", "secret123")
	fp3 := computeFingerprint("rule1", "other.go", "secret123")
	fp4 := computeFingerprint("rule1", "file.go", "different")

	if fp1 == fp2 {
		t.Error("Different rules should produce different fingerprints")
	}
	if fp1 == fp3 {
		t.Error("Different files should produce different fingerprints")
	}
	if fp1 == fp4 {
		t.Error("Different matches should produce different fingerprints")
	}
}

// =============================================================================
// truncateSecret tests
// =============================================================================

func TestTruncateSecret_Short(t *testing.T) {
	got := truncateSecret("abc")
	if got != "***REDACTED***" {
		t.Errorf("truncateSecret(short) = %q, want %q", got, "***REDACTED***")
	}
}

func TestTruncateSecret_ExactThreshold(t *testing.T) {
	got := truncateSecret("12345678")
	if got != "***REDACTED***" {
		t.Errorf("truncateSecret(8-char) = %q, want %q", got, "***REDACTED***")
	}
}

func TestTruncateSecret_Long(t *testing.T) {
	got := truncateSecret("AKIAIOSFODNN7EXAMPLE")
	expected := "AKIA***REDACTED***MPLE"
	if got != expected {
		t.Errorf("truncateSecret(long) = %q, want %q", got, expected)
	}
}

func TestTruncateSecret_PreservesFirstAndLast4(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234"
	got := truncateSecret(secret)
	if got[:4] != secret[:4] {
		t.Errorf("First 4 chars = %q, want %q", got[:4], secret[:4])
	}
	if got[len(got)-4:] != secret[len(secret)-4:] {
		t.Errorf("Last 4 chars = %q, want %q", got[len(got)-4:], secret[len(secret)-4:])
	}
}

// =============================================================================
// normalizeFindings tests
// =============================================================================

func TestNormalizeFindings_Empty(t *testing.T) {
	result := normalizeFindings(nil, "/root")
	if len(result) != 0 {
		t.Errorf("normalizeFindings(nil) = %d findings, want 0", len(result))
	}
}

func TestNormalizeFindings_Mapping(t *testing.T) {
	gFindings := []gitleaksReport.Finding{
		{
			RuleID:      "aws-access-key-id",
			Description: "AWS Access Key ID",
			File:        "config.yaml",
			StartLine:   10,
			Match:       "AKIAIOSFODNN7EXAMPLE",
			Commit:      "abc123",
			Author:      "Test User",
			Email:       "test@example.com",
			Date:        "2026-01-01",
			Entropy:     4.5,
		},
	}

	findings := normalizeFindings(gFindings, "/root")

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	f := findings[0]

	// Check tool
	if f.Tool != "gitleaks" {
		t.Errorf("Tool = %q, want %q", f.Tool, "gitleaks")
	}

	// Check category
	if f.Category != schema.CategorySecrets {
		t.Errorf("Category = %q, want %q", f.Category, schema.CategorySecrets)
	}

	// Check severity (aws-access-key-id = critical)
	if f.Severity != schema.SeverityCritical {
		t.Errorf("Severity = %q, want %q", f.Severity, schema.SeverityCritical)
	}

	// Check CWE
	if f.CWEID != "CWE-798" {
		t.Errorf("CWEID = %q, want %q", f.CWEID, "CWE-798")
	}

	// Check file + line
	if f.File != "config.yaml" {
		t.Errorf("File = %q, want %q", f.File, "config.yaml")
	}
	if f.Line != 10 {
		t.Errorf("Line = %d, want 10", f.Line)
	}

	// Check fingerprint is set
	if f.Fingerprint == "" {
		t.Error("Fingerprint is empty, want non-empty")
	}

	// Check commit SHA
	if f.CommitSHA != "abc123" {
		t.Errorf("CommitSHA = %q, want %q", f.CommitSHA, "abc123")
	}

	// Check tags
	if len(f.Tags) != 2 || f.Tags[0] != "owasp:A07" {
		t.Errorf("Tags = %v, want [owasp:A07 secrets]", f.Tags)
	}

	// Check ID format
	if f.ID != "gitleaks:aws-access-key-id:config.yaml:10" {
		t.Errorf("ID = %q, want %q", f.ID, "gitleaks:aws-access-key-id:config.yaml:10")
	}

	// Check extra fields
	if f.Extra == nil {
		t.Fatal("Extra is nil")
	}
	if f.Extra["author"] != "Test User" {
		t.Errorf("Extra[author] = %v, want %q", f.Extra["author"], "Test User")
	}
}
